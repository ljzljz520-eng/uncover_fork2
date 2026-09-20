package fusion

import (
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Fuser is a streaming, bounded-memory, deterministic graph fusion engine.
// Use New to construct one, feed records with Ingest and consume deterministic
// lifecycle events from Events. Close emits the final ordered snapshot set.
type Fuser struct {
	cfg Config
	rk  ranker

	entities map[string]*entity
	aliases  map[string]string // absorbed id -> canonical id
	retired  map[string]int64  // id -> retirement sequence (bounded)
	keyIndex map[string]string // blocking key -> canonical id

	// host signal inverted indexes: signal value -> set of canonical host ids
	sigDNS      map[string]stringSet
	sigCert     map[string]stringSet
	sigInstance map[string]stringSet
	sigAccount  map[string]stringSet

	evictQ   evictionHeap
	rawQ     rawHeap
	eventsCh chan Event

	// reincarnating collects entities recreated during the current ingest.
	reincarnating []string

	stats  Stats
	seq    int64
	closed bool
}

// New constructs a Fuser with the given configuration.
func New(cfg Config) *Fuser {
	cfg.withDefaults()
	f := &Fuser{
		cfg:         cfg,
		rk:          ranker{overrides: cfg.ProviderConfidence},
		entities:    map[string]*entity{},
		aliases:     map[string]string{},
		retired:     map[string]int64{},
		keyIndex:    map[string]string{},
		sigDNS:      map[string]stringSet{},
		sigCert:     map[string]stringSet{},
		sigInstance: map[string]stringSet{},
		sigAccount:  map[string]stringSet{},
		eventsCh:    make(chan Event, cfg.EventBuffer),
	}
	heap.Init(&f.evictQ)
	heap.Init(&f.rawQ)
	return f
}

// Events returns the deterministic event stream. It is closed by Close.
func (f *Fuser) Events() <-chan Event { return f.eventsCh }

// Stats returns a snapshot of resource accounting.
func (f *Fuser) Stats() Stats {
	s := f.stats
	s.ActiveEntities = len(f.entities)
	return s
}

// ErrInvalidObservation is returned when an observation carries no usable
// identity (no valid IP/hostname/cloud/cert) or fails normalization.
type ErrInvalidObservation struct{ reason string }

func (e ErrInvalidObservation) Error() string {
	return "fusion: invalid observation: " + e.reason
}

// prepared holds the normalized view of one observation.
type prepared struct {
	obs    Observation
	id     string
	at     unixNano
	ip     string
	ipVer  int
	port   int
	proto  string
	fqdn   string
	apex   string
	certFP string
	asn    int
	cloud  *CloudID
	host   map[string]string // normalized host attributes
	svc    map[string]string // normalized service attributes
}

func (f *Fuser) prepare(o Observation) (*prepared, bool) {
	p := &prepared{
		obs:  o,
		at:   unixNano(o.ObservedAt.UnixNano()),
		host: map[string]string{},
		svc:  map[string]string{},
	}
	if strings.TrimSpace(o.Provider) == "" {
		return nil, false
	}
	if ip, ver, ok := NormalizeIP(o.IP); ok {
		p.ip, p.ipVer = ip, ver
	}
	p.proto = NormalizeProtocol(o.Protocol)
	if o.Port >= 1 && o.Port <= 65535 {
		p.port = o.Port
	}
	if fqdn, ok := NormalizeDNS(o.Hostname); ok {
		p.fqdn = fqdn
		p.apex = ApexDomain(fqdn)
	}
	if fp, ok := NormalizeFingerprint(o.CertFingerprint); ok {
		p.certFP = fp
	}
	if asn, ok := NormalizeASN(fmt.Sprint(o.ASN)); ok {
		p.asn = asn
	} else {
		p.asn = o.ASN
	}
	if o.Cloud != nil {
		if c, ok := NormalizeCloudID(o.Cloud.Provider, o.Cloud.ID); ok {
			c.Region = strings.ToLower(strings.TrimSpace(o.Cloud.Region))
			p.cloud = c
		}
	}
	for k, v := range o.Extra {
		key := strings.ToLower(strings.TrimSpace(k))
		val := strings.TrimSpace(v)
		if val == "" {
			continue
		}
		switch key {
		case "os", "org", "organization", "isp", "country", "country_name", "city", "location":
			if key == "organization" {
				key = "org"
			}
			if key == "country_name" {
				key = "country"
			}
			p.host[key] = val
		case "product", "version", "banner", "title", "service", "url", "transport":
			p.svc[key] = val
		}
	}
	if o.URL != "" {
		p.svc["url"] = strings.TrimSpace(o.URL)
	}
	if o.Service != "" {
		p.svc["service"] = strings.TrimSpace(o.Service)
	}
	if o.ASNOrg != "" {
		p.host["asn_org"] = NormalizeASNOrg(o.ASNOrg)
	}
	if p.ip == "" && p.fqdn == "" && p.certFP == "" && p.cloud == nil {
		return nil, false
	}
	p.id = normalizeObsID(o, p)
	return p, true
}

// normalizeObsID derives a deterministic content id when the caller did not
// assign one. Identical resends of the same provider record get the same id,
// which makes re-ingestion idempotent.
func normalizeObsID(o Observation, p *prepared) string {
	if strings.TrimSpace(o.ID) != "" {
		return strings.TrimSpace(o.ID)
	}
	h := sha256.New()
	fmt.Fprintf(h, "%s|%d|%s|%d|%s|%s|%d",
		strings.ToLower(o.Provider), int64(p.at), p.ip, p.port, p.fqdn, p.certFP, len(o.Raw))
	h.Write(o.Raw)
	sum := hex.EncodeToString(h.Sum(nil))
	return "auto-" + sum[:24]
}

// Ingest fuses one observation into the graph. It blocks on event backpressure
// and honors ctx. Invalid observations are counted (Stats.DroppedInvalid) and
// returned as ErrInvalidObservation without aborting the stream.
func (f *Fuser) Ingest(ctx context.Context, o Observation) error {
	if f.closed {
		return fmt.Errorf("fusion: fuser already closed")
	}
	p, ok := f.prepare(o)
	if !ok {
		f.stats.DroppedInvalid++
		return ErrInvalidObservation{reason: "no valid ip, hostname, certificate or cloud identity"}
	}
	f.stats.Observed++

	// ---- observation node ----
	obsID := "obs:" + p.id
	obsEnt := f.getOrCreate(obsID, LayerObservation)
	obsEnt.providers.add(strings.ToLower(p.obs.Provider))
	f.touch(obsEnt, p.at)
	obsEnt.putField("provider", strings.ToLower(p.obs.Provider), p.candidate(f.rk, "provider", false), f.rk, f)

	var hostEnt, svcEnt *entity

	// ---- host node ----
	if p.ip != "" {
		hostID := "host:" + p.ip
		hostEnt = f.getOrCreate(hostID, LayerHost)
		f.addKey(hostEnt, "ip:"+p.ip)
		hostEnt.sig.ip = p.ip
		f.touch(hostEnt, p.at)

		hostEnt.putField("ip", p.ip, p.candidate(f.rk, "ip", false), f.rk, f)
		hostEnt.putField("ip_version", fmt.Sprint(p.ipVer), p.candidate(f.rk, "ip_version", false), f.rk, f)
		if p.asn > 0 {
			hostEnt.putField("asn", fmt.Sprint(p.asn), p.candidate(f.rk, "asn", false), f.rk, f)
			hostEnt.sig.asn = p.asn
		}
		for k, v := range p.host {
			hostEnt.putField(k, v, p.candidate(f.rk, k, false), f.rk, f)
		}
		if p.fqdn != "" {
			hostEnt.putMulti("hostnames", p.fqdn, p.candidate(f.rk, "hostnames", false))
			hostEnt.sig.dnsNames.add(p.fqdn)
			f.sigAdd(f.sigDNS, p.fqdn, hostEnt.id)
		}
		if p.cloud != nil {
			f.applyCloudToHost(p, hostEnt)
		}
		f.addEdge(obsEnt, hostEnt.ID(), "observes", p)
	}

	// ---- service node ----
	if p.ip != "" && p.port > 0 {
		// Resolve the service identity. Unknown protocol attaches to the sole
		// known protocol entity; an ambiguous (tcp+udp) or first sighting uses
		// the wildcard label until promoted.
		label := p.proto
		if label == "" {
			label = "_"
		}
		svcID := fmt.Sprintf("svc:%s:%s:%d", label, p.ip, p.port)
		if p.proto != "" {
			wildID := fmt.Sprintf("svc:_:%s:%d", p.ip, p.port)
			if wild, ok := f.lookup(wildID); ok && wild.id != svcID {
				f.promoteService(wild, svcID, p)
			}
		} else {
			var known []string
			for _, proto := range []string{"tcp", "udp"} {
				id := fmt.Sprintf("svc:%s:%s:%d", proto, p.ip, p.port)
				if _, ok := f.lookup(id); ok {
					known = append(known, id)
				}
			}
			if len(known) == 1 {
				svcID = known[0]
				label = svcID[4:7] // "tcp"/"udp"
			}
		}
		svcEnt = f.getOrCreate(svcID, LayerService)
		f.addKey(svcEnt, fmt.Sprintf("ip_port:%s:%d", p.ip, p.port))
		f.addKey(svcEnt, "proto:"+label)
		f.touch(svcEnt, p.at)
		svcEnt.putField("ip", p.ip, p.candidate(f.rk, "ip", false), f.rk, f)
		svcEnt.putField("port", fmt.Sprint(p.port), p.candidate(f.rk, "port", false), f.rk, f)
		if p.proto != "" {
			svcEnt.putField("protocol", p.proto, p.candidate(f.rk, "protocol", false), f.rk, f)
		}
		for k, v := range p.svc {
			svcEnt.putField(k, v, p.candidate(f.rk, k, false), f.rk, f)
		}
		if p.certFP != "" {
			svcEnt.putField("cert_sha256", p.certFP, p.candidate(f.rk, "cert_sha256", false), f.rk, f)
			if p.obs.CertCN != "" {
				svcEnt.putField("cert_cn", strings.TrimSpace(p.obs.CertCN), p.candidate(f.rk, "cert_cn", false), f.rk, f)
			}
			if p.obs.CertIssuer != "" {
				svcEnt.putField("cert_issuer", strings.TrimSpace(p.obs.CertIssuer), p.candidate(f.rk, "cert_issuer", false), f.rk, f)
			}
			if hostEnt != nil {
				hostEnt.sig.certFPS.add(p.certFP)
				f.sigAdd(f.sigCert, p.certFP, hostEnt.id)
			}
		}
		f.addEdge(obsEnt, svcEnt.ID(), "about", p)
		f.addEdge(svcEnt, hostEnt.ID(), "bound_to", p)

		// raw evidence is co-located with the service when one exists.
		f.archiveRaw(svcEnt, p)
	} else if hostEnt != nil {
		f.archiveRaw(hostEnt, p)
	}

	// ---- asset nodes ----
	if p.fqdn != "" {
		dnsEnt := f.getOrCreate("asset:dns:"+p.fqdn, LayerAsset)
		f.addKey(dnsEnt, "dns:"+p.fqdn)
		f.touch(dnsEnt, p.at)
		dnsEnt.putField("fqdn", p.fqdn, p.candidate(f.rk, "fqdn", false), f.rk, f)
		dnsEnt.putField("apex_domain", p.apex, p.candidate(f.rk, "apex_domain", true), f.rk, f)
		if hostEnt != nil {
			f.addEdge(hostEnt, dnsEnt.ID(), "named", p)
		} else {
			f.addEdge(obsEnt, dnsEnt.ID(), "about_asset", p)
			f.archiveRaw(dnsEnt, p)
		}
	}
	if p.certFP != "" {
		certEnt := f.getOrCreate("asset:cert:"+p.certFP, LayerAsset)
		f.addKey(certEnt, "cert:"+p.certFP)
		f.touch(certEnt, p.at)
		certEnt.putField("sha256", p.certFP, p.candidate(f.rk, "sha256", false), f.rk, f)
		if p.obs.CertCN != "" {
			certEnt.putField("cn", strings.TrimSpace(p.obs.CertCN), p.candidate(f.rk, "cn", false), f.rk, f)
		}
		if p.obs.CertIssuer != "" {
			certEnt.putField("issuer", strings.TrimSpace(p.obs.CertIssuer), p.candidate(f.rk, "issuer", false), f.rk, f)
		}
		if svcEnt != nil {
			f.addEdge(svcEnt, certEnt.ID(), "presents", p)
		} else {
			f.addEdge(obsEnt, certEnt.ID(), "about_asset", p)
			if hostEnt == nil && p.fqdn == "" {
				f.archiveRaw(certEnt, p)
			}
		}
	}
	if p.cloud != nil {
		if key, ok := p.cloud.AccountKey(); ok {
			acctEnt := f.getOrCreate("asset:"+key, LayerAsset)
			f.addKey(acctEnt, key)
			f.touch(acctEnt, p.at)
			acctEnt.putField("cloud_provider", p.cloud.Provider, p.candidate(f.rk, "cloud_provider", false), f.rk, f)
			acctEnt.putField("account_id", p.cloud.ID, p.candidate(f.rk, "account_id", false), f.rk, f)
			if hostEnt != nil {
				f.addEdge(hostEnt, acctEnt.ID(), "cloud_member", p)
			}
		}
	}

	// ---- aggressive cross-IP host merging ----
	if f.cfg.Mode == ModeAggressive && hostEnt != nil {
		// a new provider attesting a distinct primary IP on an already merged
		// host must be folded to ip_aliases immediately
		f.collapseHostIPs(hostEnt)
		f.tryAggressiveHostMerge(ctx, hostEnt, p)
	}

	if err := f.enforceLimits(ctx); err != nil {
		return err
	}
	reincarnating := f.reincarnating
	f.reincarnating = nil
	for _, rid := range reincarnating {
		if e, ok := f.lookup(rid); ok {
			if err := f.emit(ctx, EventReincarnate, e); err != nil {
				return err
			}
		}
	}
	if f.cfg.EmitUpdates {
		ids := []string{obsID}
		if hostEnt != nil {
			ids = append(ids, hostEnt.id)
		}
		if svcEnt != nil {
			ids = append(ids, svcEnt.id)
		}
		for _, id := range ids {
			if e, ok := f.lookup(id); ok {
				if err := f.emit(ctx, EventUpsert, e); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (p prepared) candidate(rk ranker, _ string, inferred bool) candidate {
	provider := strings.ToLower(strings.TrimSpace(p.obs.Provider))
	return candidate{
		provider: provider,
		obsID:    "obs:" + p.id,
		at:       p.at,
		inferred: inferred,
		conf:     rk.evidenceConfidence(provider, inferred),
	}
}

func (f *Fuser) applyCloudToHost(p *prepared, h *entity) {
	c := p.cloud
	h.putField("cloud_provider", c.Provider, p.candidate(f.rk, "cloud_provider", false), f.rk, f)
	h.sig.cloudProvider = c.Provider
	if c.Region != "" {
		h.putField("cloud_region", c.Region, p.candidate(f.rk, "cloud_region", false), f.rk, f)
		h.sig.cloudRegion = c.Region
	}
	switch c.Type {
	case "account":
		h.putField("cloud_account", c.ID, p.candidate(f.rk, "cloud_account", false), f.rk, f)
		h.sig.accountKey = fmt.Sprintf("cloud:%s:account:%s", c.Provider, c.ID)
		f.sigAdd(f.sigAccount, h.sig.accountKey, h.id)
	case "instance", "arn":
		if ik, ok := c.InstanceKey(); ok {
			h.putField("cloud_instance", c.ID, p.candidate(f.rk, "cloud_instance", false), f.rk, f)
			h.sig.instanceKey = ik
			f.sigAdd(f.sigInstance, ik, h.id)
		}
		if ak, ok := c.AccountKey(); ok {
			h.sig.accountKey = ak
			f.sigAdd(f.sigAccount, ak, h.id)
		}
	}
}

// tryAggressiveHostMerge finds distinct-IP hosts sharing strong signals and
// merges the connected candidate set with the current host.
func (f *Fuser) tryAggressiveHostMerge(ctx context.Context, h *entity, p *prepared) {
	cand := map[string]struct{}{}
	collect := func(idx map[string]stringSet, key string) {
		for id := range idx[key] {
			if canon, ok := f.resolve(id); ok && canon != h.id {
				cand[canon] = struct{}{}
			}
		}
	}
	for n := range h.sig.dnsNames {
		collect(f.sigDNS, n)
	}
	for fp := range h.sig.certFPS {
		collect(f.sigCert, fp)
	}
	if h.sig.instanceKey != "" {
		collect(f.sigInstance, h.sig.instanceKey)
	}
	if h.sig.accountKey != "" {
		collect(f.sigAccount, h.sig.accountKey)
	}
	if len(cand) == 0 {
		return
	}
	mergeSet := []string{h.id}
	var explanations []string
	for id := range cand {
		other := f.entities[id]
		if other == nil || other.layer != LayerHost {
			continue
		}
		res := scoreHostMerge(h.sig, other.sig)
		if res.contradiction != "" || res.score < ModeThresholdAggressive {
			continue
		}
		mergeSet = append(mergeSet, id)
		explanations = append(explanations,
			fmt.Sprintf("%s score=%.2f [%s] rule=%s", id, res.score, res.explain(), RuleVersion))
	}
	if len(mergeSet) == 1 {
		return
	}
	sort.Strings(mergeSet[1:])
	target := f.entities[mergeSet[0]]
	for _, id := range mergeSet[1:] {
		if e := f.entities[id]; e != nil {
			f.mergeEntities(target, e, "aggressive host merge: "+explanationsJoin(explanations, id), p)
		}
	}
}

func explanationsJoin(all []string, id string) string {
	for _, s := range all {
		if strings.HasPrefix(s, id+" ") {
			return s
		}
	}
	return "aggressive host merge"
}

// promoteService absorbs an unknown-protocol service entity into the now
// protocol-labelled entity.
func (f *Fuser) promoteService(wild *entity, canonicalID string, p *prepared) {
	target := f.getOrCreate(canonicalID, LayerService)
	f.mergeEntitiesKeep(target, wild, true, "protocol identified as "+p.proto, p)
}

// Graph returns the current materialized graph. Entities are sorted by ID, so
// rendering is deterministic.
func (f *Fuser) Graph() *Graph {
	ids := make([]string, 0, len(f.entities))
	for id := range f.entities {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	g := &Graph{Entities: make([]*Entity, 0, len(ids))}
	for _, id := range ids {
		g.Entities = append(g.Entities, f.entities[id].snapshot(f.rk, f.aliases))
	}
	return g
}

// Close retires no further state and emits every active entity as an ordered
// EventSnapshot stream, then closes the event channel.
func (f *Fuser) Close(ctx context.Context) error {
	if f.closed {
		return nil
	}
	f.closed = true
	ids := make([]string, 0, len(f.entities))
	for id := range f.entities {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if e, ok := f.lookup(id); ok {
			if err := f.emit(ctx, EventSnapshot, e); err != nil {
				return err
			}
		}
	}
	close(f.eventsCh)
	return nil
}

// deterministic observation-time based revision clock.
func (f *Fuser) now(p *prepared) unixNano {
	if p != nil {
		return p.at
	}
	if f.cfg.Now != nil {
		return unixNano(f.cfg.Now().UnixNano())
	}
	return unixNano(time.Now().UnixNano())
}
