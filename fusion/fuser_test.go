package fusion

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/uncover/sources"
)

var baseTime = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func mustIngest(t *testing.T, f *Fuser, o Observation) {
	t.Helper()
	if err := f.Ingest(context.Background(), o); err != nil {
		t.Fatalf("Ingest(%s %s): %v", o.Provider, o.IP, err)
	}
}

func closeFuser(t *testing.T, f *Fuser) {
	t.Helper()
	if err := f.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func findEntity(g *Graph, id string) *Entity {
	for _, e := range g.Entities {
		if e.ID == id {
			return e
		}
	}
	return nil
}

func getField(e *Entity, name string) *Field {
	for i := range e.Fields {
		if e.Fields[i].Name == name {
			return &e.Fields[i]
		}
	}
	return nil
}

func countLayer(g *Graph, l Layer) int {
	n := 0
	for _, e := range g.Entities {
		if e.Layer == l {
			n++
		}
	}
	return n
}

func drain(t *testing.T, f *Fuser) (*[]Event, <-chan struct{}) {
	t.Helper()
	var events []Event
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ev := range f.Events() {
			events = append(events, ev)
		}
	}()
	return &events, done
}

// 1. Repeated observations merge; every provider's raw evidence restorable;
// conflicting fields are exposed with confidence and reason, never overwritten.
func TestMergeConflictAndEvidenceRestore(t *testing.T) {
	f := New(Config{})
	raw1 := json.RawMessage(`{"source":"shodan","os":"linux"}`)
	raw2 := json.RawMessage(`{"source":"fofa","os":"windows"}`)
	mustIngest(t, f, Observation{
		Provider: "shodan", ObservedAt: baseTime,
		IP: "192.0.2.10", Port: 443, Protocol: "tcp",
		Extra: map[string]string{"os": "linux"}, Raw: raw1,
	})
	mustIngest(t, f, Observation{
		Provider: "fofa", ObservedAt: baseTime.Add(2 * time.Hour),
		IP: "192.0.2.10", Port: 443, Protocol: "tcp",
		Extra: map[string]string{"os": "windows"}, Raw: raw2,
	})
	closeFuser(t, f)
	g := f.Graph()

	if countLayer(g, LayerHost) != 1 || countLayer(g, LayerService) != 1 {
		t.Fatalf("expected 1 host and 1 service, got %d/%d", countLayer(g, LayerHost), countLayer(g, LayerService))
	}
	host := findEntity(g, "host:192.0.2.10")
	osf := getField(host, "os")
	if osf == nil || osf.Value != "linux" {
		t.Fatalf("winner os = %v, want linux", osf)
	}
	if osf.Conflict == nil || osf.Conflict.Code != "provider_disagreement" {
		t.Fatalf("expected provider_disagreement conflict, got %+v", osf.Conflict)
	}
	if len(osf.Conflict.Candidates) != 2 {
		t.Fatalf("want 2 conflict candidates, got %d", len(osf.Conflict.Candidates))
	}
	if osf.Conflict.Reason == "" || osf.Conflict.Rule != RuleVersion {
		t.Fatalf("conflict must carry reason and rule: %+v", osf.Conflict)
	}
	if osf.Confidence < 0.89 {
		t.Fatalf("winner confidence = %.2f", osf.Confidence)
	}
	provSet := map[string]bool{}
	for _, ev := range osf.Evidences {
		provSet[ev.Provider] = true
		if ev.Confidence <= 0 || ev.ObservedAt.IsZero() {
			t.Fatal("evidence must carry confidence and observation time")
		}
	}
	if !provSet["shodan"] || !provSet["fofa"] {
		t.Fatalf("both providers must remain on field: %v", provSet)
	}

	svc := findEntity(g, "svc:tcp:192.0.2.10:443")
	if svc == nil {
		t.Fatal("service entity missing")
	}
	if len(svc.ProviderEvidence) != 2 {
		t.Fatalf("want evidence for 2 providers, got %d", len(svc.ProviderEvidence))
	}
	gotRaw := map[string]string{}
	for prov, recs := range svc.ProviderEvidence {
		if len(recs) != 1 || len(recs[0].Raw) == 0 {
			t.Fatalf("provider %s raw evidence not restorable: %+v", prov, recs)
		}
		gotRaw[prov] = string(recs[0].Raw)
	}
	if gotRaw["shodan"] != string(raw1) || gotRaw["fofa"] != string(raw2) {
		t.Fatalf("verbatim raw evidence mismatch: %v", gotRaw)
	}
}

// 2. IPv6 spellings normalize to one host; provider evidence accumulates.
func TestIPv6NormalizationMerge(t *testing.T) {
	f := New(Config{})
	mustIngest(t, f, Observation{Provider: "shodan", ObservedAt: baseTime, IP: "2001:0DB8:0000::0001", Port: 443})
	mustIngest(t, f, Observation{Provider: "censys", ObservedAt: baseTime.Add(time.Hour), IP: "[2001:db8::1]", Port: 443})
	closeFuser(t, f)
	g := f.Graph()
	if countLayer(g, LayerHost) != 1 {
		t.Fatalf("want 1 host for equivalent IPv6 spellings, got %d", countLayer(g, LayerHost))
	}
	h := findEntity(g, "host:2001:db8::1")
	if h == nil {
		t.Fatal("canonical IPv6 host missing")
	}
	if getField(h, "ip_version").Value != "6" {
		t.Fatal("ip_version != 6")
	}
	if len(h.Providers) != 2 {
		t.Fatalf("want 2 providers on host, got %v", h.Providers)
	}
}

// 3. conservative never merges distinct IPs; aggressive merges with an
// explainable score and keeps the losing IP as an alias; far netblocks do not.
func TestConservativeVsAggressive(t *testing.T) {
	build := func(mode ResolutionMode) *Fuser {
		f := New(Config{Mode: mode})
		mustIngest(t, f, Observation{
			Provider: "shodan", ObservedAt: baseTime,
			IP: "10.0.0.1", Port: 22, Hostname: "edge.example.com", ASN: 64500,
		})
		mustIngest(t, f, Observation{
			Provider: "fofa", ObservedAt: baseTime.Add(time.Hour),
			IP: "10.0.0.2", Port: 22, Hostname: "edge.example.com", ASN: 64500,
		})
		return f
	}

	fc := build(ModeConservative)
	closeFuser(t, fc)
	gc := fc.Graph()
	if countLayer(gc, LayerHost) != 2 {
		t.Fatalf("conservative: want 2 hosts, got %d", countLayer(gc, LayerHost))
	}

	fa := build(ModeAggressive)
	closeFuser(t, fa)
	ga := fa.Graph()
	if countLayer(ga, LayerHost) != 1 {
		t.Fatalf("aggressive: want 1 merged host, got %d", countLayer(ga, LayerHost))
	}
	if fa.Stats().Merged != 1 {
		t.Fatalf("aggressive: want 1 merge, got %d", fa.Stats().Merged)
	}
	h := findEntity(ga, "host:10.0.0.1")
	if h == nil {
		t.Fatal("canonical merged host must use smallest deterministic id")
	}
	aliases := getField(h, "ip_aliases")
	if aliases == nil || !aliases.Multi || len(aliases.Values) != 1 || aliases.Values[0] != "10.0.0.2" {
		t.Fatalf("losing IP must appear as ip_aliases peer: %+v", aliases)
	}
	foundRule := false
	for _, r := range h.Revisions {
		if strings.Contains(r.Detail, "aggressive") &&
			strings.Contains(r.Detail, "shared_dns_and_netblock") &&
			strings.Contains(r.Detail, RuleVersion) {
			foundRule = true
		}
	}
	if !foundRule {
		t.Fatal("merge revision must explain score and rules")
	}

	// different /24: hostname alone is not enough
	far := New(Config{Mode: ModeAggressive})
	mustIngest(t, far, Observation{Provider: "shodan", ObservedAt: baseTime, IP: "10.0.0.1", Hostname: "edge.example.com", ASN: 1})
	mustIngest(t, far, Observation{Provider: "fofa", ObservedAt: baseTime.Add(time.Hour), IP: "10.0.9.2", Hostname: "edge.example.com", ASN: 1})
	closeFuser(t, far)
	if got := countLayer(far.Graph(), LayerHost); got != 2 {
		t.Fatalf("aggressive must not merge across distant netblocks, got %d", got)
	}
}

// 4. hard contradiction: shared hostname/netblock but different clouds.
func TestAggressiveCloudContradiction(t *testing.T) {
	f := New(Config{Mode: ModeAggressive})
	mustIngest(t, f, Observation{
		Provider: "shodan", ObservedAt: baseTime, IP: "10.1.0.1",
		Hostname: "dual.example.com", ASN: 64500,
		Cloud: &CloudID{Provider: "aws", Type: "instance", ID: "i-0aaaaaaaaaaaaaaaa"},
	})
	mustIngest(t, f, Observation{
		Provider: "censys", ObservedAt: baseTime.Add(time.Hour), IP: "10.1.0.2",
		Hostname: "dual.example.com", ASN: 64500,
		Cloud: &CloudID{Provider: "azure", Type: "account", ID: "12345678-1234-1234-1234-123456789012"},
	})
	closeFuser(t, f)
	if got := countLayer(f.Graph(), LayerHost); got != 2 {
		t.Fatalf("cloud contradiction must block merge, got %d hosts", got)
	}
}

// 5. same-provider value change over time is a visible temporal conflict.
func TestTemporalConflict(t *testing.T) {
	f := New(Config{})
	mustIngest(t, f, Observation{
		Provider: "shodan", ObservedAt: baseTime, IP: "192.0.2.20", Port: 22,
		Extra: map[string]string{"os": "windows"},
	})
	mustIngest(t, f, Observation{
		Provider: "shodan", ObservedAt: baseTime.Add(48 * time.Hour), IP: "192.0.2.20", Port: 22,
		Extra: map[string]string{"os": "linux"},
	})
	closeFuser(t, f)
	h := findEntity(f.Graph(), "host:192.0.2.20")
	osf := getField(h, "os")
	if osf == nil || osf.Value != "linux" {
		t.Fatalf("fresher value must win: %+v", osf)
	}
	if osf.Conflict == nil || osf.Conflict.Code != "value_changed_over_time" {
		t.Fatalf("expected temporal conflict, got %+v", osf.Conflict)
	}
}

// 6. full four-layer graph with provenanced edges.
func TestFourLayerGraph(t *testing.T) {
	f := New(Config{})
	fp := repeat("ab", 32)
	mustIngest(t, f, Observation{
		Provider: "shodan", ObservedAt: baseTime,
		IP: "198.51.100.7", Port: 443, Protocol: "tcp", Hostname: "app.example.org",
		CertFingerprint: fp, CertCN: "app.example.org", CertIssuer: "ca.example",
		Cloud: &CloudID{Provider: "aws", Type: "account", ID: "123456789012", Region: "us-east-1"},
	})
	closeFuser(t, f)
	g := f.Graph()

	want := []string{
		"host:198.51.100.7",
		"svc:tcp:198.51.100.7:443",
		"asset:dns:app.example.org",
		"asset:cert:" + fp,
		"asset:cloud:aws:account:123456789012",
	}
	for _, id := range want {
		if findEntity(g, id) == nil {
			t.Errorf("entity %s missing", id)
		}
	}
	if countLayer(g, LayerObservation) != 1 {
		t.Errorf("want 1 observation node, got %d", countLayer(g, LayerObservation))
	}
	edges := map[string]bool{}
	var edgeOrder []string
	for _, e := range g.Entities {
		for _, ed := range e.Edges {
			k := ed.Type + "|" + ed.From + "|" + ed.To
			edges[k] = true
			edgeOrder = append(edgeOrder, k)
			if len(ed.Provenance) == 0 {
				t.Errorf("edge %s missing provenance", k)
			}
		}
	}
	expectedEdges := []string{
		"bound_to|svc:tcp:198.51.100.7:443|host:198.51.100.7",
		"presents|svc:tcp:198.51.100.7:443|asset:cert:" + fp,
		"named|host:198.51.100.7|asset:dns:app.example.org",
		"cloud_member|host:198.51.100.7|asset:cloud:aws:account:123456789012",
	}
	for _, k := range expectedEdges {
		if !edges[k] {
			t.Errorf("edge %s missing (have: %v)", k, edgeOrder)
		}
	}
}

// 7. unknown protocol observations are promoted deterministically once known.
func TestProtocolPromotion(t *testing.T) {
	f := New(Config{})
	mustIngest(t, f, Observation{Provider: "shodan", ObservedAt: baseTime, IP: "198.51.100.9", Port: 80})
	mustIngest(t, f, Observation{Provider: "fofa", ObservedAt: baseTime.Add(time.Hour), IP: "198.51.100.9", Port: 80, Protocol: "tcp"})
	closeFuser(t, f)
	g := f.Graph()
	if findEntity(g, "svc:tcp:198.51.100.9:80") == nil {
		t.Fatal("protocol-labelled service missing")
	}
	if findEntity(g, "svc:_:198.51.100.9:80") != nil {
		t.Fatal("wildcard service must be absorbed via alias")
	}
	if _, ok := f.resolve("svc:_:198.51.100.9:80"); !ok {
		t.Fatal("old service id must resolve to canonical entity")
	}
}

// 8. materialized graph is independent of ingest order; identical sequences
// replay identically including revisions.
func TestDeterminism(t *testing.T) {
	obs := sampleObservations()

	run := func(seq []Observation) *Graph {
		f := New(Config{Mode: ModeAggressive})
		for _, o := range seq {
			mustIngest(t, f, o)
		}
		closeFuser(t, f)
		return f.Graph()
	}
	g1 := run(obs)
	shuffled := append([]Observation(nil), obs...)
	r := rand.New(rand.NewSource(42))
	r.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	g2 := run(shuffled)

	d1 := materialDigest(t, g1)
	d2 := materialDigest(t, g2)
	if len(d1) != len(d2) {
		t.Fatalf("order changed entity set: %d vs %d", len(d1), len(d2))
	}
	for id, b1 := range d1 {
		if b2, ok := d2[id]; !ok || b1 != b2 {
			t.Fatalf("materialized state for %s differs by arrival order:\n%s\nvs\n%s", id, b1, b2)
		}
	}

	// same sequence replays byte-identically including revisions
	g3 := run(obs)
	d3 := fullDigest(t, g3)
	d4 := fullDigest(t, run(obs))
	if d3 != d4 {
		t.Fatal("replaying the same sequence is not byte-identical")
	}
}

// 8b. transitive closure: A~B and B~C evidence must collapse to one component
// no matter which order the three records arrive.
func TestTransitiveClosureOrdering(t *testing.T) {
	mk := func(ip, host string) Observation {
		return Observation{
			Provider: "shodan", ObservedAt: baseTime,
			IP: ip, Port: 80, Hostname: host, ASN: 64500,
		}
	}
	A := mk("10.5.0.1", "svc-a.example.com")
	B := mk("10.5.0.2", "svc-a.example.com")
	B2 := Observation{
		Provider: "fofa", ObservedAt: baseTime.Add(time.Hour),
		IP: "10.5.0.2", Port: 80, Hostname: "svc-b.example.com", ASN: 64500,
	}
	C := mk("10.5.0.3", "svc-b.example.com")

	orders := [][]Observation{
		{A, B, B2, C},
		{C, B2, B, A},
		{B2, A, C, B},
		{B, C, A, B2},
	}
	prev := ""
	for i, order := range orders {
		f := New(Config{Mode: ModeAggressive})
		for _, o := range order {
			mustIngest(t, f, o)
		}
		closeFuser(t, f)
		g := f.Graph()
		if got := countLayer(g, LayerHost); got != 1 {
			t.Fatalf("order %d: expected single transitive component, got %d hosts", i, got)
		}
		if got := f.Stats().Merged; got != 2 {
			t.Fatalf("order %d: expected exactly 2 merges, got %d", i, got)
		}
		dm := materialDigest(t, g)
		ids := make([]string, 0, len(dm))
		for id := range dm {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		parts := make([]string, 0, len(ids))
		for _, id := range ids {
			parts = append(parts, id+"="+dm[id])
		}
		d := strings.Join(parts, "\n")
		if i > 0 && d != prev {
			t.Fatalf("order %d materialized graph differs:\n%s\nvs\n%s", i, prev, d)
		}
		prev = d
	}
}

// 8c. the full event stream (retire + snapshot) replays byte-identically.
func TestEventStreamReplayDeterminism(t *testing.T) {
	run := func() string {
		f := New(Config{MaxEntities: 9, EventBuffer: 64})
		var events []Event
		done := make(chan struct{})
		go func() {
			defer close(done)
			for ev := range f.Events() {
				events = append(events, ev)
			}
		}()
		for i := 0; i < 60; i++ {
			mustIngest(t, f, Observation{
				Provider: "shodan", ObservedAt: baseTime.Add(time.Duration(i) * time.Minute),
				IP: fmt.Sprintf("203.0.113.%d", i), Port: 80,
				Raw: json.RawMessage(fmt.Sprintf(`{"i":%d}`, i)),
			})
		}
		if err := f.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		<-done
		var parts []string
		for _, ev := range events {
			b, _ := json.Marshal(ev)
			parts = append(parts, string(b))
		}
		return strings.Join(parts, "\n")
	}
	a, b := run(), run()
	if a != b {
		t.Fatal("event stream is not replay-deterministic")
	}
}

// 9. hard memory caps: active entities and raw bytes stay bounded; deterministic
// retire events carry the complete history before removal.
func TestBoundedMemory(t *testing.T) {
	f := New(Config{MaxEntities: 12})
	events, done := drain(t, f)
	for i := 0; i < 120; i++ {
		mustIngest(t, f, Observation{
			Provider: "shodan", ObservedAt: baseTime.Add(time.Duration(i) * time.Minute),
			IP: fmt.Sprintf("203.0.113.%d", i%255), Port: 80,
			Raw: json.RawMessage(fmt.Sprintf(`{"i":%d}`, i)),
		})
		if f.Stats().ActiveEntities > 12 {
			t.Fatalf("entity cap violated: %d", f.Stats().ActiveEntities)
		}
	}
	closeFuser(t, f)
	<-done
	if f.Stats().ActiveEntities > 12 {
		t.Fatal("entity cap violated after flush")
	}
	retired := 0
	for _, ev := range *events {
		if ev.Kind == EventRetire {
			retired++
			if ev.Entity == nil || len(ev.Entity.ID) == 0 {
				t.Fatal("retire event missing snapshot")
			}
		}
	}
	if retired == 0 {
		t.Fatal("expected deterministic retirements under cap")
	}

	// raw byte budget: newest provider blobs protected, oldest trimmed/retired
	fr := New(Config{MaxEntities: 1000, MaxTotalRawBytes: 300})
	ev2, done2 := drain(t, fr)
	for i := 0; i < 60; i++ {
		mustIngest(t, fr, Observation{
			Provider: "shodan", ObservedAt: baseTime.Add(time.Duration(i) * time.Minute),
			IP: fmt.Sprintf("198.51.100.%d", i), Port: 80,
			Raw: json.RawMessage(fmt.Sprintf(`{"padding":"%s"}`, repeat("x", 80))),
		})
		if fr.Stats().ActiveRawBytes > 300 {
			t.Fatalf("raw byte cap violated: %d", fr.Stats().ActiveRawBytes)
		}
	}
	closeFuser(t, fr)
	<-done2
	if fr.Stats().ActiveRawBytes > 300 {
		t.Fatal("raw byte cap violated after flush")
	}
	if fr.Stats().TruncatedRaws == 0 {
		// retirement path is the acceptable alternative, but events must show it
		n := 0
		for _, e := range *ev2 {
			if e.Kind == EventRetire {
				n++
			}
		}
		if n == 0 {
			t.Fatal("expected raw trimming or retirement under byte pressure")
		}
	}
}

// 10. adapter: provider raw json enriches the observation end to end.
func TestAdapter(t *testing.T) {
	fp256 := repeat("cd", 32)
	raw := json.RawMessage(`{
		"ip_str":"198.51.100.50","port":8443,
		"hostnames":["host.example.net"],
		"asn":15133,
		"isp":"M247 Europe SRL",
		"ssl":{"sha256":"` + fp256 + `","cert":{"subject":{"cn":"host.example.net"}}},
		"cloud":{"provider":"aws","account":"123456789012","region":"eu-west-1"}
	}`)
	r := sources.Result{Source: "shodan", Timestamp: baseTime.Unix(), IP: "198.51.100.50", Port: 8443, Raw: raw}
	o := ResultToObservation(r)
	if o.Provider != "shodan" || o.Hostname != "host.example.net" || o.ASN != 15133 {
		t.Fatalf("basic adaptation failed: %+v", o)
	}
	if o.CertFingerprint != fp256 {
		t.Fatalf("certificate fingerprint extraction failed: %q", o.CertFingerprint)
	}
	if o.Cloud == nil || o.Cloud.Provider != "aws" || o.Cloud.ID != "123456789012" {
		t.Fatalf("cloud identity extraction failed: %+v", o.Cloud)
	}
	f := New(Config{})
	if err := f.Ingest(context.Background(), o); err != nil {
		t.Fatalf("ingest adapted observation: %v", err)
	}
	closeFuser(t, f)
	h := findEntity(f.Graph(), "host:198.51.100.50")
	if h == nil || getField(h, "asn").Value != "15133" {
		t.Fatal("adapted observation did not materialize correctly")
	}
}

// ---- helpers ----

func sampleObservations() []Observation {
	return []Observation{
		{Provider: "shodan", ObservedAt: baseTime, IP: "172.16.0.1", Port: 443, Protocol: "tcp",
			Hostname: "a.example.com", ASN: 64500, Extra: map[string]string{"os": "linux"},
			Raw: json.RawMessage(`{"p":"shodan"}`)},
		{Provider: "fofa", ObservedAt: baseTime.Add(time.Hour), IP: "172.16.0.2", Port: 443, Protocol: "tcp",
			Hostname: "a.example.com", ASN: 64500, Extra: map[string]string{"os": "windows"},
			Raw: json.RawMessage(`{"p":"fofa"}`)},
		{Provider: "censys", ObservedAt: baseTime.Add(2 * time.Hour), IP: "172.16.0.1", Port: 443, Protocol: "tcp",
			CertFingerprint: repeat("cd", 32), Hostname: "a.example.com"},
		{Provider: "shodan", ObservedAt: baseTime.Add(3 * time.Hour), IP: "172.16.0.9", Port: 53, Protocol: "udp",
			Hostname: "dns.example.com", ASN: 64501},
		{Provider: "netlas", ObservedAt: baseTime.Add(4 * time.Hour), IP: "2001:db8::10", Port: 22,
			Hostname: "v6.example.com"},
	}
}

// materialDigest renders order-independent state: revisions/version numbers
// (stream-sequence artifacts) are stripped.
func materialDigest(t *testing.T, g *Graph) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, e := range g.Entities {
		cp := *e
		cp.Revisions = nil
		cp.Version = 0
		for i := range cp.Fields {
			cp.Fields[i].Version = 0
		}
		b, err := json.Marshal(sortedEntity(&cp))
		if err != nil {
			t.Fatal(err)
		}
		out[e.ID] = string(b)
	}
	return out
}

func fullDigest(t *testing.T, g *Graph) string {
	t.Helper()
	ids := make([]string, 0, len(g.Entities))
	mp := map[string]*Entity{}
	for _, e := range g.Entities {
		ids = append(ids, e.ID)
		mp[e.ID] = e
	}
	sort.Strings(ids)
	var parts []string
	for _, id := range ids {
		b, _ := json.Marshal(sortedEntity(mp[id]))
		parts = append(parts, string(b))
	}
	return fmt.Sprint(len(parts)) + ":" + strings.Join(parts, "|")
}

func sortedEntity(e *Entity) *Entity {
	sort.Strings(e.IdentityKeys)
	sort.Strings(e.Providers)
	return e
}
