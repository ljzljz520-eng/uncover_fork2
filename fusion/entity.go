package fusion

import (
	"time"
)

type edgeKey struct{ typ, from, to string }

type edgeState struct {
	key edgeKey
	// one latest provenance per provider
	prov map[string]EdgeProvenance
}

type fieldState struct {
	name     string
	multi    bool
	current  map[string]candidate // provider -> latest candidate
	previous map[string]candidate // provider -> immediately superseded value
	// multiVals: value -> provider -> candidate (multi-valued identity sets)
	multiVals map[string]map[string]candidate
}

func newFieldState(name string, multi bool) *fieldState {
	fs := &fieldState{
		name:     name,
		multi:    multi,
		current:  map[string]candidate{},
		previous: map[string]candidate{},
	}
	if multi {
		fs.multiVals = map[string]map[string]candidate{}
	}
	return fs
}

type hostSignals struct {
	ip            string
	asn           int
	dnsNames      stringSet
	certFPS       stringSet
	instanceKey   string
	accountKey    string
	cloudProvider string
	cloudRegion   string
}

type entity struct {
	id        string
	layer     Layer
	version   int64
	keys      stringSet
	fields    map[string]*fieldState
	edges     map[edgeKey]*edgeState
	revisions []Revision
	providers stringSet

	firstObs  unixNano
	lastObs   unixNano
	createdAt unixNano

	// provider -> newest-first raw records
	raws      map[string][]RawRecord
	rawsBytes int64

	reincarnated bool
	sig          *hostSignals

	revMax  int
	heapIdx int
}

func newEntity(id string, layer Layer) *entity {
	e := &entity{
		id:        id,
		layer:     layer,
		keys:      stringSet{},
		fields:    map[string]*fieldState{},
		edges:     map[edgeKey]*edgeState{},
		providers: stringSet{},
		raws:      map[string][]RawRecord{},
		heapIdx:   -1,
	}
	if layer == LayerHost {
		e.sig = &hostSignals{dnsNames: stringSet{}, certFPS: stringSet{}}
	}
	return e
}

func (e *entity) ID() string { return e.id }

// putField records one provider attestation of a single-winner field. A
// provider replacing its own previous value moves the old one to "previous"
// (flagged as a temporal conflict at render time); nothing is overwritten
// silently. Returns true when the materialized state changed.
func (e *entity) putField(name, value string, c candidate, rk ranker, f *Fuser) bool {
	if value == "" {
		return false
	}
	e.providers.add(c.provider)
	c.value = value
	c.conf = rk.evidenceConfidence(c.provider, c.inferred)
	fs, ok := e.fields[name]
	if !ok {
		fs = newFieldState(name, false)
		e.fields[name] = fs
	}
	changed := false
	old, exists := fs.current[c.provider]
	switch {
	case !exists:
		fs.current[c.provider] = c
		e.revise(c.at, c.obsID, "field "+name+" attested by "+c.provider+" = "+value)
		changed = true
	case old.value != value:
		fs.previous[c.provider] = old
		fs.current[c.provider] = c
		e.revise(c.at, c.obsID, "field "+name+" updated by "+c.provider+": "+old.value+" -> "+value)
		changed = true
	default:
		// identical re-observation: refresh observation time/evidence. The
		// final obsID tiebreak makes same-instant re-attestations
		// arrival-order independent.
		if old.at != c.at || old.conf != c.conf || rk.better(c, old) {
			fs.current[c.provider] = c
			e.bump()
		}
	}
	return changed
}

// putMulti adds a value to a multi-valued identity-set field (hostnames,
// ip_aliases): values are peers and never compete as winner/conflict.
func (e *entity) putMulti(name, value string, c candidate) {
	if value == "" {
		return
	}
	e.providers.add(c.provider)
	fs, ok := e.fields[name]
	if !ok {
		fs = newFieldState(name, true)
		e.fields[name] = fs
	}
	c.value = value
	byProvider, ok := fs.multiVals[value]
	if !ok {
		byProvider = map[string]candidate{}
		fs.multiVals[value] = byProvider
		e.revise(c.at, c.obsID, "multi-field "+name+" += "+value+" ("+c.provider+")")
	}
	if prev, ok := byProvider[c.provider]; !ok || prev.at != c.at ||
		(prev.at == c.at && c.obsID < prev.obsID) {
		byProvider[c.provider] = c
	}
}

func (e *entity) addEdge(typ, to string, c candidate) {
	if to == "" || to == e.id {
		return
	}
	k := edgeKey{typ: typ, from: e.id, to: to}
	es, ok := e.edges[k]
	if !ok {
		es = &edgeState{key: k, prov: map[string]EdgeProvenance{}}
		e.edges[k] = es
	}
	pv := EdgeProvenance{
		Provider:   c.provider,
		ObsID:      c.obsID,
		ObservedAt: time.Unix(0, int64(c.at)),
		Confidence: c.conf,
	}
	if cur, ok := es.prov[c.provider]; !ok ||
		pv.ObservedAt.After(cur.ObservedAt) ||
		(pv.ObservedAt.Equal(cur.ObservedAt) && pv.ObsID < cur.ObsID) {
		es.prov[c.provider] = pv
	}
}

func (e *entity) bump() { e.version++ }

func (e *entity) revise(at unixNano, obsID, detail string) {
	rev := Revision{Seq: int64(len(e.revisions) + 1), At: time.Unix(0, int64(at)), ObsID: obsID, Detail: detail}
	e.revisions = append(e.revisions, rev)
	if e.revMax > 0 {
		e.trimRevisions(e.revMax)
	}
	e.version++
}

// trimRevisions keeps the revision log bounded and deterministic (oldest
// dropped, but the creation entry seq 1 is always retained).
func (e *entity) trimRevisions(max int) {
	if len(e.revisions) <= max {
		return
	}
	first := e.revisions[0]
	keep := e.revisions[len(e.revisions)-(max-1):]
	e.revisions = append([]Revision{first}, keep...)
	// re-sequence the retained window
	for i := range e.revisions {
		e.revisions[i].Seq = int64(i + 1)
	}
}

func (e *entity) providerList() []string {
	out := e.providers.sorted()
	return out
}

func (e *entity) identityKeys() []string { return e.keys.sorted() }
