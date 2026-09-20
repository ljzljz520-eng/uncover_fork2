package fusion

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// findRaw locates the retained verbatim record for an observation id.
func (e *entity) findRaw(obsID string) (RawRecord, bool) {
	for _, recs := range e.raws {
		for _, r := range recs {
			if r.ObsID == obsID {
				return r, true
			}
		}
	}
	return RawRecord{}, false
}

func (e *entity) toEvidence(c candidate) Evidence {
	ev := Evidence{
		Provider:   c.provider,
		ObsID:      c.obsID,
		ObservedAt: time.Unix(0, int64(c.at)),
		Confidence: c.conf,
		Inferred:   c.inferred,
	}
	if rec, ok := e.findRaw(c.obsID); ok {
		ev.Raw = rec.Raw
		ev.RawTruncated = rec.Truncated
	}
	return ev
}

// snapshot renders the immutable export view. aliases resolves ids of entities
// absorbed by merges so edges always point at the canonical node.
func (e *entity) snapshot(rk ranker, aliases map[string]string) *Entity {
	out := &Entity{
		ID:           e.id,
		Layer:        e.layer,
		Version:      e.version,
		CreatedAt:    time.Unix(0, int64(e.createdAt)),
		FirstObsAt:   time.Unix(0, int64(e.firstObs)),
		LastObsAt:    time.Unix(0, int64(e.lastObs)),
		IdentityKeys: e.identityKeys(),
		Providers:    e.providerList(),
		Reincarnated: e.reincarnated,
		Revisions:    append([]Revision(nil), e.revisions...),
	}

	names := make([]string, 0, len(e.fields))
	for n := range e.fields {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if fld := renderField(e, rk, e.fields[n]); fld != nil {
			out.Fields = append(out.Fields, *fld)
		}
	}

	out.Edges = renderEdges(e, aliases)

	if len(e.raws) > 0 {
		out.ProviderEvidence = map[string][]RawRecord{}
		for _, prov := range e.providerList() {
			if recs, ok := e.raws[prov]; ok {
				out.ProviderEvidence[prov] = append([]RawRecord(nil), recs...)
			}
		}
	}
	return out
}

func renderField(e *entity, rk ranker, fs *fieldState) *Field {
	if fs.multi {
		values := make([]string, 0, len(fs.multiVals))
		provCands := map[string]candidate{}
		for v, byProv := range fs.multiVals {
			values = append(values, v)
			for prov, c := range byProv {
				if old, ok := provCands[prov]; !ok || rk.better(c, old) {
					provCands[prov] = c
				}
			}
		}
		sort.Strings(values)
		cands := candMapValues(provCands)
		sortCands(rk, cands)
		best := 0.0
		if len(cands) > 0 {
			best = cands[0].conf
		}
		evs := sortedEvidences(e, rk, cands)
		return &Field{Name: fs.name, Value: values[0], Values: values, Multi: true,
			Confidence: best, Version: int64(len(values) + len(provCands)), Evidences: evs}
	}

	if len(fs.current) == 0 {
		return nil
	}
	cur := candMapValues(fs.current)
	sortCands(rk, cur)
	winner := cur[0]

	// group current candidates by value, representative = best per group
	type group struct {
		value string
		best  candidate
		mems  []candidate
	}
	byValue := map[string]*group{}
	for _, c := range cur {
		g := byValue[c.value]
		if g == nil {
			g = &group{value: c.value}
			byValue[c.value] = g
		}
		g.mems = append(g.mems, c)
		if g.best.value == "" || rk.better(c, g.best) {
			g.best = c
		}
	}
	groups := make([]*group, 0, len(byValue))
	for _, g := range byValue {
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool { return rk.better(groups[i].best, groups[j].best) })

	field := &Field{
		Name:       fs.name,
		Value:      winner.value,
		Confidence: winner.conf,
		Version:    int64(len(cur) + len(fs.previous)),
		Evidences:  sortedEvidences(e, rk, cur),
	}

	// conflicts: distinct current values and/or same-provider temporal change
	if len(groups) > 1 || len(fs.previous) > 0 {
		conf := &Conflict{Winner: winner.value, Rule: RuleVersion}
		prev := candMapValues(fs.previous)
		sortCands(rk, prev)
		switch {
		case len(groups) > 1:
			conf.Code = "provider_disagreement"
		default:
			conf.Code = "value_changed_over_time"
		}
		var reasons []string
		for _, g := range groups {
			c := g.best
			cc := ConflictCandidate{
				Value:      g.value,
				Evidence:   e.toEvidence(c),
				ScoreTuple: rk.scoreTuple(c),
			}
			if g.value == winner.value {
				cc.Reason = "winner: highest deterministic rank"
			} else {
				cc.Reason = "lost: " + rk.explainWinner(winner, c)
				reasons = append(reasons, fmt.Sprintf("%q(%s) lost to %q(%s): %s",
					g.value, c.provider, winner.value, winner.provider, rk.explainWinner(winner, c)))
			}
			conf.Candidates = append(conf.Candidates, cc)
		}
		for _, c := range prev {
			if c.value == winner.value {
				continue
			}
			conf.Candidates = append(conf.Candidates, ConflictCandidate{
				Value:      c.value,
				Evidence:   e.toEvidence(c),
				ScoreTuple: rk.scoreTuple(c),
				Reason: fmt.Sprintf("superseded: %s observed %q earlier (%s), current value is %q",
					c.provider, c.value, time.Unix(0, int64(c.at)).Format(time.RFC3339), winner.value),
			})
			if len(groups) == 1 {
				reasons = append(reasons, fmt.Sprintf("%s changed %q -> %q over time",
					c.provider, c.value, winner.value))
			}
		}
		sort.SliceStable(conf.Candidates, func(i, j int) bool {
			return conf.Candidates[i].Value < conf.Candidates[j].Value
		})
		conf.Reason = strings.Join(reasons, " | ")
		if conf.Reason == "" {
			conf.Reason = "single provider temporal update; newest observation retained"
		}
		field.Conflict = conf
	}
	return field
}

func renderEdges(e *entity, aliases map[string]string) []Edge {
	type merged struct {
		typ, to string
		prov    map[string]EdgeProvenance
	}
	order := make([]edgeKey, 0, len(e.edges))
	byResolved := map[string]*merged{}
	for k, es := range e.edges {
		to := k.to
		for {
			if canon, ok := aliases[to]; ok && canon != to {
				to = canon
				continue
			}
			break
		}
		rk := k.typ + "|" + to
		m := byResolved[rk]
		if m == nil {
			m = &merged{typ: k.typ, to: to, prov: map[string]EdgeProvenance{}}
			byResolved[rk] = m
			order = append(order, edgeKey{typ: k.typ, to: to})
		}
		for prov, p := range es.prov {
			if cur, ok := m.prov[prov]; !ok || p.ObservedAt.After(cur.ObservedAt) {
				m.prov[prov] = p
			}
		}
	}
	keys := make([]string, 0, len(byResolved))
	for k := range byResolved {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Edge, 0, len(keys))
	for _, k := range keys {
		m := byResolved[k]
		provs := make([]string, 0, len(m.prov))
		for p := range m.prov {
			provs = append(provs, p)
		}
		sort.Strings(provs)
		pl := make([]EdgeProvenance, 0, len(provs))
		for _, p := range provs {
			pl = append(pl, m.prov[p])
		}
		out = append(out, Edge{Type: m.typ, From: e.id, To: m.to, Provenance: pl})
	}
	return out
}

func candMapValues(m map[string]candidate) []candidate {
	out := make([]candidate, 0, len(m))
	for _, c := range m {
		out = append(out, c)
	}
	return out
}

func sortCands(rk ranker, cs []candidate) {
	sort.Slice(cs, func(i, j int) bool { return rk.better(cs[i], cs[j]) })
}

func sortedEvidences(e *entity, rk ranker, cs []candidate) []Evidence {
	sortCands(rk, cs)
	out := make([]Evidence, 0, len(cs))
	for _, c := range cs {
		out = append(out, e.toEvidence(c))
	}
	return out
}
