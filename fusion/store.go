package fusion

import (
	"context"
	"sort"
)

// resolve chases merge aliases and returns the canonical live entity.
func (f *Fuser) resolve(id string) (string, bool) {
	seen := map[string]bool{}
	for {
		if seen[id] {
			return "", false
		}
		seen[id] = true
		if canon, ok := f.aliases[id]; ok && canon != id {
			id = canon
			continue
		}
		_, live := f.entities[id]
		return id, live
	}
}

func (f *Fuser) lookup(id string) (*entity, bool) {
	canon, ok := f.resolve(id)
	if !ok {
		return nil, false
	}
	return f.entities[canon], true
}

// getOrCreate returns the live entity for id, transparently following merge
// aliases. New entities are placed in all indexes at touch time.
func (f *Fuser) getOrCreate(id string, layer Layer) *entity {
	if canon, ok := f.aliases[id]; ok {
		if e := f.entities[canon]; e != nil {
			return e
		}
	}
	if e, ok := f.entities[id]; ok {
		return e
	}
	e := newEntity(id, layer)
	e.revMax = f.cfg.MaxRevisions
	f.entities[id] = e
	if _, wasRetired := f.retired[id]; wasRetired {
		e.reincarnated = true
		delete(f.retired, id)
		f.reincarnating = append(f.reincarnating, id)
		e.revise(0, "", "entity reincarnated after retirement; prior history was emitted as retire event")
	}
	e.revise(0, "", "created "+string(layer)+" entity "+id)
	return e
}

func (f *Fuser) addKey(e *entity, key string) {
	e.keys.add(key)
	f.keyIndex[key] = e.id
}

func (f *Fuser) touch(e *entity, at unixNano) {
	if e.firstObs == 0 || at < e.firstObs {
		e.firstObs = at
	}
	if at > e.lastObs {
		e.lastObs = at
	}
	if e.createdAt == 0 || at < e.createdAt {
		e.createdAt = at
	}
	f.evictQ.update(e)
}

func (f *Fuser) addEdge(from *entity, toID, typ string, p *prepared) {
	if canon, ok := f.resolve(toID); ok {
		toID = canon
	}
	c := p.candidate(f.rk, typ, false)
	from.addEdge(typ, toID, c)
}

func (f *Fuser) sigAdd(idx map[string]stringSet, key, hostID string) {
	s := idx[key]
	if s == nil {
		s = stringSet{}
		idx[key] = s
	}
	if canon, ok := f.resolve(hostID); ok {
		s.add(canon)
	}
}

// archiveRaw stores the verbatim provider payload on the attested entity,
// newest first, deduplicated by observation id, bounded per (entity, provider)
// by count and bytes. Every provider keeps at least its newest blob.
func (f *Fuser) archiveRaw(e *entity, p *prepared) {
	if len(p.obs.Raw) == 0 {
		return
	}
	provider := p.candidate(f.rk, "", false).provider
	blob := append(jsonRawCopy(nil), p.obs.Raw...)
	rec := RawRecord{ObsID: "obs:" + p.id, ObservedAt: timeUnix(p.at), Raw: blob}

	recs := e.raws[provider]
	replaced := false
	for i := range recs {
		if recs[i].ObsID == rec.ObsID {
			f.removeRawBytes(e, provider, i)
			recs[i] = rec
			replaced = true
			break
		}
	}
	if !replaced {
		recs = append([]RawRecord{rec}, recs...)
	}
	sort.SliceStable(recs, func(i, j int) bool {
		if recs[i].ObservedAt != recs[j].ObservedAt {
			return recs[i].ObservedAt.After(recs[j].ObservedAt)
		}
		return recs[i].ObsID < recs[j].ObsID
	})
	// count cap
	if len(recs) > f.cfg.MaxProviderRaws {
		for _, r := range recs[f.cfg.MaxProviderRaws:] {
			f.stats.ActiveRawBytes -= int64(len(r.Raw))
		}
		recs = recs[:f.cfg.MaxProviderRaws]
	}
	// per-provider byte cap (drop oldest)
	for sumRaw(recs) > int64(f.cfg.MaxProviderRawBytes) && len(recs) > 1 {
		last := recs[len(recs)-1]
		f.stats.ActiveRawBytes -= int64(len(last.Raw))
		recs = recs[:len(recs)-1]
	}
	e.raws[provider] = recs
	if !replaced {
		f.stats.ActiveRawBytes += int64(len(rec.Raw))
		f.rawQ.push(&rawEntry{
			eid: e.id, provider: provider, obsID: rec.ObsID,
			at: p.at, size: len(rec.Raw),
		})
	} else {
		f.stats.ActiveRawBytes += int64(len(rec.Raw))
		f.rawQ.push(&rawEntry{
			eid: e.id, provider: provider, obsID: rec.ObsID,
			at: p.at, size: len(rec.Raw),
		})
	}
}

func (f *Fuser) removeRawBytes(e *entity, provider string, i int) {
	if recs, ok := e.raws[provider]; ok && i < len(recs) {
		f.stats.ActiveRawBytes -= int64(len(recs[i].Raw))
	}
}

func sumRaw(recs []RawRecord) int64 {
	var n int64
	for _, r := range recs {
		n += int64(len(r.Raw))
	}
	return n
}

// mergeEntities absorbs src into target. The canonical survivor is the
// lexicographically smallest entity id, which makes final ids independent of
// ingest order. Merge is commutative/associative on materialized state.
func (f *Fuser) mergeEntities(target, src *entity, reason string, p *prepared) *entity {
	return f.mergeEntitiesKeep(target, src, false, reason, p)
}

// mergeEntitiesKeep performs the union. When keepTargetID is false the smaller
// id wins (stream merges); when true the target keeps its identity even if
// lexicically larger (protocol-labelled promotion).
func (f *Fuser) mergeEntitiesKeep(target, src *entity, keepTargetID bool, reason string, p *prepared) *entity {
	if src.id == target.id {
		return target
	}
	if !keepTargetID && src.id < target.id {
		target, src = src, target
	}

	// 1. fields (host ip identity is merged separately to avoid losing
	// displaced IPs through the one-deep previous slot)
	for name, sfs := range src.fields {
		if target.layer == LayerHost && (name == "ip" || name == "ip_aliases") {
			continue
		}
		tfs, ok := target.fields[name]
		if !ok {
			tfs = newFieldState(name, sfs.multi)
			target.fields[name] = tfs
		}
		mergeFieldState(tfs, sfs, f.rk)
	}

	// 2. host ip identity: every observed IP survives as an alias, the
	// non-winner primary IPs never surface as fake field conflicts.
	if target.layer == LayerHost {
		f.mergeHostIPIdentity(target, src)
		target.sig = mergeSignals(target.sig, src.sig)
	}

	// 3. edges (rebased onto target id)
	for k, es := range src.edges {
		nk := edgeKey{typ: k.typ, from: target.id, to: k.to}
		tes := target.edges[nk]
		if tes == nil {
			cp := &edgeState{key: nk, prov: map[string]EdgeProvenance{}}
			for prov, pv := range es.prov {
				cp.prov[prov] = pv
			}
			target.edges[nk] = cp
		} else {
			for prov, pv := range es.prov {
				if cur, ok := tes.prov[prov]; !ok ||
					pv.ObservedAt.After(cur.ObservedAt) ||
					(pv.ObservedAt.Equal(cur.ObservedAt) && pv.ObsID < cur.ObsID) {
					tes.prov[prov] = pv
				}
			}
		}
	}

	// 4. providers / times / keys
	for prov := range src.providers {
		target.providers.add(prov)
	}
	if src.firstObs != 0 && (target.firstObs == 0 || src.firstObs < target.firstObs) {
		target.firstObs = src.firstObs
	}
	if src.lastObs > target.lastObs {
		target.lastObs = src.lastObs
	}
	if src.createdAt != 0 && (target.createdAt == 0 || src.createdAt < target.createdAt) {
		target.createdAt = src.createdAt
	}
	for _, k := range src.keys.sorted() {
		f.addKey(target, k)
	}

	// 5. raw evidence archives
	for prov, srecs := range src.raws {
		trecs := target.raws[prov]
		trecs = append(trecs, srecs...)
		sort.SliceStable(trecs, func(i, j int) bool {
			if trecs[i].ObservedAt != trecs[j].ObservedAt {
				return trecs[i].ObservedAt.After(trecs[j].ObservedAt)
			}
			return trecs[i].ObsID < trecs[j].ObsID
		})
		// dedupe obs ids
		seen := map[string]bool{}
		merged := trecs[:0]
		for _, r := range trecs {
			if seen[r.ObsID] {
				f.stats.ActiveRawBytes -= int64(len(r.Raw))
				continue
			}
			seen[r.ObsID] = true
			merged = append(merged, r)
		}
		trecs = merged
		if len(trecs) > f.cfg.MaxProviderRaws {
			for _, r := range trecs[f.cfg.MaxProviderRaws:] {
				f.stats.ActiveRawBytes -= int64(len(r.Raw))
			}
			trecs = trecs[:f.cfg.MaxProviderRaws]
		}
		target.raws[prov] = trecs
		for _, r := range trecs {
			if len(r.Raw) > 0 {
				f.rawQ.push(&rawEntry{eid: target.id, provider: prov, obsID: r.ObsID,
					at: unixNano(r.ObservedAt.UnixNano()), size: len(r.Raw)})
			}
		}
	}
	target.rawsBytes = 0
	for _, recs := range target.raws {
		target.rawsBytes += sumRaw(recs)
	}

	// 6. revisions (bounded)
	obsID := ""
	if p != nil {
		obsID = "obs:" + p.id
	}
	for _, r := range src.revisions {
		target.revisions = append(target.revisions, r)
	}
	target.revise(f.now(p), obsID, "absorbed "+src.id+": "+reason)

	// 7. bookkeeping: alias, removal, indexes
	f.aliases[src.id] = target.id
	delete(f.entities, src.id)
	for _, k := range src.keys.sorted() {
		if f.keyIndex[k] == src.id {
			f.keyIndex[k] = target.id
		}
	}
	if src.layer == LayerHost {
		f.removeHostFromIndex(src.id)
		f.reindexHost(target)
	}
	f.evictQ.update(target)
	f.stats.Merged++
	return target
}

// mergeFieldState unions two field states with set semantics so the result is
// arrival-order independent. Exact ties (same time) are broken with the same
// total-order ranker used for field winners.
func mergeFieldState(dst, src *fieldState, rk ranker) {
	if dst.multi {
		for v, byProv := range src.multiVals {
			dv := dst.multiVals[v]
			if dv == nil {
				dv = map[string]candidate{}
				dst.multiVals[v] = dv
			}
			for prov, c := range byProv {
				if old, ok := dv[prov]; !ok || rk.better(c, old) {
					dv[prov] = c
				}
			}
		}
		return
	}
	for prov, c := range src.current {
		if old, ok := dst.current[prov]; !ok || rk.better(c, old) {
			if ok && old.value != c.value {
				mergePrevious(dst, prov, old, rk)
			}
			dst.current[prov] = c
		} else if c.value != old.value {
			mergePrevious(dst, prov, c, rk)
		}
	}
	for prov, c := range src.previous {
		mergePrevious(dst, prov, c, rk)
	}
}

// mergePrevious retains the most recently observed displaced value per
// provider (one deep) for temporal conflict reporting.
func mergePrevious(dst *fieldState, prov string, c candidate, rk ranker) {
	if cur, ok := dst.current[prov]; ok && cur.value == c.value {
		return
	}
	if old, ok := dst.previous[prov]; ok && !rk.better(c, old) {
		return
	}
	dst.previous[prov] = c
}

// mergeHostIPIdentity combines the primary-ip states of two hosts that are
// being merged. Every distinct IP ever attested on either side is first
// harvested into the target's ip_aliases set, so a value displaced by a
// later per-provider update cannot be lost through the one-deep previous
// slot; collapseHostIPs then promotes the globally winning IP to primary.
func (f *Fuser) mergeHostIPIdentity(target, src *entity) {
	harvest := func(e *entity) {
		if fs := e.fields["ip"]; fs != nil {
			for _, c := range fs.current {
				target.putMulti("ip_aliases", c.value, c)
			}
			for _, c := range fs.previous {
				target.putMulti("ip_aliases", c.value, c)
			}
		}
		if as := e.fields["ip_aliases"]; as != nil {
			for _, byProv := range as.multiVals {
				for _, c := range byProv {
					target.putMulti("ip_aliases", c.value, c)
				}
			}
		}
	}
	harvest(target)
	harvest(src)

	if sfs := src.fields["ip"]; sfs != nil {
		tfs, ok := target.fields["ip"]
		if !ok {
			tfs = newFieldState("ip", false)
			target.fields["ip"] = tfs
		}
		for prov, c := range sfs.current {
			if old, ok := tfs.current[prov]; !ok || f.rk.better(c, old) {
				if ok && old.value != c.value {
					mergePrevious(tfs, prov, old, f.rk)
				}
				tfs.current[prov] = c
			} else if c.value != old.value {
				mergePrevious(tfs, prov, c, f.rk)
			}
		}
		for prov, c := range sfs.previous {
			mergePrevious(tfs, prov, c, f.rk)
		}
	}

	f.collapseHostIPs(target)
}

// collapseHostIPs turns all non-winning distinct primary IP values of a host
// into peer ip_aliases values instead of fake field conflicts.
func (f *Fuser) collapseHostIPs(h *entity) {
	fs := h.fields["ip"]
	if fs == nil || fs.multi {
		return
	}
	all := append(candMapValues(fs.current), candMapValues(fs.previous)...)
	if len(all) == 0 {
		return
	}
	best := all[0]
	for _, c := range all[1:] {
		if f.rk.better(c, best) {
			best = c
		}
	}
	// the winning primary IP is never its own alias, but other providers that
	// attested the same winning IP must migrate back onto the primary field
	// instead of being discarded
	var bestAliases map[string]candidate
	if as := h.fields["ip_aliases"]; as != nil {
		bestAliases = as.multiVals[best.value]
	}
	values := map[string]struct{}{}
	for _, c := range all {
		if c.value != best.value {
			values[c.value] = struct{}{}
		}
	}
	newCurrent := map[string]candidate{}
	newPrev := map[string]candidate{}
	for prov, c := range fs.current {
		if c.value == best.value {
			newCurrent[prov] = c
		} else {
			h.putMulti("ip_aliases", c.value, c)
		}
	}
	for prov, c := range fs.previous {
		if c.value == best.value {
			newPrev[prov] = c
		} else {
			h.putMulti("ip_aliases", c.value, c)
		}
	}
	for prov, c := range bestAliases {
		if _, ok := newCurrent[prov]; !ok {
			newCurrent[prov] = c
		}
	}
	if as := h.fields["ip_aliases"]; as != nil {
		delete(as.multiVals, best.value)
	}
	fs.current = newCurrent
	fs.previous = newPrev
	if len(fs.current) == 0 {
		fs.current[best.provider] = best
	}
}

func mergeSignals(a, b *hostSignals) *hostSignals {
	if a == nil {
		a = &hostSignals{dnsNames: stringSet{}, certFPS: stringSet{}}
	}
	if b == nil {
		return a
	}
	out := &hostSignals{
		ip:            a.ip,
		asn:           a.asn,
		dnsNames:      stringSet{},
		certFPS:       stringSet{},
		instanceKey:   a.instanceKey,
		accountKey:    a.accountKey,
		cloudProvider: a.cloudProvider,
		cloudRegion:   a.cloudRegion,
	}
	for _, s := range []stringSet{a.dnsNames, b.dnsNames} {
		for v := range s {
			out.dnsNames.add(v)
		}
	}
	for _, s := range []stringSet{a.certFPS, b.certFPS} {
		for v := range s {
			out.certFPS.add(v)
		}
	}
	if out.instanceKey == "" {
		out.instanceKey = b.instanceKey
	}
	if out.accountKey == "" {
		out.accountKey = b.accountKey
	}
	if out.cloudProvider == "" {
		out.cloudProvider = b.cloudProvider
	}
	if out.cloudRegion == "" {
		out.cloudRegion = b.cloudRegion
	}
	if b.asn != 0 && out.asn == 0 {
		out.asn = b.asn
	}
	if out.ip == "" {
		out.ip = b.ip
	}
	return out
}

func (f *Fuser) removeHostFromIndex(id string) {
	removeFrom := func(idx map[string]stringSet) {
		for key, set := range idx {
			delete(set, id)
			if len(set) == 0 {
				delete(idx, key)
			}
		}
	}
	removeFrom(f.sigDNS)
	removeFrom(f.sigCert)
	removeFrom(f.sigInstance)
	removeFrom(f.sigAccount)
}

func (f *Fuser) reindexHost(h *entity) {
	if h.sig == nil {
		return
	}
	for n := range h.sig.dnsNames {
		s := f.sigDNS[n]
		if s == nil {
			s = stringSet{}
			f.sigDNS[n] = s
		}
		s.add(h.id)
	}
	for fp := range h.sig.certFPS {
		s := f.sigCert[fp]
		if s == nil {
			s = stringSet{}
			f.sigCert[fp] = s
		}
		s.add(h.id)
	}
	if h.sig.instanceKey != "" {
		s := f.sigInstance[h.sig.instanceKey]
		if s == nil {
			s = stringSet{}
			f.sigInstance[h.sig.instanceKey] = s
		}
		s.add(h.id)
	}
	if h.sig.accountKey != "" {
		s := f.sigAccount[h.sig.accountKey]
		if s == nil {
			s = stringSet{}
			f.sigAccount[h.sig.accountKey] = s
		}
		s.add(h.id)
	}
}

func (f *Fuser) emit(ctx context.Context, kind EventKind, e *entity) error {
	ev := Event{Kind: kind, Entity: e.snapshot(f.rk, f.aliases)}
	select {
	case f.eventsCh <- ev:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
