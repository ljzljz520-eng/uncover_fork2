package fusion

import (
	"container/heap"
	"context"
	"time"
)

// ---- deterministic eviction heap: min (lastObs, entityID) ----

type evictEntry struct {
	id   string
	last unixNano
	idx  int
}

type evictionHeap []*evictEntry

func (h evictionHeap) Len() int { return len(h) }
func (h evictionHeap) Less(i, j int) bool {
	if h[i].last != h[j].last {
		return h[i].last < h[j].last
	}
	return h[i].id < h[j].id
}
func (h evictionHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].idx = i
	h[j].idx = j
}
func (h *evictionHeap) Push(x any) {
	e := x.(*evictEntry)
	e.idx = len(*h)
	*h = append(*h, e)
}
func (h *evictionHeap) Pop() any {
	old := *h
	n := len(old)
	e := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	e.idx = -1
	return e
}

func (h *evictionHeap) update(e *entity) {
	if e.heapIdx >= 0 {
		ent := (*h)[e.heapIdx]
		if ent.id == e.id {
			ent.last = e.lastObs
			heap.Fix(h, e.heapIdx)
			return
		}
		e.heapIdx = -1
	}
	ent := &evictEntry{id: e.id, last: e.lastObs}
	heap.Push(h, ent)
	e.heapIdx = ent.idx
}

// ---- global raw-byte heap: min (observedAt, entityID, obsID) ----

type rawEntry struct {
	eid      string
	provider string
	obsID    string
	at       unixNano
	size     int
	idx      int
}

type rawHeap []*rawEntry

func (h rawHeap) Len() int { return len(h) }
func (h rawHeap) Less(i, j int) bool {
	if h[i].at != h[j].at {
		return h[i].at < h[j].at
	}
	if h[i].eid != h[j].eid {
		return h[i].eid < h[j].eid
	}
	return h[i].obsID < h[j].obsID
}
func (h rawHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].idx = i
	h[j].idx = j
}
func (h *rawHeap) Push(x any) {
	e := x.(*rawEntry)
	e.idx = len(*h)
	*h = append(*h, e)
}
func (h *rawHeap) Pop() any {
	old := *h
	n := len(old)
	e := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	e.idx = -1
	return e
}

func (h *rawHeap) push(e *rawEntry) { heap.Push(h, e) }

// enforceLimits keeps both caps after every ingest: the entity count cap and
// the global raw-byte cap. Trimming never drops the newest blob of any
// contributing provider; when even that cannot satisfy the byte budget, the
// oldest raw-holding entity is retired deterministically.
func (f *Fuser) enforceLimits(ctx context.Context) error {
	for len(f.entities) > f.cfg.MaxEntities {
		retired, err := f.retireOldest(ctx, false)
		if err != nil {
			return err
		}
		if !retired {
			break
		}
	}
	for f.stats.ActiveRawBytes > f.cfg.MaxTotalRawBytes {
		var protected []*rawEntry
		trimmed := false
		for f.rawQ.Len() > 0 {
			entry := heap.Pop(&f.rawQ).(*rawEntry)
			ent := f.entities[entry.eid] // canonical entities only
			if ent == nil {
				continue // stale: source entity merged away or retired
			}
			rec := ent.findLiveRaw(entry.provider, entry.obsID)
			if rec == nil || len(rec.Raw) != entry.size {
				continue
			}
			if countNonTruncated(ent, entry.provider) <= 1 {
				protected = append(protected, entry) // newest-per-provider guarantee
				continue
			}
			rec.Truncated = true
			f.stats.ActiveRawBytes -= int64(len(rec.Raw))
			rec.Raw = nil
			f.stats.TruncatedRaws++
			trimmed = true
			break
		}
		for _, e := range protected {
			f.rawQ.push(e)
		}
		if !trimmed {
			done, err := f.retireOldest(ctx, true)
			if err != nil {
				return err
			}
			if !done {
				break // no raw-holding entity remains; nothing more to do
			}
		}
	}
	return nil
}

// findLiveRaw returns a pointer to a still-retained non-empty blob.
func (e *entity) findLiveRaw(provider, obsID string) *RawRecord {
	for i := range e.raws[provider] {
		r := &e.raws[provider][i]
		if r.ObsID == obsID && len(r.Raw) > 0 {
			return r
		}
	}
	return nil
}

func countNonTruncated(e *entity, provider string) int {
	n := 0
	for _, r := range e.raws[provider] {
		if len(r.Raw) > 0 {
			n++
		}
	}
	return n
}

// retireOldest deterministically retires the bottom of the eviction heap.
// When rawsOnly is set, entities without retained raw payloads are skipped.
func (f *Fuser) retireOldest(ctx context.Context, rawsOnly bool) (bool, error) {
	var deferred []*evictEntry
	for f.evictQ.Len() > 0 {
		entry := heap.Pop(&f.evictQ).(*evictEntry)
		e := f.entities[entry.id]
		if e == nil || e.heapIdx < 0 {
			continue // stale alias entry
		}
		if rawsOnly && e.rawsByteCount() == 0 {
			deferred = append(deferred, entry)
			continue
		}
		for _, d := range deferred {
			heap.Push(&f.evictQ, d)
		}
		if err := f.retire(ctx, entry.id); err != nil {
			return false, err
		}
		return true, nil
	}
	for _, d := range deferred {
		heap.Push(&f.evictQ, d)
	}
	return false, nil
}

func (e *entity) rawsByteCount() int64 {
	n := int64(0)
	for _, recs := range e.raws {
		for _, r := range recs {
			n += int64(len(r.Raw))
		}
	}
	return n
}

func (f *Fuser) retire(ctx context.Context, id string) error {
	e := f.entities[id]
	if e == nil {
		return nil
	}
	if err := f.emit(ctx, EventRetire, e); err != nil {
		return err
	}
	for k := range e.keys {
		if f.keyIndex[k] == id {
			delete(f.keyIndex, k)
		}
	}
	if e.layer == LayerHost {
		f.removeHostFromIndex(id)
	}
	for prov, recs := range e.raws {
		for _, r := range recs {
			f.stats.ActiveRawBytes -= int64(len(r.Raw))
		}
		delete(e.raws, prov)
	}
	delete(f.entities, id)
	// drop aliases that pointed at the retired canonical node
	for from, to := range f.aliases {
		if to == id || from == id {
			delete(f.aliases, from)
		}
	}
	f.seq++
	f.retired[id] = f.seq
	if len(f.retired) > f.cfg.MaxEntities {
		smallest := ""
		for k := range f.retired {
			if smallest == "" || k < smallest {
				smallest = k
			}
		}
		delete(f.retired, smallest)
	}
	e.heapIdx = -1
	f.stats.Retired++
	return nil
}

func jsonRawCopy(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func timeUnix(t unixNano) time.Time { return time.Unix(0, int64(t)) }
