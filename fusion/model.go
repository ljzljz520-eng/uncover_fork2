// Package fusion implements a versioned, provenance-preserving graph fusion
// engine for multi-provider internet-exposure observations.
//
// The graph has four layers:
//
//	observation -> service -> host -> asset
//
// An Observation is one provider attestation at one point in time. Services
// are ip:port endpoints, hosts are IP nodes, assets are DNS names, TLS
// certificates or cloud accounts/resources. Every merged field retains the
// full per-provider evidence chain (provider, original raw record,
// observation time, confidence); conflicting values are never silently
// overwritten — the deterministic winner, all alternatives and the decision
// reason are exported on the field.
//
// Determinism contract:
//
//   - Replaying the same observation sequence always yields byte-identical
//     output (same IDs, versions, winners, revisions and events).
//   - The materialized graph (entities, fields, winner values, evidence and
//     edges, excluding append-only revision logs) is a pure function of the
//     observation set: shuffling arrival order without eviction produces an
//     identical graph.
//   - Memory is bounded by Config.MaxEntities and Config.MaxTotalRawBytes;
//     over-cap work is retired deterministically (oldest LastObservedAt,
//     tie broken by entity ID) and emitted as an event before removal.
package fusion

import (
	"encoding/json"
	"time"
)

// Layer identifies one graph layer.
type Layer string

const (
	LayerObservation Layer = "observation"
	LayerService     Layer = "service"
	LayerHost        Layer = "host"
	LayerAsset       Layer = "asset"
)

// ResolutionMode controls how aggressively distinct identifiers are merged.
type ResolutionMode string

const (
	// ModeConservative merges entities only on exact strong identifiers
	// (canonical ip, canonical ip:port, exact asset key). Soft, signal based
	// cross-identifier merges are disabled.
	ModeConservative ResolutionMode = "conservative"
	// ModeAggressive additionally merges host entities when deterministic
	// signal scores reach ModeThresholdAggressive and no hard contradiction
	// applies (see scoring.go).
	ModeAggressive ResolutionMode = "aggressive"
)

// Observation is the fused input: one record attested by one provider at one
// point in time. Fields may be raw (any IPv6/DNS/ASN spelling) — the fuser
// normalizes them. Raw is the provider's original record, preserved verbatim
// so provider evidence can always be restored after merging.
type Observation struct {
	// ID is optional; when empty a deterministic content ID is derived.
	ID string
	// Provider is the data source name, e.g. "shodan", "censys".
	Provider string
	// ObservedAt is when the provider attested the record.
	ObservedAt time.Time

	// Network endpoint.
	IP       string
	Port     int
	Protocol string // "tcp" / "udp"; empty = unknown (promoted later)
	Service  string // e.g. "http", "ssh"

	// DNS / URL.
	Hostname string
	URL      string

	// TLS certificate (any common fingerprint spelling for Fingerprint;
	// DER can alternatively be supplied and is hashed by the adapter).
	CertFingerprint string
	CertCN          string
	CertIssuer      string

	// Routing.
	ASN    int
	ASNOrg string

	// Cloud identity, when known (see cloud.go for accepted spellings).
	Cloud *CloudID

	// Extra carries additional attested attributes (os, product, version,
	// banner, country, isp, org, ...). Keys are normalized to lower case.
	Extra map[string]string

	// Raw is the verbatim provider payload.
	Raw json.RawMessage
}

// Evidence is one provenance entry for a field value.
type Evidence struct {
	Provider   string          `json:"provider"`
	ObsID      string          `json:"obs_id"`
	ObservedAt time.Time       `json:"observed_at"`
	Confidence float64         `json:"confidence"`
	// Raw is the verbatim provider record backing this evidence. It is
	// retained per provider on the merged entity; RawTruncated is set when a
	// bounded-memory trim had to drop the blob (metadata is still kept).
	Raw          json.RawMessage `json:"raw,omitempty"`
	RawTruncated bool            `json:"raw_truncated,omitempty"`
	// Inferred marks values derived by a deterministic rule rather than
	// stated directly by the provider.
	Inferred bool `json:"inferred,omitempty"`
}

// ConflictCandidate is one competing value for a field.
type ConflictCandidate struct {
	Value      string    `json:"value"`
	Evidence   Evidence  `json:"evidence"`
	ScoreTuple string    `json:"score_tuple"`
	Reason     string    `json:"reason"`
}

// Conflict describes a disagreement that was resolved, never overwritten.
type Conflict struct {
	// Code is the machine readable conflict class:
	// "provider_disagreement" or "value_changed_over_time".
	Code   string `json:"code"`
	Rule   string `json:"rule"`
	Winner string `json:"winner"`
	// Reason is the deterministic, human readable decision explanation.
	Reason     string              `json:"reason"`
	Candidates []ConflictCandidate `json:"candidates"`
}

// Field is one versioned attribute of a merged entity.
type Field struct {
	Name       string  `json:"name"`
	Value      string  `json:"value"`
	Confidence float64 `json:"confidence"`
	Version    int64   `json:"version"`
	// Evidences is one current entry per contributing provider, ordered by
	// deterministic winner rank.
	Evidences []Evidence `json:"evidences"`
	// Conflict is present when two or more distinct values compete.
	Conflict *Conflict `json:"conflict,omitempty"`
	// Multi marks identity-set fields (e.g. ip_aliases, hostnames) where all
	// values are peers instead of a single winner; Values then carries them.
	Multi  bool     `json:"multi,omitempty"`
	Values []string `json:"values,omitempty"`
}

// EdgeProvenance records which providers attested an edge.
type EdgeProvenance struct {
	Provider   string    `json:"provider"`
	ObsID      string    `json:"obs_id"`
	ObservedAt time.Time `json:"observed_at"`
	Confidence float64   `json:"confidence"`
}

// Edge is a provenance-bearing directed link between graph entities.
type Edge struct {
	Type       string          `json:"type"`
	From       string          `json:"from"`
	To         string          `json:"to"`
	Provenance []EdgeProvenance `json:"provenance"`
}

// Revision is an append-only, per-entity audit entry. Revision logs reflect
// the actual ingest sequence (like any changelog); the materialized entity
// state itself is independent of ingest order.
type Revision struct {
	Seq    int64     `json:"seq"`
	At     time.Time `json:"at"`
	ObsID  string    `json:"obs_id"`
	Detail string    `json:"detail"`
}

// RawRecord is a retained verbatim provider payload.
type RawRecord struct {
	ObsID      string          `json:"obs_id"`
	ObservedAt time.Time       `json:"observed_at"`
	Raw        json.RawMessage `json:"raw,omitempty"`
	// Truncated is true when the blob was dropped under memory pressure;
	// provider/obs/time metadata is still preserved.
	Truncated bool `json:"truncated,omitempty"`
}

// Entity is an immutable snapshot of one merged graph node.
type Entity struct {
	ID      string `json:"id"`
	Layer   Layer  `json:"layer"`
	Version int64  `json:"version"`

	CreatedAt  time.Time `json:"created_at"`
	FirstObsAt time.Time `json:"first_obs_at"`
	LastObsAt  time.Time `json:"last_obs_at"`

	// IdentityKeys are the deterministic blocking keys contributed by
	// evidence, sorted and deduplicated.
	IdentityKeys []string `json:"identity_keys"`

	Fields     []Field          `json:"fields"`
	Edges      []Edge           `json:"edges"`
	Revisions  []Revision       `json:"revisions"`
	Providers  []string         `json:"providers"`
	ProviderEvidence map[string][]RawRecord `json:"provider_evidence,omitempty"`

	// Reincarnated is set when the entity had been retired under memory
	// pressure and was later observed again: history before retirement was
	// emitted in the earlier retire event.
	Reincarnated bool `json:"reincarnated,omitempty"`
}

// Graph is a materialized snapshot of the fusion store.
type Graph struct {
	Entities []*Entity `json:"entities"`
}

// EventKind enumerates deterministic fuser output events.
type EventKind string

const (
	// EventRetire: an entity was retired to respect memory bounds; snapshot
	// is final until a possible later EventReincarnate.
	EventRetire EventKind = "retire"
	// EventReincarnate: a previously retired entity was observed again.
	EventReincarnate EventKind = "reincarnate"
	// EventUpsert: an entity changed while streaming (only with
	// Config.EmitUpdates).
	EventUpsert EventKind = "upsert"
	// EventSnapshot: final ordered snapshot emitted by Close.
	EventSnapshot EventKind = "snapshot"
)

// Event is one deterministic output of the fuser.
type Event struct {
	Kind   EventKind `json:"kind"`
	Entity *Entity   `json:"entity"`
}

// Stats exposes bounded-resource accounting.
type Stats struct {
	Observed       int64 `json:"observed"`
	ActiveEntities int   `json:"active_entities"`
	Retired        int64 `json:"retired"`
	Merged         int64 `json:"merged"`
	ActiveRawBytes int64 `json:"active_raw_bytes"`
	TruncatedRaws  int64 `json:"truncated_raws"`
	DroppedInvalid int64 `json:"dropped_invalid"`
}

const (
	defaultMaxEntities        = 100000
	defaultMaxProviderRaws    = 3
	defaultMaxProviderRawSize = 16 * 1024
	defaultMaxTotalRawBytes   = 256 * 1024 * 1024
	defaultMaxEvidences       = 64
	defaultMaxRevisions       = 128
	defaultEventBuffer        = 256
)

// Config configures a Fuser. Zero value fields fall back to documented
// defaults. The fuser never allocates beyond the configured caps.
type Config struct {
	// Mode selects conservative (default) or aggressive resolution.
	Mode ResolutionMode

	// MaxEntities is the hard cap on simultaneously materialized entities.
	MaxEntities int
	// MaxProviderRaws is how many verbatim payloads to keep per
	// (entity, provider); newest records are retained.
	MaxProviderRaws int
	// MaxProviderRawBytes is the per (entity, provider) raw byte budget.
	MaxProviderRawBytes int
	// MaxTotalRawBytes is the hard global raw-byte budget. When exceeded the
	// oldest non-last blobs are trimmed first; if still exceeded the oldest
	// entities are retired. The newest raw of every contributing provider is
	// never dropped while an entity stays active.
	MaxTotalRawBytes int64
	// MaxEvidencesPerField bounds evidence entries kept on one field.
	MaxEvidencesPerField int
	// MaxRevisions bounds the per-entity append-only revision log.
	MaxRevisions int
	// EventBuffer bounds the internal event channel (backpressure applies).
	EventBuffer int

	// ProviderConfidence optionally overrides base provider confidence
	// (0..1). Unknown providers default to 0.70.
	ProviderConfidence map[string]float64

	// EmitUpdates emits EventUpsert on every entity change.
	EmitUpdates bool

	// Now overrides revision wall-clock time (tests / replay); defaults to
	// the observation time of the triggering record.
	Now func() time.Time
}

func (c *Config) withDefaults() {
	if c.Mode == "" {
		c.Mode = ModeConservative
	}
	if c.MaxEntities <= 0 {
		c.MaxEntities = defaultMaxEntities
	}
	if c.MaxProviderRaws <= 0 {
		c.MaxProviderRaws = defaultMaxProviderRaws
	}
	if c.MaxProviderRawBytes <= 0 {
		c.MaxProviderRawBytes = defaultMaxProviderRawSize
	}
	if c.MaxTotalRawBytes <= 0 {
		c.MaxTotalRawBytes = defaultMaxTotalRawBytes
	}
	if c.MaxEvidencesPerField <= 0 {
		c.MaxEvidencesPerField = defaultMaxEvidences
	}
	if c.MaxRevisions <= 0 {
		c.MaxRevisions = defaultMaxRevisions
	}
	if c.EventBuffer <= 0 {
		c.EventBuffer = defaultEventBuffer
	}
}
