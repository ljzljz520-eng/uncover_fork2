package fusion

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// baseProviderConfidence assigns each supported provider a fixed base
// confidence. Values are part of the deterministic decision rule set: do not
// change without bumping the rule version. Unknown providers default to 0.70.
var baseProviderConfidence = map[string]float64{
	"shodan":     0.90,
	"censys":     0.90,
	"netlas":     0.88,
	"fofa":       0.85,
	"quake":      0.82,
	"hunter":     0.82,
	"zoomeye":    0.82,
	"binaryedge": 0.80,
	"onyphe":     0.80,
	"greynoise":  0.78,
	"shodan-idb": 0.78,
	"criminalip": 0.78,
	"google":     0.75,
	"odin":       0.75,
	"hunterhow":  0.75,
	"publicwww":  0.72,
	"driftnet":   0.72,
	"daydaymap":  0.72,
	"nerdydata":  0.70,
}

const defaultProviderConfidence = 0.70

// Rule version: emitted in conflict/merge explanations so decision logic is
// traceable across releases.
const RuleVersion = "fusion-rules-1"

// ModeThresholdAggressive is the deterministic score at/above which aggressive
// mode merges two distinct-IP host entities.
const ModeThresholdAggressive = 0.70

type ranker struct {
	overrides map[string]float64
}

func (r ranker) baseConfidence(provider string) float64 {
	if c, ok := r.overrides[provider]; ok && c >= 0 && c <= 1 {
		return c
	}
	if c, ok := baseProviderConfidence[provider]; ok {
		return c
	}
	return defaultProviderConfidence
}

// evidenceConfidence computes the final 0..1 confidence of one attested value:
// provider base confidence, discounted for inferred/derived attributes.
func (r ranker) evidenceConfidence(provider string, inferred bool) float64 {
	c := r.baseConfidence(provider)
	if inferred {
		c *= 0.85
	}
	return round2(c)
}

// candidate is one provider's current attestation of a field.
type candidate struct {
	value    string
	provider string
	obsID    string
	at       unixNano
	conf     float64
	inferred bool
}

// unixNano is the deterministic time representation used in all comparisons.
type unixNano int64

// better reports whether a outranks b as the field winner. The ranking is a
// total order, so ties are impossible:
//
//  1. higher evidence confidence
//  2. higher provider base confidence (source authority)
//  3. more recent observation (fresher)
//  4. lexicographically smaller value (stable, content based)
//  5. lexicographically smaller provider name
//  6. lexicographically smaller observation id (final content tiebreak)
func (r ranker) better(a, b candidate) bool {
	if a.conf != b.conf {
		return a.conf > b.conf
	}
	ab, bb := r.baseConfidence(a.provider), r.baseConfidence(b.provider)
	if ab != bb {
		return ab > bb
	}
	if a.at != b.at {
		return a.at > b.at
	}
	if a.value != b.value {
		return a.value < b.value
	}
	if a.provider != b.provider {
		return a.provider < b.provider
	}
	return a.obsID < b.obsID
}

// scoreTuple renders the comparable decision tuple for export.
func (r ranker) scoreTuple(c candidate) string {
	return fmt.Sprintf("conf=%.2f,base=%.2f,obs=%d,value=%q,provider=%q",
		c.conf, r.baseConfidence(c.provider), int64(c.at), c.value, c.provider)
}

// explainWinner renders the deterministic reason one candidate won.
func (r ranker) explainWinner(w, l candidate) string {
	switch {
	case w.conf > l.conf:
		return fmt.Sprintf("higher evidence confidence %.2f > %.2f", w.conf, l.conf)
	case r.baseConfidence(w.provider) > r.baseConfidence(l.provider):
		return fmt.Sprintf("provider authority %s(%.2f) > %s(%.2f)",
			w.provider, r.baseConfidence(w.provider), l.provider, r.baseConfidence(l.provider))
	case w.at > l.at:
		return "equal confidence; more recent observation wins"
	case w.value != l.value:
		return "all signals tied; stable lexicographic value tiebreak"
	default:
		return "all signals tied; stable provider name tiebreak"
	}
}

// ruleVote is one explainable contribution to a merge score.
type ruleVote struct {
	rule   string
	weight float64
	why    string
}

func (v ruleVote) String() string {
	return fmt.Sprintf("%s(+%.2f: %s)", v.rule, v.weight, v.why)
}

// matchResult is the deterministic verdict when comparing two distinct-IP
// hosts. Votes are sorted by rule name before rendering so explanations are
// independent of evaluation order.
type matchResult struct {
	score         float64
	votes         []ruleVote
	contradiction string
}

func (m matchResult) explain() string {
	parts := make([]string, 0, len(m.votes))
	for _, v := range m.votes {
		parts = append(parts, v.String())
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

// scoreHostMerge evaluates whether two hosts with different canonical IPs
// describe the same physical/logical machine. Signals are taken from already
// normalized host state. Conservative callers must skip this entirely.
func scoreHostMerge(a, b *hostSignals) matchResult {
	res := matchResult{}

	// Hard contradictions: never merge.
	if a.instanceKey != "" && b.instanceKey != "" && a.instanceKey != b.instanceKey {
		res.contradiction = "distinct cloud instance identities"
		return res
	}
	if a.cloudProvider != "" && b.cloudProvider != "" && a.cloudProvider != b.cloudProvider {
		res.contradiction = "distinct cloud providers"
		return res
	}
	near := networkProximate(a.ip, b.ip)

	// Strong identity: exact cloud instance id.
	if a.instanceKey != "" && a.instanceKey == b.instanceKey {
		res.votes = append(res.votes, ruleVote{
			"exact_cloud_instance", 0.95, "same cloud instance id " + a.instanceKey,
		})
	}

	// Hostname evidence, accepted only with network proximity.
	if near && intersects(a.dnsNames, b.dnsNames) {
		res.votes = append(res.votes, ruleVote{
			"shared_dns_and_netblock", 0.60, "shared hostname within same netblock",
		})
		if a.asn > 0 && a.asn == b.asn {
			res.votes = append(res.votes, ruleVote{
				"same_asn", 0.15, fmt.Sprintf("both originated in AS%d", a.asn),
			})
		}
	}

	// Certificate evidence, accepted only with network proximity.
	if near && intersects(a.certFPS, b.certFPS) {
		res.votes = append(res.votes, ruleVote{
			"shared_cert_and_netblock", 0.70, "identical TLS certificate within same netblock",
		})
	}

	// Same cloud account + region + netblock.
	if a.accountKey != "" && a.accountKey == b.accountKey && near &&
		a.cloudRegion != "" && a.cloudRegion == b.cloudRegion {
		res.votes = append(res.votes, ruleVote{
			"same_cloud_account_region_netblock", 0.70,
			"same cloud account and region within same netblock",
		})
	}

	for _, v := range res.votes {
		res.score += v.weight
	}
	if res.score > 0.95 {
		res.score = 0.95
	}
	return res
}

// networkProximate returns true when two canonical IPs are in the same IPv4
// /24 or IPv6 /64 — a deliberately narrow, deterministic netblock rule.
func networkProximate(ipa, ipb string) bool {
	a, err1 := netip.ParseAddr(ipa)
	b, err2 := netip.ParseAddr(ipb)
	if err1 != nil || err2 != nil || a.Is4() != b.Is4() {
		return false
	}
	bits := 24
	if a.Is6() {
		bits = 64
	}
	pa := netip.PrefixFrom(a, bits).Masked()
	pb := netip.PrefixFrom(b, bits).Masked()
	return pa == pb
}

func intersects(a, b stringSet) bool {
	small, large := a, b
	if len(b) < len(a) {
		small, large = b, a
	}
	for v := range small {
		if large.has(v) {
			return true
		}
	}
	return false
}

type stringSet map[string]struct{}

func (s stringSet) add(v string) {
	if v != "" {
		s[v] = struct{}{}
	}
}

func (s stringSet) has(v string) bool {
	_, ok := s[v]
	return ok
}

func (s stringSet) sorted() []string {
	out := make([]string, 0, len(s))
	for v := range s {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func round2(f float64) float64 {
	return float64(int64(f*100+0.5)) / 100
}
