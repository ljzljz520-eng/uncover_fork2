package fusion

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// NormalizeIP parses any IPv4/IPv6 spelling and returns the canonical form:
// IPv4 in dotted quad, IPv6 in RFC 5952 compressed lowercase form. IPv4-mapped
// IPv6 addresses (::ffff:1.2.3.4) are unmapped to IPv4. Brackets, whitespace,
// embedded zone ids and IPv4-compatible spellings are accepted. The returned
// version is 4 or 6. ok is false for unparseable or zero-valued input.
func NormalizeIP(raw string) (canonical string, version int, ok bool) {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	if i := strings.IndexByte(s, '%'); i >= 0 {
		s = s[:i] // zone ids are link-local, not identity
	}
	if s == "" {
		return "", 0, false
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		// fall back to the stdlib parser, which tolerates e.g. leading zeros
		ip := net.ParseIP(s)
		if ip == nil {
			return "", 0, false
		}
		var ok bool
		addr, ok = netip.AddrFromSlice(ip.To16())
		if !ok {
			return "", 0, false
		}
	}
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsUnspecified() {
		return "", 0, false
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if addr.Is4() {
		return addr.String(), 4, true
	}
	return addr.String(), 6, true
}

// NormalizeProtocol lowercases and validates a transport protocol.
func NormalizeProtocol(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	switch p {
	case "tcp", "udp":
		return p
	}
	return ""
}

var dnsInvalid = regexp.MustCompile(`[^a-z0-9.\-_\*]`)

// NormalizeDNS canonicalizes a DNS name: lower case, trimmed, no root dot,
// wildcard label stripped (recorded by caller as inferred=false semantics),
// consecutive dots collapsed. Punycode (xn--) input is preserved as-is.
func NormalizeDNS(name string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(name))
	s = strings.TrimSuffix(s, ".")
	s = strings.TrimPrefix(s, "*.")
	for strings.Contains(s, "..") {
		s = strings.ReplaceAll(s, "..", ".")
	}
	if s == "" || dnsInvalid.MatchString(s) || strings.HasPrefix(s, ".") || strings.HasSuffix(s, "-") {
		return "", false
	}
	// reject labels longer than 63 or names longer than 253
	if len(s) > 253 {
		return "", false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return "", false
		}
	}
	return s, true
}

// multiLabelTLDs holds common second-level suffixes for the deterministic
// apex-domain heuristic. Keys that are not in this table fall back to the
// last two labels. Apex grouping is an asset-field hint only; full FQDNs are
// always the identity keys.
var multiLabelTLDs = map[string]bool{
	"co.uk": true, "org.uk": true, "me.uk": true, "gov.uk": true, "ac.uk": true,
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true, "edu.cn": true,
	"com.hk": true, "com.tw": true, "com.br": true, "com.mx": true,
	"co.jp": true, "or.jp": true, "ne.jp": true, "go.jp": true, "ac.jp": true,
	"co.kr": true, "com.au": true, "net.au": true, "org.au": true, "edu.au": true,
	"co.in": true, "co.nz": true, "com.sg": true, "com.tr": true, "co.za": true,
}

// ApexDomain returns the deterministic registrable-domain hint for a
// normalized DNS name (last two labels, three for known multi-part suffixes).
func ApexDomain(fqdn string) string {
	labels := strings.Split(fqdn, ".")
	n := len(labels)
	if n <= 2 {
		return fqdn
	}
	last2 := strings.Join(labels[n-2:], ".")
	last3 := strings.Join(labels[n-3:], ".")
	if multiLabelTLDs[last2] && n >= 3 {
		return last3
	}
	return last2
}

var (
	hexColonFP = regexp.MustCompile(`[^0-9a-fA-F]`)
	hexOnlyFP  = regexp.MustCompile(`^[0-9a-fA-F]+$`)
)

// NormalizeFingerprint canonicalizes a TLS certificate fingerprint: accepts
// colon/hyphen/space separated hex (SHA-1 40 chars, SHA-256 64 chars) or raw
// hex and returns lowercase hex. Empty/invalid input returns false.
func NormalizeFingerprint(fp string) (string, bool) {
	s := strings.TrimSpace(fp)
	if s == "" {
		return "", false
	}
	if !hexOnlyFP.MatchString(s) {
		s = hexColonFP.ReplaceAllString(s, "")
	}
	s = strings.ToLower(s)
	if len(s) != 40 && len(s) != 64 {
		return "", false
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", false
	}
	return s, true
}

// FingerprintDER returns the lowercase hex SHA-256 fingerprint of DER-encoded
// certificate bytes.
func FingerprintDER(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// NormalizeASN accepts "AS15133", "as 15,133", "15133" etc. and returns the
// integer AS number. ok is false for AS0 or unparseable input.
func NormalizeASN(raw string) (int, bool) {
	s := strings.ToLower(strings.TrimSpace(raw))
	s = strings.TrimPrefix(s, "as")
	s = strings.ReplaceAll(s, ",", "")
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

// NormalizeASNOrg trims an ASN/organization label to a stable comparable form.
func NormalizeASNOrg(org string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(org)), " ")
}

// cloudProviders maps various provider spellings to canonical names.
var cloudProviders = map[string]string{
	"aws": "aws", "amazon": "aws", "amazonaws": "aws", "ec2": "aws",
	"gcp": "gcp", "google": "gcp", "googlecloud": "gcp", "gce": "gcp",
	"azure": "azure", "microsoft": "azure", "microsoftazure": "azure",
	"alibaba": "alibaba", "aliyun": "alibaba",
	"tencent": "tencent", "tencentcloud": "tencent",
	"oracle": "oci", "oci": "oci",
	"digitalocean": "digitalocean", "do": "digitalocean",
	"vultr": "vultr", "linode": "linode", "hetzner": "hetzner",
}

var (
	arnRe     = regexp.MustCompile(`^arn:(aws|aws-cn|aws-us-gov):([a-zA-Z0-9\-]+):([a-z0-9\-]*):(\d{12})?:?(.*)$`)
	accountRe = regexp.MustCompile(`^\d{12}$`)
	uuidRe    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	awsTagRe  = regexp.MustCompile(`^i-[0-9a-f]{8,17}$`)
	gcpInstRe = regexp.MustCompile(`^[0-9]{13,20}$`)
)

// CloudID is a normalized cloud identifier.
//
//	Type is one of: "account" (aws account / gcp project / azure
//	subscription), "instance", "arn" or "resource". Provider is the canonical
//	cloud name (aws/gcp/azure/alibaba/tencent/oci/...).
type CloudID struct {
	Provider string `json:"provider"`
	Type     string `json:"type"`
	ID       string `json:"id"`
	Region   string `json:"region,omitempty"`
	// ARN parts retained when Type == "arn".
	Service string `json:"service,omitempty"`
}

// NormalizeCloudID parses provider-specific cloud identifier spellings into a
// canonical CloudID. The input pair (provider hint, value) follows these
// deterministic rules:
//
//   - value matching an ARN: aws arn (partition, service, region, account and
//     resource are extracted; ID is the account id when present).
//   - 12 decimal digits with provider aws: account id.
//   - GUID with provider azure: subscription id.
//   - i-xxxxxxxx: aws ec2 instance id.
func NormalizeCloudID(providerHint, value string) (*CloudID, bool) {
	p := canonicalCloudProvider(providerHint)
	v := strings.TrimSpace(value)
	if v == "" {
		return nil, false
	}
	if m := arnRe.FindStringSubmatch(v); m != nil {
		cp := "aws"
		if strings.HasPrefix(m[1], "aws-cn") {
			cp = "aws"
		}
		c := &CloudID{Provider: cp, Type: "arn", ID: v, Service: m[2], Region: m[3]}
		if m[4] != "" {
			c.ID = m[4]
			c.Type = "account"
		}
		return c, true
	}
	if accountRe.MatchString(v) && (p == "aws" || p == "") {
		return &CloudID{Provider: "aws", Type: "account", ID: v}, true
	}
	if uuidRe.MatchString(v) && (p == "azure" || p == "") {
		return &CloudID{Provider: "azure", Type: "account", ID: strings.ToLower(v)}, true
	}
	if awsTagRe.MatchString(v) && (p == "aws" || p == "") {
		return &CloudID{Provider: "aws", Type: "instance", ID: v}, true
	}
	if p == "gcp" && gcpInstRe.MatchString(v) {
		return &CloudID{Provider: p, Type: "instance", ID: v}, true
	}
	if p != "" {
		return &CloudID{Provider: p, Type: "resource", ID: v}, true
	}
	return nil, false
}

func canonicalCloudProvider(s string) string {
	s = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	if c, ok := cloudProviders[s]; ok {
		return c
	}
	return s
}

// CloudAccountKey returns the deterministic asset-layer key for the account
// behind a cloud identifier, or false for instance/resource ids that have no
// account context.
func (c *CloudID) AccountKey() (string, bool) {
	switch c.Type {
	case "account":
		return fmt.Sprintf("cloud:%s:account:%s", c.Provider, c.ID), true
	case "arn":
		if c.ID != "" {
			return fmt.Sprintf("cloud:%s:account:%s", c.Provider, c.ID), true
		}
	}
	return "", false
}

// InstanceKey returns the deterministic identity key for a cloud instance.
func (c *CloudID) InstanceKey() (string, bool) {
	if c.Type == "instance" {
		return fmt.Sprintf("cloud:%s:instance:%s", c.Provider, c.ID), true
	}
	if c.Type == "arn" && strings.Contains(c.Service, "ec2") && c.ID != "" {
		return fmt.Sprintf("cloud:%s:instance:%s", c.Provider, c.ID), true
	}
	return "", false
}
