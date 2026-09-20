package fusion

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/projectdiscovery/uncover/sources"
)

// ResultToObservation adapts a flat sources.Result (any uncover agent output)
// into a fusion Observation. Structured fields are taken from the result; when
// the agent retained its original payload (Result.Raw), well-known paths from
// shodan/censys/fofa-style records are additionally extracted in a
// provider-neutral best effort. The verbatim raw payload is always preserved.
func ResultToObservation(r sources.Result) Observation {
	o := Observation{
		Provider:   strings.ToLower(strings.TrimSpace(r.Source)),
		ObservedAt: time.Unix(r.Timestamp, 0),
		IP:         strings.TrimSpace(r.IP),
		Port:       r.Port,
		Hostname:   strings.TrimSpace(r.Host),
		URL:        strings.TrimSpace(r.Url),
		Raw:        append(json.RawMessage(nil), r.Raw...),
		Extra:      map[string]string{},
	}
	enrichFromRaw(&o, r.Raw)
	if len(o.Extra) == 0 {
		o.Extra = nil
	}
	return o
}

func enrichFromRaw(o *Observation, raw []byte) {
	if len(raw) == 0 {
		return
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return
	}
	m, ok := doc.(map[string]any)
	if !ok {
		return
	}
	// altScalar returns the first non-empty scalar among alternative paths.
	altScalar := func(paths ...[]string) string {
		for _, p := range paths {
			if v := scalarString(dig(m, p...)); v != "" {
				return v
			}
		}
		return ""
	}
	altFirst := func(paths ...[]string) string {
		for _, p := range paths {
			if v := firstString(dig(m, p...)); v != "" {
				return v
			}
		}
		return ""
	}

	if o.Hostname == "" {
		o.Hostname = altFirst(
			[]string{"hostname"}, []string{"domain"},
			[]string{"dns", "names"}, []string{"hostnames"},
			[]string{"dns", "reverse_dns", "names"},
		)
	}

	if o.CertFingerprint == "" {
		fp := altScalar(
			[]string{"ssl", "sha256"}, []string{"ssl", "sha1"},
			[]string{"ssl", "cert", "sha256"}, []string{"ssl", "cert", "fingerprint"},
			[]string{"ssl", "fingerprint"}, []string{"cert", "sha256"},
			[]string{"certificate_fingerprint"}, []string{"certificate_fp"},
			[]string{"fingerprint"},
		)
		if canon, ok := NormalizeFingerprint(fp); ok {
			o.CertFingerprint = canon
		}
	}
	if o.CertCN == "" {
		o.CertCN = altScalar([]string{"ssl", "cert", "subject", "cn"})
	}
	if o.CertIssuer == "" {
		o.CertIssuer = altScalar([]string{"ssl", "cert", "issuer", "cn"})
	}

	if o.ASN == 0 {
		if asn, ok := NormalizeASN(altScalar(
			[]string{"asn"}, []string{"as_number"}, []string{"asno"}, []string{"as_num"},
		)); ok {
			o.ASN = asn
		}
	}
	if o.ASNOrg == "" {
		o.ASNOrg = altScalar(
			[]string{"asn_org"}, []string{"asn", "organization"},
			[]string{"asn", "org"}, []string{"isp"},
		)
	}
	addExtra := func(key string, paths ...[]string) {
		if v := altScalar(paths...); v != "" {
			o.Extra[key] = v
		}
	}
	addExtra("os", []string{"os"}, []string{"operating_system"})
	addExtra("product", []string{"product"})
	addExtra("version", []string{"version"})
	addExtra("banner", []string{"data"}, []string{"banner"})
	addExtra("title", []string{"http", "title"}, []string{"title"})
	addExtra("service", []string{"service"}, []string{"name"}, []string{"_shodan.module"})
	addExtra("country", []string{"location", "country_name"}, []string{"country_name"}, []string{"country"})
	addExtra("city", []string{"location", "city"}, []string{"city"})
	addExtra("isp", []string{"isp"})
	addExtra("org", []string{"org"}, []string{"organization"})

	// cloud identity: explicit cloud block first, then tag-based provider hint
	var hint, account, instance, region string
	if cp := asMap(dig(m, "cloud")); cp != nil {
		hint = scalarString(dig(cp, "provider"))
		account = altScalarOn(cp,
			[]string{"account"}, []string{"account_id"}, []string{"project"},
			[]string{"project_id"}, []string{"subscription"}, []string{"subscription_id"},
		)
		instance = altScalarOn(cp, []string{"instance"}, []string{"instance_id"}, []string{"vm_id"})
		region = scalarString(dig(cp, "region"))
	}
	if hint == "" {
		hint = cloudHintFromTags(m)
	}
	if account == "" {
		account = altScalar(
			[]string{"cloud_account"}, []string{"account_id"}, []string{"aws_account_id"},
			[]string{"project_id"}, []string{"subscription_id"},
		)
	}
	if instance == "" {
		instance = altScalar([]string{"instance_id"}, []string{"vm_id"})
	}
	if region == "" {
		region = altScalar([]string{"location", "region_code"}, []string{"region"})
	}
	id := account
	typ := "account"
	if id == "" && instance != "" {
		id, typ = instance, "instance"
	}
	if hint != "" && id != "" {
		if c, ok := NormalizeCloudID(hint, id); ok {
			c.Region = strings.ToLower(strings.TrimSpace(region))
			// NormalizeCloudID may reinterpret the value type; trust explicit
			// instance hints from the raw record.
			if typ == "instance" && c.Type != "instance" && c.Type == "resource" {
				c.Type = "instance"
			}
			o.Cloud = c
		}
	}
}

func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}

// dig walks a normalized JSON document following path keys.
func dig(v any, path ...string) any {
	cur := v
	for _, key := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = m[key]
		if !ok {
			return nil
		}
	}
	return cur
}

// scalarString renders a JSON scalar; arrays and objects yield "".
func scalarString(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%v", t)
	case bool:
		return fmt.Sprintf("%t", t)
	default:
		return ""
	}
}

// firstString accepts a scalar string or the first element of a string array.
func firstString(v any) string {
	if s := scalarString(v); s != "" {
		return s
	}
	if arr, ok := v.([]any); ok && len(arr) > 0 {
		return scalarString(arr[0])
	}
	return ""
}

func altScalarOn(m map[string]any, paths ...[]string) string {
	for _, p := range paths {
		if v := scalarString(dig(m, p...)); v != "" {
			return v
		}
	}
	return ""
}

func cloudHintFromTags(m map[string]any) string {
	tags, ok := dig(m, "tags").([]any)
	if !ok {
		return ""
	}
	for _, t := range tags {
		s, ok := t.(string)
		if !ok {
			continue
		}
		if c := canonicalCloudProvider(s); c != "" {
			return c
		}
	}
	return ""
}
