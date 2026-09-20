package fusion

import (
	"testing"
)

func TestNormalizeIP(t *testing.T) {
	cases := []struct {
		in   string
		want string
		v    int
	}{
		{"2001:db8::1", "2001:db8::1", 6},
		{"2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1", 6},
		{"2001:DB8::1", "2001:db8::1", 6},
		{"[2001:db8::1]", "2001:db8::1", 6},
		{"2001:db8::1%eth0", "2001:db8::1", 6},
		{"::ffff:192.0.2.1", "192.0.2.1", 4},
		{"::ffff:c000:0201", "192.0.2.1", 4},
		{"192.0.2.1", "192.0.2.1", 4},
		{"2001:db8:0:0:1:0:0:1", "2001:db8::1:0:0:1", 6},
		{"FE80:0:0:0:0:0:0:1", "fe80::1", 6},
	}
	for _, c := range cases {
		got, v, ok := NormalizeIP(c.in)
		if !ok || got != c.want || v != c.v {
			t.Errorf("NormalizeIP(%q) = %q v%d ok%v, want %q v%d", c.in, got, v, ok, c.want, c.v)
		}
	}
	for _, bad := range []string{"", "0.0.0.0", "::", "not-an-ip", "999.1.1.1"} {
		if _, _, ok := NormalizeIP(bad); ok {
			t.Errorf("NormalizeIP(%q) unexpectedly valid", bad)
		}
	}
}

func TestNormalizeDNS(t *testing.T) {
	cases := map[string]string{
		"WWW.Example.COM.":  "www.example.com",
		"*.api.example.com": "api.example.com",
		"a..b.example.com":  "a.b.example.com",
		"Example.COM":       "example.com",
	}
	for in, want := range cases {
		got, ok := NormalizeDNS(in)
		if !ok || got != want {
			t.Errorf("NormalizeDNS(%q) = %q ok%v, want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", ".", "a b.com", "a..", "exa mple.com"} {
		if _, ok := NormalizeDNS(bad); ok {
			t.Errorf("NormalizeDNS(%q) unexpectedly valid", bad)
		}
	}
	if ApexDomain("www.example.co.uk") != "example.co.uk" {
		t.Error("apex heuristic failed for co.uk")
	}
	if ApexDomain("a.b.example.com") != "example.com" {
		t.Error("apex heuristic failed for example.com")
	}
}

func TestNormalizeFingerprint(t *testing.T) {
	long := "AB" + repeat("CD", 31) // 64 hex chars
	want := "ab" + repeat("cd", 31)
	colons := "AB:" + repeat("CD:", 30) + "CD"
	for _, in := range []string{long, colons, want} {
		got, ok := NormalizeFingerprint(in)
		if !ok || got != want {
			t.Errorf("NormalizeFingerprint(%q) = %q ok%v, want %q", in, got, ok, want)
		}
	}
	if got, ok := NormalizeFingerprint("zz"); ok || got != "" {
		t.Error("non-hex fingerprint accepted")
	}
	if _, ok := NormalizeFingerprint("abc"); ok {
		t.Error("short fingerprint accepted")
	}
	if got := FingerprintDER([]byte("hello")); len(got) != 64 {
		t.Errorf("FingerprintDER length = %d, want 64", len(got))
	}
}

func TestNormalizeASN(t *testing.T) {
	cases := map[string]int{
		"AS15133":  15133,
		"as15133":  15133,
		"AS 15,133": 15133,
		"15133":    15133,
	}
	for in, want := range cases {
		got, ok := NormalizeASN(in)
		if !ok || got != want {
			t.Errorf("NormalizeASN(%q) = %d ok%v, want %d", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "AS0", "abc"} {
		if _, ok := NormalizeASN(bad); ok {
			t.Errorf("NormalizeASN(%q) unexpectedly valid", bad)
		}
	}
}

func TestNormalizeCloudID(t *testing.T) {
	// ARN with account -> account identity
	c, ok := NormalizeCloudID("", "arn:aws:ec2:us-east-1:123456789012:instance/i-0abcdef1234567890")
	if !ok || c.Provider != "aws" || c.Type != "account" || c.ID != "123456789012" {
		t.Fatalf("arn normalize failed: %+v ok%v", c, ok)
	}
	key, _ := c.AccountKey()
	if key != "cloud:aws:account:123456789012" {
		t.Errorf("account key = %q", key)
	}

	// bare 12-digit account
	c, ok = NormalizeCloudID("AWS", "123456789012")
	if !ok || c.Type != "account" {
		t.Fatalf("aws account normalize failed: %+v", c)
	}

	// ec2 instance id
	c, ok = NormalizeCloudID("amazon", "i-0abcdef1234567890")
	if !ok || c.Type != "instance" {
		t.Fatalf("aws instance normalize failed: %+v", c)
	}
	ik, _ := c.InstanceKey()
	if ik != "cloud:aws:instance:i-0abcdef1234567890" {
		t.Errorf("instance key = %q", ik)
	}

	// azure subscription guid
	guid := "12345678-1234-1234-1234-123456789012"
	c, ok = NormalizeCloudID("azure", guid)
	if !ok || c.Type != "account" || c.ID != guid {
		t.Fatalf("azure subscription normalize failed: %+v", c)
	}

	// gcp numeric instance
	c, ok = NormalizeCloudID("gcp", "1234567890123456789")
	if !ok || c.Type != "instance" {
		t.Fatalf("gcp instance normalize failed: %+v", c)
	}

	if _, ok := NormalizeCloudID("", ""); ok {
		t.Error("empty cloud id accepted")
	}
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}
