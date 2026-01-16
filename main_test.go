package main

import (
	"bytes"
	"io"
	"net"
	"os/exec"
	"strings"
	"testing"
)

func TestParseCIDR(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantNil bool
		wantErr bool
	}{
		// Valid IPv4 CIDRs
		{name: "IPv4 /24", input: "192.168.1.0/24", want: "192.168.1.0/24"},
		{name: "IPv4 /32", input: "10.0.0.1/32", want: "10.0.0.1/32"},
		{name: "IPv4 /0", input: "0.0.0.0/0", want: "0.0.0.0/0"},
		{name: "IPv4 /16", input: "172.16.0.0/16", want: "172.16.0.0/16"},

		// Plain IPs (should get /32 or /128)
		{name: "Plain IPv4", input: "192.168.1.1", want: "192.168.1.1/32"},
		{name: "Plain IPv6", input: "2001:db8::1", want: "2001:db8::1/128"},

		// Valid IPv6 CIDRs
		{name: "IPv6 /64", input: "2001:db8::/64", want: "2001:db8::/64"},
		{name: "IPv6 /128", input: "2001:db8::1/128", want: "2001:db8::1/128"},
		{name: "IPv6 /48", input: "2001:db8:abcd::/48", want: "2001:db8:abcd::/48"},

		// Whitespace handling
		{name: "Leading whitespace", input: "  192.168.1.0/24", want: "192.168.1.0/24"},
		{name: "Trailing whitespace", input: "192.168.1.0/24  ", want: "192.168.1.0/24"},
		{name: "Both whitespace", input: "  192.168.1.0/24  ", want: "192.168.1.0/24"},

		// Comment handling (Spamhaus format)
		{name: "Semicolon comment", input: "192.168.1.0/24 ; SBL123", want: "192.168.1.0/24"},
		{name: "Hash comment", input: "192.168.1.0/24 # comment", want: "192.168.1.0/24"},
		{name: "Tab then comment", input: "192.168.1.0/24\t; comment", want: "192.168.1.0/24"},

		// Skip lines (return nil, nil)
		{name: "Empty line", input: "", wantNil: true},
		{name: "Whitespace only", input: "   ", wantNil: true},
		{name: "Comment line hash", input: "# this is a comment", wantNil: true},
		{name: "Comment line semicolon", input: "; this is a comment", wantNil: true},
		{name: "Whitespace then comment", input: "   ; comment only", wantNil: true},
		{name: "Tab then hash comment", input: "\t# comment", wantNil: true},
		{name: "Space before semicolon", input: " ;", wantNil: true},

		// Invalid inputs (negative flow)
		{name: "Invalid IP", input: "not.an.ip/24", wantErr: true},
		{name: "Invalid prefix too large", input: "192.168.1.0/33", wantErr: true},
		{name: "Invalid prefix negative", input: "192.168.1.0/-1", wantErr: true},
		{name: "IPv6 invalid prefix", input: "2001:db8::/129", wantErr: true},
		{name: "Malformed missing octet", input: "192.168.1/24", wantErr: true},
		{name: "Malformed double slash", input: "192.168.1.0//24", wantErr: true},
		{name: "Malformed just slash", input: "/24", wantErr: true},
		{name: "Malformed letters in IP", input: "192.168.a.1/24", wantErr: true},
		{name: "Malformed too many octets", input: "192.168.1.1.1/24", wantErr: true},
		{name: "Malformed negative octet", input: "192.168.-1.0/24", wantErr: true},
		{name: "Malformed octet too large", input: "192.168.256.0/24", wantErr: true},

		// Edge cases
		{name: "Zero IP /32", input: "0.0.0.0/32", want: "0.0.0.0/32"},
		{name: "Max IPv4 /32", input: "255.255.255.255/32", want: "255.255.255.255/32"},
		{name: "IPv4 default route", input: "0.0.0.0/0", want: "0.0.0.0/0"},
		{name: "IPv6 loopback", input: "::1", want: "::1/128"},
		{name: "IPv6 default route", input: "::/0", want: "::/0"},
		{name: "IPv6 max address", input: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"},
		{name: "IPv4-mapped IPv6 normalised to IPv4", input: "::ffff:192.168.1.1/128", want: "192.168.1.1/32"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCIDR(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseCIDR(%q) expected error, got nil", tt.input)
				}
				return
			}

			if err != nil {
				t.Errorf("parseCIDR(%q) unexpected error: %v", tt.input, err)
				return
			}

			if tt.wantNil {
				if got != nil {
					t.Errorf("parseCIDR(%q) expected nil, got %v", tt.input, got)
				}
				return
			}

			if got == nil {
				t.Errorf("parseCIDR(%q) got nil, want %q", tt.input, tt.want)
				return
			}

			if got.String() != tt.want {
				t.Errorf("parseCIDR(%q) = %q, want %q", tt.input, got.String(), tt.want)
			}
		})
	}
}

func TestCIDRContains(t *testing.T) {
	tests := []struct {
		name  string
		cidr  string
		other string
		want  bool
	}{
		// IPv4 containment
		{name: "/24 contains /32", cidr: "192.168.1.0/24", other: "192.168.1.100/32", want: true},
		{name: "/24 contains /25", cidr: "192.168.1.0/24", other: "192.168.1.0/25", want: true},
		{name: "/24 contains /24 same", cidr: "192.168.1.0/24", other: "192.168.1.0/24", want: true},
		{name: "/24 not contains different /24", cidr: "192.168.1.0/24", other: "192.168.2.0/24", want: false},
		{name: "/32 not contains /24", cidr: "192.168.1.1/32", other: "192.168.1.0/24", want: false},
		{name: "/16 contains /24", cidr: "192.168.0.0/16", other: "192.168.1.0/24", want: true},
		{name: "/0 contains all", cidr: "0.0.0.0/0", other: "192.168.1.0/24", want: true},

		// IPv6 containment
		{name: "IPv6 /64 contains /128", cidr: "2001:db8::/64", other: "2001:db8::1/128", want: true},
		{name: "IPv6 /48 contains /64", cidr: "2001:db8::/48", other: "2001:db8::/64", want: true},
		{name: "IPv6 /64 not contains different /64", cidr: "2001:db8::/64", other: "2001:db9::/64", want: false},

		// Cross-version (should not contain)
		{name: "IPv4 not contains IPv6", cidr: "0.0.0.0/0", other: "2001:db8::/64", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidr, _ := parseCIDR(tt.cidr)
			other, _ := parseCIDR(tt.other)

			got := cidr.Contains(other)
			if got != tt.want {
				t.Errorf("CIDR(%q).Contains(%q) = %v, want %v", tt.cidr, tt.other, got, tt.want)
			}
		})
	}
}

func TestCIDRCanAggregate(t *testing.T) {
	tests := []struct {
		name  string
		cidr  string
		other string
		want  bool
	}{
		// Adjacent networks that can aggregate
		{name: "Adjacent /25s", cidr: "192.168.1.0/25", other: "192.168.1.128/25", want: true},
		{name: "Adjacent /24s", cidr: "192.168.0.0/24", other: "192.168.1.0/24", want: true},
		{name: "Adjacent /32s", cidr: "192.168.1.0/32", other: "192.168.1.1/32", want: true},

		// Non-adjacent networks
		{name: "Non-adjacent /24s", cidr: "192.168.0.0/24", other: "192.168.2.0/24", want: false},
		{name: "Same network", cidr: "192.168.1.0/24", other: "192.168.1.0/24", want: true}, // Same parent

		// Different prefix lengths
		{name: "Different prefix /24 /25", cidr: "192.168.1.0/24", other: "192.168.1.0/25", want: false},

		// IPv6 aggregation
		{name: "IPv6 adjacent /65s", cidr: "2001:db8::/65", other: "2001:db8::8000:0:0:0/65", want: true},
		{name: "IPv6 non-adjacent", cidr: "2001:db8::/64", other: "2001:db9::/64", want: false},

		// Cross-version
		{name: "IPv4 and IPv6", cidr: "192.168.1.0/24", other: "2001:db8::/64", want: false},

		// Edge case: /0
		{name: "/0 cannot aggregate", cidr: "0.0.0.0/0", other: "0.0.0.0/0", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidr, _ := parseCIDR(tt.cidr)
			other, _ := parseCIDR(tt.other)

			got := cidr.CanAggregate(other)
			if got != tt.want {
				t.Errorf("CIDR(%q).CanAggregate(%q) = %v, want %v", tt.cidr, tt.other, got, tt.want)
			}
		})
	}
}

func TestCIDRAggregate(t *testing.T) {
	tests := []struct {
		name  string
		cidr  string
		other string
		want  string
	}{
		{name: "Two /25s to /24", cidr: "192.168.1.0/25", other: "192.168.1.128/25", want: "192.168.1.0/24"},
		{name: "Two /24s to /23", cidr: "192.168.0.0/24", other: "192.168.1.0/24", want: "192.168.0.0/23"},
		{name: "Two /32s to /31", cidr: "192.168.1.0/32", other: "192.168.1.1/32", want: "192.168.1.0/31"},
		{name: "IPv6 two /65s to /64", cidr: "2001:db8::/65", other: "2001:db8::8000:0:0:0/65", want: "2001:db8::/64"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidr, _ := parseCIDR(tt.cidr)
			other, _ := parseCIDR(tt.other)

			got := cidr.Aggregate(other)
			if got.String() != tt.want {
				t.Errorf("CIDR(%q).Aggregate(%q) = %q, want %q", tt.cidr, tt.other, got.String(), tt.want)
			}
		})
	}
}

func TestCompareIPs(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want int // -1, 0, or 1
	}{
		{name: "Equal", a: "192.168.1.1", b: "192.168.1.1", want: 0},
		{name: "Less than", a: "192.168.1.1", b: "192.168.1.2", want: -1},
		{name: "Greater than", a: "192.168.1.2", b: "192.168.1.1", want: 1},
		{name: "Different octets", a: "10.0.0.1", b: "192.168.1.1", want: -1},
		{name: "IPv6 equal", a: "2001:db8::1", b: "2001:db8::1", want: 0},
		{name: "IPv6 less", a: "2001:db8::1", b: "2001:db8::2", want: -1},
		{name: "IPv6 greater", a: "2001:db8::2", b: "2001:db8::1", want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := net.ParseIP(tt.a)
			b := net.ParseIP(tt.b)

			got := compareIPs(a, b)
			if got != tt.want {
				t.Errorf("compareIPs(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestRemoveOverlaps(t *testing.T) {
	tests := []struct {
		name   string
		input  []string
		expect []string
	}{
		{
			name:   "No overlaps",
			input:  []string{"192.168.1.0/24", "192.168.2.0/24"},
			expect: []string{"192.168.1.0/24", "192.168.2.0/24"},
		},
		{
			name:   "Complete overlap",
			input:  []string{"192.168.0.0/16", "192.168.1.0/24"},
			expect: []string{"192.168.0.0/16"},
		},
		{
			name:   "Multiple overlaps",
			input:  []string{"10.0.0.0/8", "10.0.0.0/16", "10.0.0.0/24"},
			expect: []string{"10.0.0.0/8"},
		},
		{
			name:   "Single entry",
			input:  []string{"192.168.1.0/24"},
			expect: []string{"192.168.1.0/24"},
		},
		{
			name:   "Empty",
			input:  []string{},
			expect: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse and sort input (removeOverlaps expects sorted input)
			var cidrs []*CIDR
			for _, s := range tt.input {
				c, _ := parseCIDR(s)
				cidrs = append(cidrs, c)
			}

			got := removeOverlaps(cidrs)

			if len(got) != len(tt.expect) {
				t.Errorf("removeOverlaps() returned %d items, want %d", len(got), len(tt.expect))
				return
			}

			for i, c := range got {
				if c.String() != tt.expect[i] {
					t.Errorf("removeOverlaps()[%d] = %q, want %q", i, c.String(), tt.expect[i])
				}
			}
		})
	}
}

func TestAggregateNetworks(t *testing.T) {
	tests := []struct {
		name   string
		input  []string
		expect []string
	}{
		{
			name:   "Two adjacent /25s",
			input:  []string{"192.168.1.0/25", "192.168.1.128/25"},
			expect: []string{"192.168.1.0/24"},
		},
		{
			name:   "Four /26s to one /24",
			input:  []string{"192.168.1.0/26", "192.168.1.64/26", "192.168.1.128/26", "192.168.1.192/26"},
			expect: []string{"192.168.1.0/24"},
		},
		{
			name:   "Non-adjacent stay separate",
			input:  []string{"192.168.1.0/24", "192.168.3.0/24"},
			expect: []string{"192.168.1.0/24", "192.168.3.0/24"},
		},
		{
			name:   "Partial aggregation",
			input:  []string{"192.168.0.0/24", "192.168.1.0/24", "192.168.3.0/24"},
			expect: []string{"192.168.0.0/23", "192.168.3.0/24"},
		},
		{
			name:   "Single entry",
			input:  []string{"192.168.1.0/24"},
			expect: []string{"192.168.1.0/24"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cidrs []*CIDR
			for _, s := range tt.input {
				c, _ := parseCIDR(s)
				cidrs = append(cidrs, c)
			}

			got := aggregateNetworks(cidrs)

			if len(got) != len(tt.expect) {
				var gotStrs []string
				for _, c := range got {
					gotStrs = append(gotStrs, c.String())
				}
				t.Errorf("aggregateNetworks() returned %v, want %v", gotStrs, tt.expect)
				return
			}

			for i, c := range got {
				if c.String() != tt.expect[i] {
					t.Errorf("aggregateNetworks()[%d] = %q, want %q", i, c.String(), tt.expect[i])
				}
			}
		})
	}
}

func TestProcessNetworks(t *testing.T) {
	tests := []struct {
		name   string
		input  []string
		expect []string
	}{
		{
			name:   "Full pipeline - overlaps and aggregation",
			input:  []string{"192.168.1.0/25", "192.168.1.128/25", "192.168.1.64/26"},
			expect: []string{"192.168.1.0/24"},
		},
		{
			name:   "Unsorted input",
			input:  []string{"192.168.1.128/25", "192.168.1.0/25"},
			expect: []string{"192.168.1.0/24"},
		},
		{
			name: "Complex aggregation",
			input: []string{
				"10.0.0.0/32", "10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32",
				"10.0.0.4/32", "10.0.0.5/32", "10.0.0.6/32", "10.0.0.7/32",
			},
			expect: []string{"10.0.0.0/29"},
		},
		{
			name:   "IPv6 aggregation",
			input:  []string{"2001:db8::/65", "2001:db8::8000:0:0:0/65"},
			expect: []string{"2001:db8::/64"},
		},
		{
			name:   "Empty input",
			input:  []string{},
			expect: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cidrs []*CIDR
			for _, s := range tt.input {
				c, _ := parseCIDR(s)
				cidrs = append(cidrs, c)
			}

			got := processNetworks(cidrs)

			if len(got) != len(tt.expect) {
				var gotStrs []string
				for _, c := range got {
					gotStrs = append(gotStrs, c.String())
				}
				t.Errorf("processNetworks() returned %v, want %v", gotStrs, tt.expect)
				return
			}

			for i, c := range got {
				if c.String() != tt.expect[i] {
					t.Errorf("processNetworks()[%d] = %q, want %q", i, c.String(), tt.expect[i])
				}
			}
		})
	}
}

func TestIPToUint32(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want uint32
	}{
		{name: "0.0.0.0", ip: "0.0.0.0", want: 0},
		{name: "0.0.0.1", ip: "0.0.0.1", want: 1},
		{name: "0.0.1.0", ip: "0.0.1.0", want: 256},
		{name: "0.1.0.0", ip: "0.1.0.0", want: 65536},
		{name: "1.0.0.0", ip: "1.0.0.0", want: 16777216},
		{name: "255.255.255.255", ip: "255.255.255.255", want: 4294967295},
		{name: "192.168.1.1", ip: "192.168.1.1", want: 3232235777},
		{name: "IPv6 returns 0", ip: "2001:db8::1", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			got := ipToUint32(ip)
			if got != tt.want {
				t.Errorf("ipToUint32(%q) = %d, want %d", tt.ip, got, tt.want)
			}
		})
	}
}

func TestCIDRString(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"192.168.1.0/24", "192.168.1.0/24"},
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"2001:db8::/64", "2001:db8::/64"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			cidr, _ := parseCIDR(tt.input)
			if cidr.String() != tt.want {
				t.Errorf("CIDR(%q).String() = %q, want %q", tt.input, cidr.String(), tt.want)
			}
		})
	}
}

// TestRun tests the run function directly for better coverage
func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantOutput string
		wantErr    bool
	}{
		{
			name:       "Simple IPv4 aggregation",
			input:      "192.168.1.0/25\n192.168.1.128/25\n",
			wantOutput: "192.168.1.0/24\n",
		},
		{
			name:       "Mixed IPv4 and IPv6",
			input:      "192.168.1.0/25\n192.168.1.128/25\n2001:db8::/65\n2001:db8::8000:0:0:0/65\n",
			wantOutput: "192.168.1.0/24\n2001:db8::/64\n",
		},
		{
			name:       "With comments and whitespace",
			input:      "# Header\n  192.168.1.0/24  \n; Another comment\n192.168.2.0/24 ; trailing\n",
			wantOutput: "192.168.1.0/24\n192.168.2.0/24\n",
		},
		{
			name:       "Plain IPs get /32 or /128",
			input:      "192.168.1.0\n192.168.1.1\n2001:db8::1\n",
			wantOutput: "192.168.1.0/31\n2001:db8::1/128\n",
		},
		{
			name:       "Mixed plain IPs and CIDR notation",
			input:      "192.168.1.0\n192.168.1.1/32\n192.168.1.2\n192.168.1.3/32\n",
			wantOutput: "192.168.1.0/30\n",
		},
		{
			name:       "Plain IP aggregates with /24",
			input:      "10.0.0.0/24\n10.0.0.5\n",
			wantOutput: "10.0.0.0/24\n",
		},
		{
			name:       "Non-adjacent plain IPs stay separate",
			input:      "192.168.0.1\n192.168.1.1\n",
			wantOutput: "192.168.0.1/32\n192.168.1.1/32\n",
		},

		// Edge cases
		{
			name:       "Single CIDR passthrough",
			input:      "192.168.1.0/24\n",
			wantOutput: "192.168.1.0/24\n",
		},
		{
			name:       "Duplicate entries collapsed",
			input:      "192.168.1.0/24\n192.168.1.0/24\n192.168.1.0/24\n",
			wantOutput: "192.168.1.0/24\n",
		},
		{
			name:       "IPv4 default route absorbs all",
			input:      "0.0.0.0/0\n192.168.1.0/24\n10.0.0.0/8\n172.16.0.0/12\n",
			wantOutput: "0.0.0.0/0\n",
		},
		{
			name:       "IPv6 default route absorbs all IPv6",
			input:      "::/0\n2001:db8::/32\nfe80::/10\n",
			wantOutput: "::/0\n",
		},
		{
			name:       "Boundary IPs aggregate",
			input:      "0.0.0.0/32\n0.0.0.1/32\n",
			wantOutput: "0.0.0.0/31\n",
		},
		{
			name:       "Max IPv4 addresses",
			input:      "255.255.255.254/32\n255.255.255.255/32\n",
			wantOutput: "255.255.255.254/31\n",
		},
		{
			name:       "Loopback IPv4",
			input:      "127.0.0.0/8\n127.0.0.1/32\n",
			wantOutput: "127.0.0.0/8\n",
		},
		{
			name:       "Link-local IPv6",
			input:      "fe80::1/128\nfe80::2/128\n",
			wantOutput: "fe80::1/128\nfe80::2/128\n",
		},
		{
			name:       "Private ranges separate",
			input:      "10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16\n",
			wantOutput: "10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16\n",
		},
		{
			name:       "Large aggregation chain",
			input:      "10.0.0.0/32\n10.0.0.1/32\n10.0.0.2/32\n10.0.0.3/32\n10.0.0.4/32\n10.0.0.5/32\n10.0.0.6/32\n10.0.0.7/32\n10.0.0.8/32\n10.0.0.9/32\n10.0.0.10/32\n10.0.0.11/32\n10.0.0.12/32\n10.0.0.13/32\n10.0.0.14/32\n10.0.0.15/32\n",
			wantOutput: "10.0.0.0/28\n",
		},
		{
			name:       "Mixed valid and skipped lines",
			input:      "# comment\n192.168.1.0/24\n\n; another\n192.168.2.0/24\n   \n",
			wantOutput: "192.168.1.0/24\n192.168.2.0/24\n",
		},
		{
			name:       "Reverse order input",
			input:      "192.168.1.128/25\n192.168.1.0/25\n",
			wantOutput: "192.168.1.0/24\n",
		},
		{
			name:       "IPv4 and IPv6 interleaved",
			input:      "192.168.1.0/25\n2001:db8::/65\n192.168.1.128/25\n2001:db8::8000:0:0:0/65\n",
			wantOutput: "192.168.1.0/24\n2001:db8::/64\n",
		},
		{
			name:       "Empty input",
			input:      "",
			wantOutput: "",
		},
		{
			name:       "Only comments and whitespace",
			input:      "# comment\n; comment\n   \n\n",
			wantOutput: "",
		},
		{
			name:       "Overlapping networks removed",
			input:      "10.0.0.0/8\n10.1.0.0/16\n10.1.1.0/24\n",
			wantOutput: "10.0.0.0/8\n",
		},
		{
			name:       "IPv6 only",
			input:      "2001:db8::/64\n2001:db9::/64\n",
			wantOutput: "2001:db8::/64\n2001:db9::/64\n",
		},
		{
			name:       "IPv4 only with complex aggregation",
			input:      "10.0.0.0/32\n10.0.0.1/32\n10.0.0.2/32\n10.0.0.3/32\n",
			wantOutput: "10.0.0.0/30\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := strings.NewReader(tt.input)
			var output, errOutput bytes.Buffer

			err := run(input, &output, &errOutput)

			if tt.wantErr {
				if err == nil {
					t.Error("run() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("run() unexpected error: %v", err)
				return
			}

			if output.String() != tt.wantOutput {
				t.Errorf("run() output = %q, want %q", output.String(), tt.wantOutput)
			}
		})
	}
}

// TestRunWithInvalidInput tests run() handles parse errors gracefully
func TestRunWithInvalidInput(t *testing.T) {
	input := strings.NewReader("192.168.1.0/24\nnot-valid\n192.168.2.0/24\n")
	var output, errOutput bytes.Buffer

	err := run(input, &output, &errOutput)

	if err != nil {
		t.Errorf("run() should not return error for parse errors: %v", err)
	}

	// Check error was written to errOutput
	if !strings.Contains(errOutput.String(), "invalid") {
		t.Errorf("Expected error in errOutput, got: %q", errOutput.String())
	}

	// Valid CIDRs should still be processed
	got := output.String()
	if !strings.Contains(got, "192.168.1.0/24") || !strings.Contains(got, "192.168.2.0/24") {
		t.Errorf("Expected valid CIDRs in output, got: %q", got)
	}
}

// TestRunWithReaderError tests run() handles reader errors
func TestRunWithReaderError(t *testing.T) {
	input := &errorReader{err: io.ErrUnexpectedEOF}
	var output, errOutput bytes.Buffer

	err := run(input, &output, &errOutput)

	if err == nil {
		t.Error("run() expected error for reader failure, got nil")
	}
}

// errorReader is a reader that always returns an error
type errorReader struct {
	err error
}

func (r *errorReader) Read(p []byte) (n int, err error) {
	return 0, r.err
}

// TestProcessNetworksSortByPrefixLength tests sorting when IPs are equal but prefix lengths differ
func TestProcessNetworksSortByPrefixLength(t *testing.T) {
	// Same starting IP, different prefix lengths - should keep larger network only
	input := []string{"192.168.0.0/24", "192.168.0.0/25", "192.168.0.0/16"}
	var cidrs []*CIDR
	for _, s := range input {
		c, _ := parseCIDR(s)
		cidrs = append(cidrs, c)
	}

	got := processNetworks(cidrs)

	// /16 should contain all others
	if len(got) != 1 {
		t.Errorf("processNetworks() returned %d items, want 1", len(got))
		return
	}
	if got[0].String() != "192.168.0.0/16" {
		t.Errorf("processNetworks()[0] = %q, want %q", got[0].String(), "192.168.0.0/16")
	}
}

// TestAggregateNetworksMultipleRounds tests aggregation requiring re-sorting
func TestAggregateNetworksMultipleRounds(t *testing.T) {
	// Eight /27s that aggregate to a single /24 through multiple rounds
	input := []string{
		"192.168.1.0/27", "192.168.1.32/27", "192.168.1.64/27", "192.168.1.96/27",
		"192.168.1.128/27", "192.168.1.160/27", "192.168.1.192/27", "192.168.1.224/27",
	}
	var cidrs []*CIDR
	for _, s := range input {
		c, _ := parseCIDR(s)
		cidrs = append(cidrs, c)
	}

	got := aggregateNetworks(cidrs)

	if len(got) != 1 {
		var gotStrs []string
		for _, c := range got {
			gotStrs = append(gotStrs, c.String())
		}
		t.Errorf("aggregateNetworks() returned %v, want [192.168.1.0/24]", gotStrs)
		return
	}
	if got[0].String() != "192.168.1.0/24" {
		t.Errorf("aggregateNetworks()[0] = %q, want %q", got[0].String(), "192.168.1.0/24")
	}
}

// TestAggregateNetworksResortWithSameIP tests re-sorting when IPs are equal after aggregation
func TestAggregateNetworksResortWithSameIP(t *testing.T) {
	// Create a scenario where after first aggregation, re-sort needs to compare by prefix
	// 192.168.0.0/26 + 192.168.0.64/26 -> 192.168.0.0/25
	// 192.168.0.128/26 + 192.168.0.192/26 -> 192.168.0.128/25
	// Then 192.168.0.0/25 + 192.168.0.128/25 -> 192.168.0.0/24
	// Include 192.168.1.0/25 and 192.168.1.128/25 which also aggregate
	input := []string{
		"192.168.0.0/26", "192.168.0.64/26", "192.168.0.128/26", "192.168.0.192/26",
		"192.168.1.0/25", "192.168.1.128/25",
	}
	var cidrs []*CIDR
	for _, s := range input {
		c, _ := parseCIDR(s)
		cidrs = append(cidrs, c)
	}

	got := aggregateNetworks(cidrs)

	// Should produce 192.168.0.0/23 (both /24s aggregate)
	if len(got) != 1 {
		var gotStrs []string
		for _, c := range got {
			gotStrs = append(gotStrs, c.String())
		}
		t.Errorf("aggregateNetworks() returned %v, want [192.168.0.0/23]", gotStrs)
		return
	}
	if got[0].String() != "192.168.0.0/23" {
		t.Errorf("aggregateNetworks()[0] = %q, want %q", got[0].String(), "192.168.0.0/23")
	}
}

// TestMainIntegration tests the main function via the compiled binary
func TestMainIntegration(t *testing.T) {
	// Build the binary first
	cmd := exec.Command("go", "build", "-o", "aggregate-cidr-test", ".")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build binary: %v", err)
	}
	defer exec.Command("rm", "aggregate-cidr-test").Run()

	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{
			name:   "Simple aggregation",
			input:  "192.168.1.0/25\n192.168.1.128/25\n",
			expect: "192.168.1.0/24\n",
		},
		{
			name:   "Mixed IPv4 and IPv6",
			input:  "192.168.1.0/25\n192.168.1.128/25\n2001:db8::/65\n2001:db8::8000:0:0:0/65\n",
			expect: "192.168.1.0/24\n2001:db8::/64\n",
		},
		{
			name:   "With comments",
			input:  "# Header comment\n192.168.1.0/24 ; SBL123\n192.168.2.0/24\n",
			expect: "192.168.1.0/24\n192.168.2.0/24\n",
		},
		{
			name:   "Plain IPs",
			input:  "192.168.1.0\n192.168.1.1\n",
			expect: "192.168.1.0/31\n",
		},
		{
			name:   "Empty input",
			input:  "",
			expect: "",
		},
		{
			name:   "Only comments",
			input:  "# comment 1\n; comment 2\n",
			expect: "",
		},
		{
			name:   "Overlapping networks",
			input:  "10.0.0.0/8\n10.1.0.0/16\n10.1.1.0/24\n",
			expect: "10.0.0.0/8\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command("./aggregate-cidr-test")
			cmd.Stdin = strings.NewReader(tt.input)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			if err := cmd.Run(); err != nil {
				t.Errorf("Command failed: %v\nstderr: %s", err, stderr.String())
				return
			}

			got := stdout.String()
			if got != tt.expect {
				t.Errorf("Output = %q, want %q", got, tt.expect)
			}
		})
	}
}

// TestMainWithInvalidInput tests error handling for invalid input
func TestMainWithInvalidInput(t *testing.T) {
	// Build the binary first
	cmd := exec.Command("go", "build", "-o", "aggregate-cidr-test", ".")
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build binary: %v", err)
	}
	defer exec.Command("rm", "aggregate-cidr-test").Run()

	cmd = exec.Command("./aggregate-cidr-test")
	cmd.Stdin = strings.NewReader("192.168.1.0/24\nnot-a-valid-ip\n192.168.2.0/24\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Should still succeed but output error to stderr
	cmd.Run()

	// Check stderr contains error message
	if !strings.Contains(stderr.String(), "invalid") {
		t.Errorf("Expected error message in stderr, got: %q", stderr.String())
	}

	// Valid CIDRs should still be in output
	got := stdout.String()
	if !strings.Contains(got, "192.168.1.0/24") || !strings.Contains(got, "192.168.2.0/24") {
		t.Errorf("Expected valid CIDRs in output, got: %q", got)
	}
}

// Benchmark tests
func BenchmarkParseCIDR(b *testing.B) {
	for i := 0; i < b.N; i++ {
		parseCIDR("192.168.1.0/24")
	}
}

func BenchmarkProcessNetworks(b *testing.B) {
	// Create a set of CIDRs to process
	inputs := []string{
		"192.168.0.0/24", "192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24",
		"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24",
	}
	var cidrs []*CIDR
	for _, s := range inputs {
		c, _ := parseCIDR(s)
		cidrs = append(cidrs, c)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Make a copy since processNetworks modifies the slice
		cp := make([]*CIDR, len(cidrs))
		copy(cp, cidrs)
		processNetworks(cp)
	}
}
