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

func (r *errorReader) Read(_ []byte) (n int, err error) {
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
	defer func() { _ = exec.Command("rm", "aggregate-cidr-test").Run() }()

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
	defer func() { _ = exec.Command("rm", "aggregate-cidr-test").Run() }()

	cmd = exec.Command("./aggregate-cidr-test")
	cmd.Stdin = strings.NewReader("192.168.1.0/24\nnot-a-valid-ip\n192.168.2.0/24\n")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Should still succeed but output error to stderr
	_ = cmd.Run()

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

// Tests for new IP range formats

func TestParseInput(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      []string
		wantNil   bool
		wantErr   bool
		wantCount int // optional: expected number of CIDRs for ranges
	}{
		// Standard CIDR passthrough
		{name: "Standard CIDR", input: "192.168.1.0/24", want: []string{"192.168.1.0/24"}},
		{name: "Plain IP", input: "192.168.1.1", want: []string{"192.168.1.1/32"}},
		{name: "IPv6 CIDR", input: "2001:db8::/64", want: []string{"2001:db8::/64"}},

		// Empty and comments
		{name: "Empty line", input: "", wantNil: true},
		{name: "Comment hash", input: "# comment", wantNil: true},
		{name: "Comment semicolon", input: "; comment", wantNil: true},
		{name: "Whitespace only", input: "   ", wantNil: true},

		// Wildcard format - IPv4
		{name: "Wildcard /24", input: "192.168.1.*", want: []string{"192.168.1.0/24"}},
		{name: "Wildcard /16", input: "192.168.*.*", want: []string{"192.168.0.0/16"}},
		{name: "Wildcard /8", input: "10.*.*.*", want: []string{"10.0.0.0/8"}},
		{name: "Wildcard /0", input: "*.*.*.*", want: []string{"0.0.0.0/0"}},

		// Wildcard format - IPv6
		{name: "IPv6 wildcard basic", input: "2001:db8::*", want: []string{"2001:db8::/32"}},
		{name: "IPv6 wildcard /48", input: "2001:db8:abcd::*", want: []string{"2001:db8:abcd::/48"}},

		// Range format - full
		{name: "Full range single IP", input: "192.168.1.1-192.168.1.1", want: []string{"192.168.1.1/32"}},
		{name: "Full range two IPs", input: "192.168.1.0-192.168.1.1", want: []string{"192.168.1.0/31"}},
		{name: "Full range /24", input: "192.168.1.0-192.168.1.255", want: []string{"192.168.1.0/24"}},

		// Range format - short
		{name: "Short range /24", input: "192.168.1.0-255", want: []string{"192.168.1.0/24"}},
		{name: "Short range single", input: "192.168.1.5-5", want: []string{"192.168.1.5/32"}},
		{name: "Short range partial", input: "192.168.1.0-127", want: []string{"192.168.1.0/25"}},

		// Netmask format
		{name: "Netmask /24", input: "192.168.1.0 255.255.255.0", want: []string{"192.168.1.0/24"}},
		{name: "Netmask /16", input: "172.16.0.0 255.255.0.0", want: []string{"172.16.0.0/16"}},
		{name: "Netmask /8", input: "10.0.0.0 255.0.0.0", want: []string{"10.0.0.0/8"}},
		{name: "Netmask /32", input: "192.168.1.1 255.255.255.255", want: []string{"192.168.1.1/32"}},
		{name: "Netmask /0", input: "0.0.0.0 0.0.0.0", want: []string{"0.0.0.0/0"}},

		// With comments
		{name: "Wildcard with comment", input: "192.168.1.* ; comment", want: []string{"192.168.1.0/24"}},
		{name: "Range with comment", input: "192.168.1.0-255 # comment", want: []string{"192.168.1.0/24"}},
		{name: "Netmask with comment", input: "192.168.1.0 255.255.255.0 ; SBL123", want: []string{"192.168.1.0/24"}},

		// Negative tests - wildcards
		{name: "Wildcard not at end", input: "192.*.1.0", wantErr: true},
		{name: "Wildcard partial", input: "192.168.1*", wantErr: true},
		{name: "Wildcard wrong count", input: "192.168.*", wantErr: true},

		// Negative tests - ranges
		{name: "Range reversed", input: "192.168.1.255-192.168.1.0", wantErr: true},
		{name: "Range bad start", input: "not.an.ip-192.168.1.255", wantErr: true},
		{name: "Range bad end", input: "192.168.1.0-not.an.ip", wantErr: true},
		{name: "Short range bad octet", input: "192.168.1.0-abc", wantErr: true},
		{name: "Short range octet > 255", input: "192.168.1.0-256", wantErr: true},

		// Negative tests - netmask
		{name: "Netmask invalid IP", input: "not.an.ip 255.255.255.0", wantErr: true},
		{name: "Netmask invalid mask", input: "192.168.1.0 not.a.mask", wantErr: true},
		{name: "Netmask non-contiguous", input: "192.168.1.0 255.255.254.1", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseInput(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseInput(%q) expected error, got nil", tt.input)
				}
				return
			}

			if err != nil {
				t.Errorf("parseInput(%q) unexpected error: %v", tt.input, err)
				return
			}

			if tt.wantNil {
				if got != nil {
					t.Errorf("parseInput(%q) expected nil, got %v", tt.input, got)
				}
				return
			}

			if len(got) != len(tt.want) {
				var gotStrs []string
				for _, c := range got {
					gotStrs = append(gotStrs, c.String())
				}
				t.Errorf("parseInput(%q) returned %v, want %v", tt.input, gotStrs, tt.want)
				return
			}

			for i, cidr := range got {
				if cidr.String() != tt.want[i] {
					t.Errorf("parseInput(%q)[%d] = %q, want %q", tt.input, i, cidr.String(), tt.want[i])
				}
			}
		})
	}
}

func TestParseWildcard(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		// IPv4 wildcards
		{name: "Single wildcard /24", input: "192.168.1.*", want: "192.168.1.0/24"},
		{name: "Two wildcards /16", input: "192.168.*.*", want: "192.168.0.0/16"},
		{name: "Three wildcards /8", input: "10.*.*.*", want: "10.0.0.0/8"},
		{name: "All wildcards /0", input: "*.*.*.*", want: "0.0.0.0/0"},
		{name: "Max octet values", input: "255.255.255.*", want: "255.255.255.0/24"},
		{name: "Zero octets", input: "0.0.0.*", want: "0.0.0.0/24"},

		// IPv6 wildcards
		{name: "IPv6 two segments", input: "2001:db8::*", want: "2001:db8::/32"},
		{name: "IPv6 three segments", input: "2001:db8:abcd::*", want: "2001:db8:abcd::/48"},
		{name: "IPv6 single segment", input: "2001::*", want: "2001::/16"},

		// Negative tests
		{name: "Wildcard not at end", input: "192.*.168.0", wantErr: true},
		{name: "Partial wildcard", input: "192.168.1*", wantErr: true},
		{name: "Missing octets", input: "192.168.*", wantErr: true},
		{name: "No wildcard", input: "192.168.1.0", wantErr: true},
		{name: "IPv6 wildcard not at end", input: "2001:*:db8::", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseWildcard(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseWildcard(%q) expected error, got nil", tt.input)
				}
				return
			}

			if err != nil {
				t.Errorf("parseWildcard(%q) unexpected error: %v", tt.input, err)
				return
			}

			if len(got) != 1 {
				t.Errorf("parseWildcard(%q) returned %d CIDRs, want 1", tt.input, len(got))
				return
			}

			if got[0].String() != tt.want {
				t.Errorf("parseWildcard(%q) = %q, want %q", tt.input, got[0].String(), tt.want)
			}
		})
	}
}

func TestParseRange(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      []string
		wantErr   bool
		wantCount int
	}{
		// Full range - CIDR aligned
		{name: "Single IP", input: "192.168.1.1-192.168.1.1", want: []string{"192.168.1.1/32"}},
		{name: "Two IPs", input: "192.168.1.0-192.168.1.1", want: []string{"192.168.1.0/31"}},
		{name: "Four IPs", input: "192.168.1.0-192.168.1.3", want: []string{"192.168.1.0/30"}},
		{name: "/24 aligned", input: "192.168.1.0-192.168.1.255", want: []string{"192.168.1.0/24"}},
		{name: "/16 aligned", input: "192.168.0.0-192.168.255.255", want: []string{"192.168.0.0/16"}},

		// Full range - non-CIDR aligned (produces multiple CIDRs)
		{name: "Non-aligned 1-5", input: "192.168.1.1-192.168.1.5", wantCount: 3},   // 1/32 + 2-3/31 + 4-5/31
		{name: "Non-aligned 1-10", input: "192.168.1.1-192.168.1.10", wantCount: 5}, // 1/32 + 2-3/31 + 4-7/30 + 8-9/31 + 10/32

		// Short range format
		{name: "Short /24", input: "192.168.1.0-255", want: []string{"192.168.1.0/24"}},
		{name: "Short single", input: "192.168.1.5-5", want: []string{"192.168.1.5/32"}},
		{name: "Short /25", input: "192.168.1.0-127", want: []string{"192.168.1.0/25"}},
		{name: "Short /25 upper", input: "192.168.1.128-255", want: []string{"192.168.1.128/25"}},

		// IPv6 ranges
		{name: "IPv6 single", input: "2001:db8::1-2001:db8::1", want: []string{"2001:db8::1/128"}},
		{name: "IPv6 two", input: "2001:db8::0-2001:db8::1", want: []string{"2001:db8::/127"}},
		{name: "IPv6 four", input: "2001:db8::0-2001:db8::3", want: []string{"2001:db8::/126"}},

		// Negative tests
		{name: "Reversed range", input: "192.168.1.255-192.168.1.0", wantErr: true},
		{name: "Invalid start", input: "invalid-192.168.1.255", wantErr: true},
		{name: "Invalid end", input: "192.168.1.0-invalid", wantErr: true},
		{name: "Short invalid octet", input: "192.168.1.0-abc", wantErr: true},
		{name: "Short octet > 255", input: "192.168.1.0-256", wantErr: true},
		{name: "Short negative octet", input: "192.168.1.0--1", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRange(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseRange(%q) expected error, got nil", tt.input)
				}
				return
			}

			if err != nil {
				t.Errorf("parseRange(%q) unexpected error: %v", tt.input, err)
				return
			}

			if tt.wantCount > 0 {
				if len(got) != tt.wantCount {
					var gotStrs []string
					for _, c := range got {
						gotStrs = append(gotStrs, c.String())
					}
					t.Errorf("parseRange(%q) returned %d CIDRs (%v), want %d", tt.input, len(got), gotStrs, tt.wantCount)
				}
				return
			}

			if len(got) != len(tt.want) {
				var gotStrs []string
				for _, c := range got {
					gotStrs = append(gotStrs, c.String())
				}
				t.Errorf("parseRange(%q) returned %v, want %v", tt.input, gotStrs, tt.want)
				return
			}

			for i, cidr := range got {
				if cidr.String() != tt.want[i] {
					t.Errorf("parseRange(%q)[%d] = %q, want %q", tt.input, i, cidr.String(), tt.want[i])
				}
			}
		})
	}
}

func TestParseNetmask(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		mask    string
		want    string
		wantErr bool
	}{
		// Standard netmasks
		{name: "/24", ip: "192.168.1.0", mask: "255.255.255.0", want: "192.168.1.0/24"},
		{name: "/16", ip: "172.16.0.0", mask: "255.255.0.0", want: "172.16.0.0/16"},
		{name: "/8", ip: "10.0.0.0", mask: "255.0.0.0", want: "10.0.0.0/8"},
		{name: "/32", ip: "192.168.1.1", mask: "255.255.255.255", want: "192.168.1.1/32"},
		{name: "/0", ip: "0.0.0.0", mask: "0.0.0.0", want: "0.0.0.0/0"},
		{name: "/25", ip: "192.168.1.0", mask: "255.255.255.128", want: "192.168.1.0/25"},
		{name: "/26", ip: "192.168.1.0", mask: "255.255.255.192", want: "192.168.1.0/26"},
		{name: "/27", ip: "192.168.1.0", mask: "255.255.255.224", want: "192.168.1.0/27"},
		{name: "/28", ip: "192.168.1.0", mask: "255.255.255.240", want: "192.168.1.0/28"},

		// Negative tests
		{name: "Invalid IP", ip: "not.an.ip", mask: "255.255.255.0", wantErr: true},
		{name: "Invalid mask", ip: "192.168.1.0", mask: "not.a.mask", wantErr: true},
		{name: "Non-contiguous mask", ip: "192.168.1.0", mask: "255.255.254.1", wantErr: true},
		{name: "Non-contiguous mask 2", ip: "192.168.1.0", mask: "255.0.255.0", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseNetmask(tt.ip, tt.mask)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseNetmask(%q, %q) expected error, got nil", tt.ip, tt.mask)
				}
				return
			}

			if err != nil {
				t.Errorf("parseNetmask(%q, %q) unexpected error: %v", tt.ip, tt.mask, err)
				return
			}

			if len(got) != 1 {
				t.Errorf("parseNetmask(%q, %q) returned %d CIDRs, want 1", tt.ip, tt.mask, len(got))
				return
			}

			if got[0].String() != tt.want {
				t.Errorf("parseNetmask(%q, %q) = %q, want %q", tt.ip, tt.mask, got[0].String(), tt.want)
			}
		})
	}
}

func TestRangeToCIDRs(t *testing.T) {
	tests := []struct {
		name    string
		start   string
		end     string
		want    []string
		wantErr bool
	}{
		// CIDR-aligned ranges
		{name: "Single IP", start: "192.168.1.1", end: "192.168.1.1", want: []string{"192.168.1.1/32"}},
		{name: "/31", start: "192.168.1.0", end: "192.168.1.1", want: []string{"192.168.1.0/31"}},
		{name: "/30", start: "192.168.1.0", end: "192.168.1.3", want: []string{"192.168.1.0/30"}},
		{name: "/24", start: "192.168.1.0", end: "192.168.1.255", want: []string{"192.168.1.0/24"}},

		// Non-aligned ranges (multiple CIDRs)
		{name: "1-5", start: "192.168.1.1", end: "192.168.1.5", want: []string{
			"192.168.1.1/32", "192.168.1.2/31", "192.168.1.4/31",
		}},
		{name: "0-5", start: "192.168.1.0", end: "192.168.1.5", want: []string{
			"192.168.1.0/30", "192.168.1.4/31",
		}},
		{name: "1-6", start: "192.168.1.1", end: "192.168.1.6", want: []string{
			"192.168.1.1/32", "192.168.1.2/31", "192.168.1.4/31", "192.168.1.6/32",
		}},

		// Edge cases
		{name: "0.0.0.0-0.0.0.0", start: "0.0.0.0", end: "0.0.0.0", want: []string{"0.0.0.0/32"}},
		{name: "255.255.255.255", start: "255.255.255.255", end: "255.255.255.255", want: []string{"255.255.255.255/32"}},
		{name: "Full IPv4 range", start: "0.0.0.0", end: "255.255.255.255", want: []string{"0.0.0.0/0"}},

		// IPv6
		{name: "IPv6 single", start: "2001:db8::1", end: "2001:db8::1", want: []string{"2001:db8::1/128"}},
		{name: "IPv6 /127", start: "2001:db8::0", end: "2001:db8::1", want: []string{"2001:db8::/127"}},

		// Errors
		{name: "Reversed", start: "192.168.1.255", end: "192.168.1.0", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start := net.ParseIP(tt.start)
			end := net.ParseIP(tt.end)

			// Normalise to IPv4 if appropriate
			if start.To4() != nil {
				start = start.To4()
				end = end.To4()
			}

			got, err := rangeToCIDRs(start, end)

			if tt.wantErr {
				if err == nil {
					t.Errorf("rangeToCIDRs(%q, %q) expected error, got nil", tt.start, tt.end)
				}
				return
			}

			if err != nil {
				t.Errorf("rangeToCIDRs(%q, %q) unexpected error: %v", tt.start, tt.end, err)
				return
			}

			if len(got) != len(tt.want) {
				var gotStrs []string
				for _, c := range got {
					gotStrs = append(gotStrs, c.String())
				}
				t.Errorf("rangeToCIDRs(%q, %q) returned %v, want %v", tt.start, tt.end, gotStrs, tt.want)
				return
			}

			for i, cidr := range got {
				if cidr.String() != tt.want[i] {
					t.Errorf("rangeToCIDRs(%q, %q)[%d] = %q, want %q", tt.start, tt.end, i, cidr.String(), tt.want[i])
				}
			}
		})
	}
}

func TestIsContiguousMask(t *testing.T) {
	tests := []struct {
		name string
		mask string
		want bool
	}{
		{name: "/24", mask: "255.255.255.0", want: true},
		{name: "/16", mask: "255.255.0.0", want: true},
		{name: "/8", mask: "255.0.0.0", want: true},
		{name: "/32", mask: "255.255.255.255", want: true},
		{name: "/0", mask: "0.0.0.0", want: true},
		{name: "/25", mask: "255.255.255.128", want: true},
		{name: "Non-contiguous", mask: "255.255.254.1", want: false},
		{name: "Non-contiguous 2", mask: "255.0.255.0", want: false},
		{name: "Non-contiguous 3", mask: "255.255.0.255", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mask := net.ParseIP(tt.mask).To4()
			got := isContiguousMask(mask)
			if got != tt.want {
				t.Errorf("isContiguousMask(%q) = %v, want %v", tt.mask, got, tt.want)
			}
		})
	}
}

// TestRunWithNewFormats tests run() with the new input formats
func TestRunWithNewFormats(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantOutput string
	}{
		// Wildcard format
		{
			name:       "Wildcard /24",
			input:      "192.168.1.*\n",
			wantOutput: "192.168.1.0/24\n",
		},
		{
			name:       "Wildcard /16",
			input:      "192.168.*.*\n",
			wantOutput: "192.168.0.0/16\n",
		},
		{
			name:       "Multiple wildcards aggregate",
			input:      "192.168.0.*\n192.168.1.*\n",
			wantOutput: "192.168.0.0/23\n",
		},

		// Range format
		{
			name:       "Full range /24",
			input:      "192.168.1.0-192.168.1.255\n",
			wantOutput: "192.168.1.0/24\n",
		},
		{
			name:       "Short range /24",
			input:      "192.168.1.0-255\n",
			wantOutput: "192.168.1.0/24\n",
		},
		{
			name:       "Non-aligned range",
			input:      "192.168.1.1-192.168.1.5\n",
			wantOutput: "192.168.1.1/32\n192.168.1.2/31\n192.168.1.4/31\n",
		},

		// Netmask format
		{
			name:       "Netmask /24",
			input:      "192.168.1.0 255.255.255.0\n",
			wantOutput: "192.168.1.0/24\n",
		},
		{
			name:       "Netmask /16",
			input:      "172.16.0.0 255.255.0.0\n",
			wantOutput: "172.16.0.0/16\n",
		},

		// Mixed formats
		{
			name:       "Mixed formats aggregate",
			input:      "192.168.0.*\n192.168.1.0/24\n",
			wantOutput: "192.168.0.0/23\n",
		},
		{
			name:       "Mixed wildcard and range",
			input:      "192.168.0.*\n192.168.1.0-255\n",
			wantOutput: "192.168.0.0/23\n",
		},
		{
			name:       "Mixed all formats",
			input:      "192.168.0.*\n192.168.1.0/24\n192.168.2.0 255.255.255.0\n192.168.3.0-255\n",
			wantOutput: "192.168.0.0/22\n",
		},

		// With comments
		{
			name:       "Wildcard with comment",
			input:      "192.168.1.* ; my network\n",
			wantOutput: "192.168.1.0/24\n",
		},
		{
			name:       "Netmask with comment",
			input:      "192.168.1.0 255.255.255.0 ; SBL123\n",
			wantOutput: "192.168.1.0/24\n",
		},

		// IPv6
		{
			name:       "IPv6 wildcard",
			input:      "2001:db8::*\n",
			wantOutput: "2001:db8::/32\n",
		},
		{
			name:       "IPv6 range",
			input:      "2001:db8::0-2001:db8::ff\n",
			wantOutput: "2001:db8::/120\n",
		},

		// Edge cases
		{
			name:       "Overlapping formats",
			input:      "192.168.1.*\n192.168.1.0/24\n192.168.1.0-255\n",
			wantOutput: "192.168.1.0/24\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := strings.NewReader(tt.input)
			var output, errOutput bytes.Buffer

			err := run(input, &output, &errOutput)

			if err != nil {
				t.Errorf("run() unexpected error: %v", err)
				return
			}

			if errOutput.String() != "" {
				t.Errorf("run() wrote to stderr: %q", errOutput.String())
			}

			if output.String() != tt.wantOutput {
				t.Errorf("run() output = %q, want %q", output.String(), tt.wantOutput)
			}
		})
	}
}

// TestRunWithInvalidNewFormats tests run() handles errors in new formats
func TestRunWithInvalidNewFormats(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantErrContain string
	}{
		{name: "Invalid wildcard", input: "192.*.168.0\n", wantErrContain: "wildcard"},
		{name: "Invalid range reversed", input: "192.168.1.255-192.168.1.0\n", wantErrContain: "range"},
		{name: "Invalid netmask", input: "192.168.1.0 255.255.254.1\n", wantErrContain: "not a valid mask"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := strings.NewReader(tt.input)
			var output, errOutput bytes.Buffer

			err := run(input, &output, &errOutput)

			// run() should not return error (just log to stderr)
			if err != nil {
				t.Errorf("run() returned error: %v", err)
			}

			if !strings.Contains(strings.ToLower(errOutput.String()), tt.wantErrContain) {
				t.Errorf("run() stderr = %q, want to contain %q", errOutput.String(), tt.wantErrContain)
			}
		})
	}
}

// Benchmark tests
func BenchmarkParseCIDR(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = parseCIDR("192.168.1.0/24")
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
