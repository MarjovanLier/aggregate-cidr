package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
)

// CIDR represents a network with helper methods
type CIDR struct {
	net  *net.IPNet
	ip   net.IP
	ones int
	bits int
}

func parseCIDR(s string) (*CIDR, error) {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") {
		return nil, nil // skip empty lines and comments
	}

	// Extract just the IP/CIDR part (handle "IP/CIDR ; comment" format)
	if idx := strings.IndexAny(s, " \t;#"); idx != -1 {
		s = s[:idx]
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}

	// Add /32 or /128 if no prefix specified
	if !strings.Contains(s, "/") {
		if strings.Contains(s, ":") {
			s += "/128"
		} else {
			s += "/32"
		}
	}

	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %v", s, err)
	}

	ones, bits := ipnet.Mask.Size()
	return &CIDR{
		net:  ipnet,
		ip:   ipnet.IP,
		ones: ones,
		bits: bits,
	}, nil
}

// Contains returns true if c fully contains other
func (c *CIDR) Contains(other *CIDR) bool {
	if c.bits != other.bits { // different IP versions
		return false
	}
	if c.ones > other.ones { // c is smaller, can't contain other
		return false
	}
	return c.net.Contains(other.ip)
}

// CanAggregate returns true if two CIDRs can be combined into one larger CIDR
func (c *CIDR) CanAggregate(other *CIDR) bool {
	if c.bits != other.bits || c.ones != other.ones {
		return false
	}
	if c.ones == 0 {
		return false // already at max size
	}

	// Two networks can aggregate if they differ only in the last bit of network portion
	// Create parent mask (one bit less)
	parentOnes := c.ones - 1
	parentMask := net.CIDRMask(parentOnes, c.bits)

	// Both networks must have the same parent
	cParent := c.ip.Mask(parentMask)
	otherParent := other.ip.Mask(parentMask)

	return cParent.Equal(otherParent)
}

// Aggregate combines two CIDRs into their parent
func (c *CIDR) Aggregate(other *CIDR) *CIDR {
	parentOnes := c.ones - 1
	parentMask := net.CIDRMask(parentOnes, c.bits)
	parentIP := c.ip.Mask(parentMask)

	return &CIDR{
		net: &net.IPNet{
			IP:   parentIP,
			Mask: parentMask,
		},
		ip:   parentIP,
		ones: parentOnes,
		bits: c.bits,
	}
}

func (c *CIDR) String() string {
	return c.net.String()
}

// ipToUint32 converts IPv4 to uint32 for sorting
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func main() {
	var cidrs []*CIDR
	scanner := bufio.NewScanner(os.Stdin)

	// Read all CIDRs from stdin
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		cidr, err := parseCIDR(scanner.Text())
		if err != nil {
			fmt.Fprintf(os.Stderr, "line %d: %v\n", lineNum, err)
			continue
		}
		if cidr != nil {
			cidrs = append(cidrs, cidr)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "error reading input: %v\n", err)
		os.Exit(1)
	}

	if len(cidrs) == 0 {
		return
	}

	// Separate IPv4 and IPv6
	var ipv4, ipv6 []*CIDR
	for _, c := range cidrs {
		if c.bits == 32 {
			ipv4 = append(ipv4, c)
		} else {
			ipv6 = append(ipv6, c)
		}
	}

	// Process each separately
	ipv4 = processNetworks(ipv4)
	ipv6 = processNetworks(ipv6)

	// Output results
	for _, c := range ipv4 {
		fmt.Println(c)
	}
	for _, c := range ipv6 {
		fmt.Println(c)
	}
}

func processNetworks(cidrs []*CIDR) []*CIDR {
	if len(cidrs) == 0 {
		return cidrs
	}

	// Sort by IP address, then by prefix length (smaller prefix = larger network first)
	sort.Slice(cidrs, func(i, j int) bool {
		cmpIP := compareIPs(cidrs[i].ip, cidrs[j].ip)
		if cmpIP != 0 {
			return cmpIP < 0
		}
		return cidrs[i].ones < cidrs[j].ones
	})

	// Remove overlaps (if A contains B, remove B)
	cidrs = removeOverlaps(cidrs)

	// Aggregate adjacent networks
	cidrs = aggregateNetworks(cidrs)

	return cidrs
}

func compareIPs(a, b net.IP) int {
	a = a.To16()
	b = b.To16()
	for i := 0; i < len(a); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

func removeOverlaps(cidrs []*CIDR) []*CIDR {
	if len(cidrs) <= 1 {
		return cidrs
	}

	result := []*CIDR{cidrs[0]}
	for i := 1; i < len(cidrs); i++ {
		current := result[len(result)-1]
		next := cidrs[i]

		// If current contains next, skip next (it's redundant)
		if current.Contains(next) {
			continue
		}
		result = append(result, next)
	}
	return result
}

func aggregateNetworks(cidrs []*CIDR) []*CIDR {
	changed := true
	for changed {
		changed = false
		var newCIDRs []*CIDR

		i := 0
		for i < len(cidrs) {
			if i+1 < len(cidrs) && cidrs[i].CanAggregate(cidrs[i+1]) {
				// Combine into parent
				newCIDRs = append(newCIDRs, cidrs[i].Aggregate(cidrs[i+1]))
				i += 2
				changed = true
			} else {
				newCIDRs = append(newCIDRs, cidrs[i])
				i++
			}
		}
		cidrs = newCIDRs

		// Re-sort after aggregation (parent might now be adjacent to another network)
		if changed {
			sort.Slice(cidrs, func(i, j int) bool {
				cmpIP := compareIPs(cidrs[i].ip, cidrs[j].ip)
				if cmpIP != 0 {
					return cmpIP < 0
				}
				return cidrs[i].ones < cidrs[j].ones
			})
		}
	}
	return cidrs
}
