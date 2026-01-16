// Package main provides aggregate-cidr, a tool to combine a list of CIDR address blocks.
//
// Based on aggregate-cidr-addresses by Mark Suter <suter@zwitterion.org>
// Original Perl version: https://zwitterion.org/software/aggregate-cidr-addresses/
//
// This Go port aggregates overlapping and adjacent IP address blocks
// into the smallest possible set of CIDR prefixes.
package main

import (
	"bufio"
	"fmt"
	"io"
	"math/big"
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

// Aggregate combines two CIDRs into their parent.
// The other parameter is required by the API but not used in the calculation
// since both CIDRs mask to the same parent (verified by CanAggregate).
func (c *CIDR) Aggregate(_ *CIDR) *CIDR {
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

// parseInput parses various IP range formats and returns one or more CIDRs.
// Supported formats:
//   - Standard CIDR: 192.168.1.0/24
//   - Plain IP: 192.168.1.1
//   - Wildcard: 192.168.1.* or 2001:db8::*
//   - Dash range: 192.168.1.1-192.168.1.255 or 2001:db8::1-2001:db8::ff
//   - Short range: 192.168.1.0-255
//   - Netmask: 192.168.1.0 255.255.255.0
func parseInput(s string) ([]*CIDR, error) {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") {
		return nil, nil // skip empty lines and comments
	}

	// Extract just the IP/CIDR part (handle "IP/CIDR ; comment" format)
	// But preserve spaces for netmask format detection
	originalS := s
	if idx := strings.IndexAny(s, ";#"); idx != -1 {
		s = strings.TrimSpace(s[:idx])
	}
	if s == "" {
		return nil, nil
	}

	// Check for netmask format first (contains space but not a comment delimiter)
	// Format: "192.168.1.0 255.255.255.0"
	if strings.Contains(s, " ") {
		parts := strings.Fields(s)
		if len(parts) == 2 && !strings.Contains(parts[0], "/") && !strings.Contains(parts[0], "-") && !strings.Contains(parts[0], "*") {
			return parseNetmask(parts[0], parts[1])
		}
	}

	// Now strip any trailing content after space/tab for other formats
	if idx := strings.IndexAny(s, " \t"); idx != -1 {
		s = s[:idx]
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}

	// Check for wildcard format
	if strings.Contains(s, "*") {
		return parseWildcard(s)
	}

	// Check for range format (contains dash but not in IPv6 address)
	if strings.Contains(s, "-") {
		// IPv6 addresses don't use dash, so any dash is a range indicator
		// For IPv4, check if it's a range vs potential (invalid) negative number
		return parseRange(s)
	}

	// Standard CIDR or plain IP
	cidr, err := parseCIDR(originalS)
	if err != nil {
		return nil, err
	}
	if cidr == nil {
		return nil, nil
	}
	return []*CIDR{cidr}, nil
}

// parseWildcard converts wildcard notation to CIDR.
// Examples:
//   - 192.168.1.* → 192.168.1.0/24
//   - 192.168.*.* → 192.168.0.0/16
//   - 2001:db8::* → 2001:db8::/32 (everything after :: is wildcarded)
func parseWildcard(s string) ([]*CIDR, error) {
	// IPv6 wildcard
	if strings.Contains(s, ":") {
		return parseIPv6Wildcard(s)
	}

	// IPv4 wildcard: count asterisks and validate format
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid wildcard format %q: expected 4 octets", s)
	}

	// Find first asterisk and ensure all following are asterisks
	firstWildcard := -1
	for i, p := range parts {
		if p == "*" {
			if firstWildcard == -1 {
				firstWildcard = i
			}
		} else if firstWildcard != -1 {
			return nil, fmt.Errorf("invalid wildcard format %q: wildcard must be at end", s)
		}
	}

	if firstWildcard == -1 {
		return nil, fmt.Errorf("invalid wildcard format %q: no wildcard found", s)
	}

	// Build base IP by replacing * with 0
	for i := firstWildcard; i < 4; i++ {
		parts[i] = "0"
	}
	baseIP := strings.Join(parts, ".")

	// Calculate prefix length (8 bits per non-wildcard octet)
	prefixLen := firstWildcard * 8

	cidrStr := fmt.Sprintf("%s/%d", baseIP, prefixLen)
	return parseCIDRToSlice(cidrStr)
}

// parseIPv6Wildcard handles IPv6 wildcard notation.
// The wildcard * replaces everything after the last specified segment.
// Examples:
//   - 2001:db8::* → 2001:db8::/32
//   - 2001:db8:abcd::* → 2001:db8:abcd::/48
func parseIPv6Wildcard(s string) ([]*CIDR, error) {
	if !strings.HasSuffix(s, "*") {
		return nil, fmt.Errorf("invalid IPv6 wildcard format %q: wildcard must be at end", s)
	}

	// Remove the trailing *
	s = strings.TrimSuffix(s, "*")

	// Handle :: notation - count specified segments
	var prefixLen int
	if strings.Contains(s, "::") {
		// For patterns like "2001:db8::*", count segments before ::
		parts := strings.Split(s, "::")
		if len(parts) > 2 {
			return nil, fmt.Errorf("invalid IPv6 wildcard format %q: contains multiple double-colons", s)
		}

		segments := 0
		if parts[0] != "" {
			segments = len(strings.Split(parts[0], ":"))
		}
		// Each segment is 16 bits
		prefixLen = segments * 16

		// Build CIDR notation - use the prefix part
		var prefix string
		if parts[0] != "" {
			prefix = parts[0]
		}
		cidrStr := fmt.Sprintf("%s::/%d", prefix, prefixLen)
		return parseCIDRToSlice(cidrStr)
	}

	// No :: notation - remove trailing colons and count segments
	s = strings.TrimSuffix(s, ":")
	segments := len(strings.Split(s, ":"))
	prefixLen = segments * 16

	// Build CIDR notation
	cidrStr := fmt.Sprintf("%s::/%d", s, prefixLen)
	return parseCIDRToSlice(cidrStr)
}

// parseRange handles dash range notation.
// Examples:
//   - 192.168.1.1-192.168.1.255 (full range)
//   - 192.168.1.0-255 (short range - last octet only)
//   - 2001:db8::1-2001:db8::ff (IPv6 range)
func parseRange(s string) ([]*CIDR, error) {
	dashIdx := strings.LastIndex(s, "-")
	if dashIdx == -1 {
		return nil, fmt.Errorf("invalid range format %q: no dash found", s)
	}

	startStr := s[:dashIdx]
	endStr := s[dashIdx+1:]

	// Detect if this is a short range (last octet only)
	isIPv6 := strings.Contains(startStr, ":")

	if !isIPv6 && !strings.Contains(endStr, ".") {
		// Short range format: 192.168.1.0-255
		return parseShortRange(startStr, endStr)
	}

	// Full range format
	startIP := net.ParseIP(startStr)
	endIP := net.ParseIP(endStr)

	if startIP == nil {
		return nil, fmt.Errorf("invalid range start IP %q", startStr)
	}
	if endIP == nil {
		return nil, fmt.Errorf("invalid range end IP %q", endStr)
	}

	// Normalise to same format
	if isIPv6 {
		startIP = startIP.To16()
		endIP = endIP.To16()
	} else {
		startIP = startIP.To4()
		endIP = endIP.To4()
		if startIP == nil || endIP == nil {
			return nil, fmt.Errorf("invalid IPv4 range %q", s)
		}
	}

	return rangeToCIDRs(startIP, endIP)
}

// parseShortRange handles short range notation where only the last octet varies.
// Example: 192.168.1.0-255 → 192.168.1.0 to 192.168.1.255
func parseShortRange(startStr, endOctetStr string) ([]*CIDR, error) {
	startIP := net.ParseIP(startStr)
	if startIP == nil {
		return nil, fmt.Errorf("invalid short range start IP %q", startStr)
	}

	startIP = startIP.To4()
	if startIP == nil {
		return nil, fmt.Errorf("short range only supports IPv4 %q", startStr)
	}

	// Parse end octet
	var endOctet int
	_, err := fmt.Sscanf(endOctetStr, "%d", &endOctet)
	if err != nil || endOctet < 0 || endOctet > 255 {
		return nil, fmt.Errorf("invalid short range end octet %q", endOctetStr)
	}

	// Build end IP
	endIP := make(net.IP, 4)
	copy(endIP, startIP)
	endIP[3] = byte(endOctet) //nolint:gosec // G602: endIP is always 4 bytes (created above)

	return rangeToCIDRs(startIP, endIP)
}

// parseNetmask handles netmask notation.
// Example: 192.168.1.0 255.255.255.0 → 192.168.1.0/24
func parseNetmask(ipStr, maskStr string) ([]*CIDR, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP in netmask notation %q", ipStr)
	}

	mask := net.ParseIP(maskStr)
	if mask == nil {
		return nil, fmt.Errorf("invalid netmask %q", maskStr)
	}

	// Convert to IPv4 if possible
	ip4 := ip.To4()
	mask4 := mask.To4()

	var prefixLen int
	if ip4 != nil && mask4 != nil {
		// IPv4 netmask
		ipMask := net.IPMask(mask4)
		ones, bits := ipMask.Size()
		if bits == 0 {
			return nil, fmt.Errorf("invalid netmask %q: not a valid mask", maskStr)
		}
		// Validate mask is contiguous
		if !isContiguousMask(mask4) {
			return nil, fmt.Errorf("invalid netmask %q: non-contiguous mask", maskStr)
		}
		prefixLen = ones
		ip = ip4
	} else {
		// IPv6 netmask (rare but supported)
		ip = ip.To16()
		mask = mask.To16()
		ipMask := net.IPMask(mask)
		ones, bits := ipMask.Size()
		if bits == 0 {
			return nil, fmt.Errorf("invalid IPv6 netmask %q", maskStr)
		}
		if !isContiguousMask(mask) {
			return nil, fmt.Errorf("invalid netmask %q: non-contiguous mask", maskStr)
		}
		prefixLen = ones
	}

	cidrStr := fmt.Sprintf("%s/%d", ip.String(), prefixLen)
	return parseCIDRToSlice(cidrStr)
}

// isContiguousMask checks if a netmask has contiguous 1-bits.
// A valid mask like 255.255.255.0 is contiguous, 255.255.254.1 is not.
func isContiguousMask(mask net.IP) bool {
	// Convert to binary and check for pattern: 1111...0000
	foundZero := false
	for _, b := range mask {
		for i := 7; i >= 0; i-- {
			bit := (b >> i) & 1
			if bit == 0 {
				foundZero = true
			} else if foundZero {
				// Found a 1 after a 0 - not contiguous
				return false
			}
		}
	}
	return true
}

// rangeToCIDRs converts an IP range to the minimal set of CIDRs.
// Algorithm:
// 1. Convert start/end IPs to big integers
// 2. Find largest CIDR that fits within range starting at current position
// 3. Add to result, advance position
// 4. Repeat until range covered
func rangeToCIDRs(startIP, endIP net.IP) ([]*CIDR, error) {
	// Validate range direction
	if compareIPs(startIP, endIP) > 0 {
		return nil, fmt.Errorf("invalid range: start %s > end %s", startIP, endIP)
	}

	// Determine IP version
	bits := 32
	if len(startIP) == 16 && startIP.To4() == nil {
		bits = 128
	} else {
		startIP = startIP.To4()
		endIP = endIP.To4()
		if startIP == nil || endIP == nil {
			return nil, fmt.Errorf("mismatched IP versions in range")
		}
	}

	start := ipToBigInt(startIP)
	end := ipToBigInt(endIP)

	var cidrs []*CIDR
	one := big.NewInt(1)

	for start.Cmp(end) <= 0 {
		// Find the largest CIDR block that:
		// 1. Starts at 'start'
		// 2. Doesn't exceed 'end'

		// Find how many trailing zeros in start (determines max alignment)
		maxSize := trailingZeros(start, bits)

		// Find the largest block that doesn't exceed end
		// Size of block = 2^(bits - prefix)
		remaining := new(big.Int).Sub(end, start)
		remaining.Add(remaining, one) // +1 because range is inclusive

		for maxSize > 0 {
			blockSize := new(big.Int).Lsh(one, uint(maxSize))
			if blockSize.Cmp(remaining) <= 0 {
				break
			}
			maxSize--
		}

		// Create CIDR
		prefixLen := bits - maxSize
		ip := bigIntToIP(start, bits)
		cidrStr := fmt.Sprintf("%s/%d", ip.String(), prefixLen)
		cidr, err := parseCIDR(cidrStr)
		if err != nil {
			return nil, fmt.Errorf("internal error creating CIDR %s: %v", cidrStr, err)
		}
		cidrs = append(cidrs, cidr)

		// Advance start by block size
		blockSize := new(big.Int).Lsh(one, uint(maxSize)) //nolint:gosec // G115: maxSize is bounded [0, 128]
		start.Add(start, blockSize)
	}

	return cidrs, nil
}

// ipToBigInt converts an IP address to a big.Int.
func ipToBigInt(ip net.IP) *big.Int {
	return new(big.Int).SetBytes(ip)
}

// bigIntToIP converts a big.Int back to an IP address.
func bigIntToIP(n *big.Int, bits int) net.IP {
	bytes := n.Bytes()
	length := bits / 8

	// Pad with leading zeros if necessary
	if len(bytes) < length {
		padded := make([]byte, length)
		copy(padded[length-len(bytes):], bytes)
		bytes = padded
	}

	return net.IP(bytes)
}

// trailingZeros returns the number of trailing zero bits in n.
// For IP alignment, this determines the maximum CIDR block size.
func trailingZeros(n *big.Int, maxBits int) int {
	if n.Sign() == 0 {
		return maxBits // Zero has all trailing zeros up to max
	}

	count := 0
	one := big.NewInt(1)
	temp := new(big.Int).Set(n)

	for count < maxBits {
		if temp.Bit(0) == 1 {
			break
		}
		temp.Rsh(temp, 1)
		count++
	}

	// Clamp to maxBits (for /0 equivalent)
	_ = one // silence unused warning
	if count > maxBits {
		count = maxBits
	}
	return count
}

// parseCIDRToSlice is a helper that wraps parseCIDR result in a slice.
func parseCIDRToSlice(s string) ([]*CIDR, error) {
	cidr, err := parseCIDR(s)
	if err != nil {
		return nil, err
	}
	if cidr == nil {
		return nil, nil
	}
	return []*CIDR{cidr}, nil
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
	os.Exit(mainRun())
}

func mainRun() int {
	var input *os.File
	var err error

	if len(os.Args) > 1 {
		// File argument provided
		input, err = os.Open(os.Args[1])
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error opening file: %v\n", err)
			return 1
		}
		defer func() { _ = input.Close() }()
	} else {
		// Read from stdin
		input = os.Stdin
	}

	if err := run(input, os.Stdout, os.Stderr); err != nil {
		return 1
	}
	return 0
}

func run(input io.Reader, output, errOutput io.Writer) error {
	var cidrs []*CIDR
	scanner := bufio.NewScanner(input)

	// Read all CIDRs from input (supporting multiple formats)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		parsed, err := parseInput(scanner.Text())
		if err != nil {
			_, _ = fmt.Fprintf(errOutput, "line %d: %v\n", lineNum, err)
			continue
		}
		cidrs = append(cidrs, parsed...)
	}

	if err := scanner.Err(); err != nil {
		_, _ = fmt.Fprintf(errOutput, "error reading input: %v\n", err)
		return err
	}

	if len(cidrs) == 0 {
		return nil
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
		if _, err := fmt.Fprintln(output, c); err != nil {
			return err
		}
	}
	for _, c := range ipv6 {
		if _, err := fmt.Fprintln(output, c); err != nil {
			return err
		}
	}

	return nil
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
