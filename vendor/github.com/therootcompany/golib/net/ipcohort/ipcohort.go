package ipcohort

import (
	"cmp"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"
)

// IPv4Net represents a subnet or single address (/32).
type IPv4Net struct {
	networkBE uint32
	prefix    uint8
}

func NewIPv4Net(ip4be uint32, prefix uint8) IPv4Net {
	return IPv4Net{
		networkBE: ip4be,
		prefix:    prefix,
	}
}

func (r IPv4Net) Contains(ip uint32) bool {
	mask := uint32(0xFFFFFFFF) << (32 - r.prefix)
	return (ip & mask) == r.networkBE
}

// Cohort is an immutable, read-only set of IPv4 addresses and subnets.
// Contains is safe for concurrent use without locks.
//
// hosts holds sorted /32 addresses for O(log n) binary search.
// nets holds CIDR ranges (prefix < 32), sorted by networkBE.
//
// Invariant: nets is an anti-chain — no net contains another. Cohort
// sources are expected to ship pre-normalized (a /8 supersedes any /24
// inside it; the /24 is omitted). Under this invariant at most one net
// can match any IP, so Contains does a single binary search + one
// Contains check rather than walking candidates.
type Cohort struct {
	hosts []uint32
	nets  []IPv4Net
}

func sortNets(nets []IPv4Net) {
	slices.SortFunc(nets, func(a, b IPv4Net) int {
		return cmp.Compare(a.networkBE, b.networkBE)
	})
}

// Size returns the total number of entries (hosts + nets).
func (c *Cohort) Size() int {
	return len(c.hosts) + len(c.nets)
}

// Contains reports whether ipStr falls within any host or subnet in the cohort.
// Returns an error if ipStr is unparseable; callers decide fail-open vs
// fail-closed for invalid input. IPv6 addresses parse but always return false
// (cohort is IPv4-only).
func (c *Cohort) Contains(ipStr string) (bool, error) {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false, fmt.Errorf("parse %q: %w", ipStr, err)
	}
	return c.ContainsAddr(ip), nil
}

// ContainsAddr reports whether ip falls within any host or subnet in the cohort.
// IPv6 addresses always return false (cohort is IPv4-only).
func (c *Cohort) ContainsAddr(ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}
	ip4 := ip.As4()
	ipU32 := binary.BigEndian.Uint32(ip4[:])

	if _, found := slices.BinarySearch(c.hosts, ipU32); found {
		return true
	}

	// Under the anti-chain invariant, at most one net can contain ipU32,
	// and (when one does) it's the net with the largest networkBE <= ipU32.
	// Binary-search for the upper bound, then check the immediate predecessor.
	hi, _ := slices.BinarySearchFunc(c.nets, ipU32, func(n IPv4Net, target uint32) int {
		if n.networkBE > target {
			return 1
		}
		return -1
	})
	if hi == 0 {
		return false
	}
	return c.nets[hi-1].Contains(ipU32)
}

// Parse builds a Cohort from a list of IP/CIDR strings. Returns an error
// listing every unparseable entry; the caller decides whether to proceed
// with a partial cohort by inspecting the returned (non-nil) Cohort.
func Parse(prefixList []string) (*Cohort, error) {
	var hosts []uint32
	var nets []IPv4Net
	var errs []error

	for i, raw := range prefixList {
		ipv4net, err := ParseIPv4(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("entry %d %q: %w", i, raw, err))
			continue
		}
		if ipv4net.prefix == 32 {
			hosts = append(hosts, ipv4net.networkBE)
		} else {
			nets = append(nets, ipv4net)
		}
	}

	slices.Sort(hosts)
	sortNets(nets)

	c := &Cohort{hosts: hosts, nets: nets}
	if len(errs) > 0 {
		return c, fmt.Errorf("ipcohort.Parse: %d invalid entries: %w",
			len(errs), errors.Join(errs...))
	}
	return c, nil
}

func ParseIPv4(raw string) (ipv4net IPv4Net, err error) {
	var ippre netip.Prefix
	var ip netip.Addr
	if strings.Contains(raw, "/") {
		ippre, err = netip.ParsePrefix(raw)
		if err != nil {
			return ipv4net, err
		}
	} else {
		ip, err = netip.ParseAddr(raw)
		if err != nil {
			return ipv4net, err
		}
		ippre = netip.PrefixFrom(ip, 32)
	}

	addr := ippre.Addr()
	if !addr.Is4() {
		return ipv4net, fmt.Errorf("not an IPv4 address: %s", raw)
	}
	ip4 := addr.As4()
	prefix := uint8(ippre.Bits()) // 0–32
	return NewIPv4Net(
		binary.BigEndian.Uint32(ip4[:]),
		prefix,
	), nil
}

// LoadFile reads path and parses it into a Cohort. On open or read
// errors, returns nil + error. On parse errors only, returns the partial
// cohort + a joined error.
func LoadFile(path string) (*Cohort, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not load %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return ParseCSV(f)
}

// LoadFiles loads and merges multiple files into one Cohort. Useful when
// hosts and networks are stored in separate files.
//
// On open or read errors, returns nil + error. On parse errors only,
// returns the partial cohort + a joined error so callers can choose to
// proceed with what loaded.
func LoadFiles(paths ...string) (*Cohort, error) {
	var hosts []uint32
	var nets []IPv4Net
	var parseErrs []error

	for _, path := range paths {
		c, err := LoadFile(path)
		if c == nil {
			return nil, err
		}
		if err != nil {
			parseErrs = append(parseErrs, fmt.Errorf("%s: %w", path, err))
		}
		hosts = append(hosts, c.hosts...)
		nets = append(nets, c.nets...)
	}

	slices.Sort(hosts)
	sortNets(nets)

	c := &Cohort{hosts: hosts, nets: nets}
	if len(parseErrs) > 0 {
		return c, errors.Join(parseErrs...)
	}
	return c, nil
}

// ParseCSV parses CSV cohort data from r.
func ParseCSV(r io.Reader) (*Cohort, error) {
	csvReader := csv.NewReader(r)
	csvReader.FieldsPerRecord = -1
	return ReadAll(csvReader)
}

// ReadAll reads CSV records from r and builds a Cohort. Returns an error
// listing every unparseable entry (with line number); the returned Cohort
// is non-nil and contains every entry that did parse, so callers can choose
// to proceed with a partial cohort.
func ReadAll(r *csv.Reader) (*Cohort, error) {
	var hosts []uint32
	var nets []IPv4Net
	var errs []error

	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("csv read error: %w", err)
		}

		if len(record) == 0 {
			continue
		}

		raw := strings.TrimSpace(record[0])

		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}

		ipv4net, err := ParseIPv4(raw)
		if err != nil {
			line, _ := r.FieldPos(0)
			errs = append(errs, fmt.Errorf("line %d %q: %w", line, raw, err))
			continue
		}

		if ipv4net.prefix == 32 {
			hosts = append(hosts, ipv4net.networkBE)
		} else {
			nets = append(nets, ipv4net)
		}
	}

	slices.Sort(hosts)
	sortNets(nets)

	c := &Cohort{hosts: hosts, nets: nets}
	if len(errs) > 0 {
		return c, fmt.Errorf("ipcohort.ReadAll: %d invalid entries: %w",
			len(errs), errors.Join(errs...))
	}
	return c, nil
}
