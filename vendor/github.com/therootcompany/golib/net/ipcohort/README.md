# [ipcohort](https://github.com/therootcompany/golib/tree/main/net/ipcohort)

A memory-efficient, fast IP cohort checker for blacklists, whitelists, and ad cohorts.

- 4 bytes per /32 host, 5 bytes per CIDR range (8 with alignment padding)
- O(log n) binary search across both hosts and CIDR ranges
- immutable cohorts — callers swap via `atomic.Pointer` for lock-free reads
- requires CIDR sources to be an anti-chain (no entry contained in another;
  a /8 supersedes any /24 inside it). Most curated blocklists already
  ship pre-normalized this way.

## Example

Check if an IP address belongs to a cohort (such as a blacklist):

```go
cohort, err := ipcohort.LoadFile("/srv/data/inbound.txt")
if err != nil {
    log.Fatalf("load: %v", err)
}

blocked, err := cohort.Contains("92.255.85.72")
if err != nil {
    log.Fatalf("parse: %v", err)
}
if blocked {
    fmt.Println("BLOCKED")
    os.Exit(1)
}
fmt.Println("allowed")
```

`Cohort.Contains(string)` parses the address each call and returns an error
on unparseable input — callers decide fail-open vs fail-closed. If you
already have a `netip.Addr` (e.g. from `netip.ParseAddr` on a request peer),
use `Cohort.ContainsAddr(netip.Addr)` to skip the parse and the error.
