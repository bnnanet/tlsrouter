package tlsrouter

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sync/atomic"
	"time"

	"github.com/therootcompany/golib/net/gitshallow"
	"github.com/therootcompany/golib/net/ipcohort"
)

const (
	blocklistRepoURL  = "https://github.com/bitwire-it/ipblocklist.git"
	blocklistInterval = 47 * time.Minute
)

type IPBlocklist struct {
	repo     *gitshallow.Repo
	inbound  atomic.Pointer[ipcohort.Cohort]
	outbound atomic.Pointer[ipcohort.Cohort]
}

func NewIPBlocklist(ctx context.Context, dataPath string) (*IPBlocklist, error) {
	bl := &IPBlocklist{
		repo: gitshallow.New(
			blocklistRepoURL,
			dataPath,
			1,
			"",
		),
	}

	if err := bl.reload(ctx); err != nil {
		return nil, fmt.Errorf("ipblocklist: initial load: %w", err)
	}

	go bl.refreshLoop(ctx)

	return bl, nil
}

func (bl *IPBlocklist) reload(ctx context.Context) error {
	updated, err := bl.repo.Fetch(ctx)
	if err != nil {
		return err
	}
	if !updated && bl.inbound.Load() != nil {
		return nil
	}

	in, err := ipcohort.LoadFiles(
		bl.repo.FilePath("tables/inbound/single_ips.txt"),
		bl.repo.FilePath("tables/inbound/networks.txt"),
	)
	if err != nil {
		return fmt.Errorf("load inbound: %w", err)
	}

	out, err := ipcohort.LoadFiles(
		bl.repo.FilePath("tables/outbound/single_ips.txt"),
		bl.repo.FilePath("tables/outbound/networks.txt"),
	)
	if err != nil {
		return fmt.Errorf("load outbound: %w", err)
	}

	bl.inbound.Store(in)
	bl.outbound.Store(out)

	fmt.Fprintf(os.Stderr, "INFO: ipblocklist: loaded inbound=%d outbound=%d entries\n",
		in.Size(), out.Size())
	return nil
}

func (bl *IPBlocklist) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(blocklistInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := bl.reload(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "WARN: ipblocklist: reload: %v\n", err)
			}
		}
	}
}

func (bl *IPBlocklist) IsBlockedInbound(addr netip.Addr) bool {
	cohort := bl.inbound.Load()
	if cohort == nil {
		return false
	}
	return cohort.ContainsAddr(addr)
}

func (bl *IPBlocklist) IsBlockedOutbound(addr netip.Addr) bool {
	cohort := bl.outbound.Load()
	if cohort == nil {
		return false
	}
	return cohort.ContainsAddr(addr)
}
