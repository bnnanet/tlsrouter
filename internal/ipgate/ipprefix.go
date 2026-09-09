package ipgate

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

const prefixSetRefreshInterval = 47 * time.Minute

type PrefixSet struct {
	ctx          context.Context
	repo         *gitshallow.Repo
	files        []string
	overlayFiles []string
	cohort       atomic.Pointer[ipcohort.Cohort]
}

func EmptyPrefixSet() *PrefixSet {
	ps := &PrefixSet{}
	ps.cohort.Store(&ipcohort.Cohort{})
	return ps
}

func NewPrefixSet(ctx context.Context, repoURL, dataPath string, overlayFiles []string, files []string) (*PrefixSet, error) {
	if err := os.MkdirAll(dataPath, 0o755); err != nil {
		return nil, fmt.Errorf("ipgate: create data dir: %w", err)
	}

	repo := gitshallow.New(repoURL, dataPath, 0, "")

	ps := &PrefixSet{
		ctx:          ctx,
		repo:         repo,
		files:        files,
		overlayFiles: overlayFiles,
	}
	ps.cohort.Store(&ipcohort.Cohort{})

	go ps.refreshLoop(ctx)

	return ps, nil
}

func (ps *PrefixSet) Contains(addr netip.Addr) bool {
	cohort := ps.cohort.Load()
	if cohort == nil {
		cohort = &ipcohort.Cohort{}
		ps.cohort.CompareAndSwap(nil, cohort)
	}
	return cohort.ContainsAddr(addr)
}

func (ps *PrefixSet) reload() error {
	ctx := ps.ctx
	updated, err := ps.repo.Fetch(ctx)
	if err != nil {
		return err
	}
	paths := make([]string, 0, len(ps.files)+len(ps.overlayFiles))
	for _, f := range ps.files {
		paths = append(paths, ps.repo.FilePath(f))
	}
	for _, f := range ps.overlayFiles {
		paths = append(paths, f)
	}

	current := ps.cohort.Load()
	if !updated && current != nil && current.Size() > 0 && filesPresent(paths) {
		return nil
	}

	cohort, err := ipcohort.LoadFiles(paths...)
	if err != nil {
		return fmt.Errorf("load files: %w", err)
	}

	ps.cohort.Store(cohort)

	log().Info("prefix set loaded", "entries", commaify(cohort.Size()))
	return nil
}

func filesPresent(paths []string) bool {
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			return false
		}
	}
	return true
}

func (ps *PrefixSet) refreshLoop(ctx context.Context) {
	if err := ps.reload(); err != nil {
		log().Warn("prefix set initial load (will retry)", "err", err)
	}

	ticker := time.NewTicker(prefixSetRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := ps.reload(); err != nil {
				log().Warn("prefix set reload failed", "err", err)
			}
		}
	}
}
