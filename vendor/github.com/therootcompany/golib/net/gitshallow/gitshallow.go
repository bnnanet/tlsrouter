package gitshallow

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Repo manages a shallow git clone used as a periodically-updated data source.
type Repo struct {
	URL    string
	Path   string
	Depth  int    // 0 defaults to 1, -1 for all
	Branch string // Optional: specific branch to clone/pull

	// MaxAge skips the git fetch when .git/FETCH_HEAD is younger than this
	// duration. Persists across process restarts (unlike the in-process
	// singleflight dedup) — so repeated short-lived CLI invocations don't
	// hammer the remote. 0 defaults to 1 minute; -1 disables.
	MaxAge time.Duration

	// GCInterval controls explicit aggressive GC after pulls.
	//   0 (default) — no explicit gc; git runs gc.auto on its own schedule
	//   1           — aggressive gc after every pull
	//   N           — aggressive gc after every Nth pull
	GCInterval int

	sf        singleflight.Group
	mu        sync.Mutex // guards pullCount
	pullCount int
}

// New creates a new Repo instance.
func New(url, path string, depth int, branch string) *Repo {
	return &Repo{
		URL:    url,
		Path:   path,
		Depth:  depth,
		Branch: strings.TrimSpace(branch),
	}
}

// validRef matches branch/ref names that are safe to pass to git as a
// positional argument: no leading dash (which git would treat as a flag),
// no whitespace, no shell metacharacters.
var validRef = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

// validateArgs rejects branch values git would interpret as options.
// URL is passed to git after a `--` flag terminator, so git won't
// reinterpret a leading `-` as an option.
func (r *Repo) validateArgs() error {
	if _, err := url.Parse(r.URL); err != nil {
		return fmt.Errorf("invalid URL %q: %w", r.URL, err)
	}
	if r.Branch != "" && !validRef.MatchString(r.Branch) {
		return fmt.Errorf("branch %q contains invalid characters", r.Branch)
	}
	return nil
}

// effectiveDepth returns the depth to use for clone/pull.
// 0 means unset — defaults to 1. -1 means full history.
func (r *Repo) effectiveDepth() int {
	if r.Depth == 0 {
		return 1
	}
	return r.Depth
}

// effectiveMaxAge returns the MaxAge to apply.
// 0 means unset — defaults to 1 minute. -1 disables the gate.
func (r *Repo) effectiveMaxAge() time.Duration {
	switch {
	case r.MaxAge == 0:
		return time.Minute
	case r.MaxAge < 0:
		return 0
	default:
		return r.MaxAge
	}
}

func (r *Repo) clone(ctx context.Context) (bool, error) {
	if r.exists() {
		return false, nil
	}
	if r.URL == "" {
		return false, fmt.Errorf("repository URL is required")
	}
	if r.Path == "" {
		return false, fmt.Errorf("local path is required")
	}
	if err := r.validateArgs(); err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(r.Path), 0o755); err != nil {
		return false, err
	}

	args := []string{"clone", "--no-tags"}
	if depth := r.effectiveDepth(); depth >= 0 {
		args = append(args, "--depth", fmt.Sprintf("%d", depth))
	}
	args = append(args, "--single-branch")
	if r.Branch != "" {
		args = append(args, "--branch", r.Branch)
	}
	// `--` separates flags from positional URL/path so a URL beginning
	// with `-` cannot be reinterpreted by git as an option.
	args = append(args, "--", r.URL, filepath.Base(r.Path))

	_, err := r.runGit(ctx, args...)
	return true, err
}

// exists checks if the directory contains a .git folder.
func (r *Repo) exists() bool {
	_, err := os.Stat(filepath.Join(r.Path, ".git"))
	return err == nil
}

// runGit executes a git command in the repo directory (or parent for clone).
// ctx cancels the child git process via SIGKILL.
func (r *Repo) runGit(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	if _, err := os.Stat(r.Path); err == nil && r.exists() {
		cmd.Dir = r.Path
	} else {
		cmd.Dir = filepath.Dir(r.Path)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Redact userinfo from both the args echo (we may have just passed
		// r.URL) and from git's own output (git embeds the URL in messages
		// like "fatal: unable to access 'https://user:pass@host/'"). If a
		// caller put credentials in the URL — even though the docs steer
		// them to Authorization headers — they don't end up in error logs.
		safeArgs := redactUserinfo(strings.Join(args, " "), r.URL)
		safeOut := redactUserinfo(string(output), r.URL)
		return "", fmt.Errorf("git %s failed: %w\n%s", safeArgs, err, safeOut)
	}
	return strings.TrimSpace(string(output)), nil
}

// redactUserinfo returns s with any "user:pass@" or "user@" segment from
// rawURL replaced with "redacted@". No-op if rawURL has no userinfo.
func redactUserinfo(s, rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.User == nil {
		return s
	}
	return strings.ReplaceAll(s, u.User.String()+"@", "redacted@")
}

func (r *Repo) pull(ctx context.Context) (updated bool, err error) {
	if !r.exists() {
		return false, fmt.Errorf("repository does not exist at %s", r.Path)
	}
	if err := r.validateArgs(); err != nil {
		return false, err
	}

	oldHead, _ := r.runGit(ctx, "rev-parse", "HEAD")

	branch := r.Branch
	if branch == "" {
		out, err := r.runGit(ctx, "symbolic-ref", "--short", "refs/remotes/origin/HEAD")
		if err != nil {
			return false, err
		}
		_, branch, _ = strings.Cut(out, "/")
		if !validRef.MatchString(branch) {
			return false, fmt.Errorf("remote default branch %q contains invalid characters", branch)
		}
	}

	fetchArgs := []string{"fetch", "--no-tags"}
	if depth := r.effectiveDepth(); depth >= 0 {
		fetchArgs = append(fetchArgs, "--depth", fmt.Sprintf("%d", depth))
	}
	// `--` separates flags from positional remote/branch.
	fetchArgs = append(fetchArgs, "--", "origin", branch)
	if _, err := r.runGit(ctx, fetchArgs...); err != nil {
		return false, err
	}

	if _, err := r.runGit(ctx, "reset", "--hard", "origin/"+branch); err != nil {
		return false, err
	}

	newHead, err := r.runGit(ctx, "rev-parse", "HEAD")
	if err != nil {
		return false, err
	}
	return oldHead != newHead, nil
}

func (r *Repo) gc(ctx context.Context) error {
	if !r.exists() {
		return fmt.Errorf("repository does not exist at %s", r.Path)
	}
	_, err := r.runGit(ctx, "gc", "--aggressive", "--prune=now")
	return err
}

// Fetch clones the repo if missing, pulls otherwise, and conditionally runs
// GC based on GCInterval. Returns whether HEAD changed. Implements Fetcher.
// Safe to call concurrently — concurrent callers share a single in-flight
// fetch (via singleflight) and all receive the same result. To force a
// pull regardless of MaxAge, set MaxAge=-1 before calling.
func (r *Repo) Fetch(ctx context.Context) (updated bool, err error) {
	// MaxAge: file-mtime gate (FETCH_HEAD is rewritten on every successful
	// fetch, so its mtime is "last time we talked to the remote").
	if maxAge := r.effectiveMaxAge(); maxAge > 0 {
		if info, err := os.Stat(filepath.Join(r.Path, ".git", "FETCH_HEAD")); err == nil {
			if time.Since(info.ModTime()) < maxAge {
				return false, nil
			}
		}
	}

	v, err, _ := r.sf.Do("fetch", func() (any, error) {
		return r.fetch(ctx)
	})
	if err != nil {
		return false, err
	}
	return v.(bool), nil
}

func (r *Repo) fetch(ctx context.Context) (bool, error) {
	if cloned, err := r.clone(ctx); err != nil {
		return false, err
	} else if cloned {
		return true, nil
	}

	updated, err := r.pull(ctx)
	if err != nil {
		return false, err
	}
	if !updated {
		return false, nil
	}

	if r.GCInterval > 0 {
		r.mu.Lock()
		r.pullCount++
		shouldGC := r.pullCount%r.GCInterval == 0
		r.mu.Unlock()
		if shouldGC {
			return true, r.gc(ctx)
		}
	}

	return true, nil
}

// FilePath returns the absolute path to relPath within this repo.
func (r *Repo) FilePath(rel string) string {
	return filepath.Join(r.Path, rel)
}

// File returns a handle to relPath within this repo. The handle's Path and
// Open methods give access to the file; its Fetch method syncs the repo and
// reports whether this specific file changed (by mtime).
func (r *Repo) File(relPath string) *RepoFile {
	return &RepoFile{repo: r, rel: relPath}
}

// RepoFile is a handle to a single file inside a Repo. Fetch syncs the repo
// (deduped across all RepoFile handles sharing the same Repo) and reports
// whether this file changed. The Repo prefix avoids collision with os.File,
// which is the type returned by Open.
type RepoFile struct {
	repo    *Repo
	rel     string
	mu      sync.Mutex
	lastMod time.Time
}

// Path returns the absolute path to the file.
func (f *RepoFile) Path() string {
	return filepath.Join(f.repo.Path, f.rel)
}

// Fetch syncs the repo and reports whether this file changed since last call.
// Safe to call concurrently. Implements Fetcher.
func (f *RepoFile) Fetch(ctx context.Context) (bool, error) {
	if _, err := f.repo.Fetch(ctx); err != nil {
		return false, err
	}
	info, err := os.Stat(f.Path())
	if err != nil {
		return false, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if info.ModTime().Equal(f.lastMod) {
		return false, nil
	}
	f.lastMod = info.ModTime()
	return true, nil
}
