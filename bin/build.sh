#!/bin/sh
set -eu

# Build tlsrouter with version/commit/date injected via ldflags.
# Matches the GoReleaser-style vars in cmd/tlsrouter/main.go.

g_out="${1:-./tlsrouter}"

g_version="$(git describe --tags --always --dirty 2> /dev/null || echo 0.0.0-dev)"
g_version="${g_version#v}"
g_commit="$(git rev-parse HEAD 2> /dev/null || echo 0000000)"
if test -z "$(git status --porcelain)"; then
	g_date="$(git log -1 --format=%cI)"
else
	g_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
fi

g_ldflags="-X main.version=${g_version}"
g_ldflags="${g_ldflags} -X main.commit=${g_commit}"
g_ldflags="${g_ldflags} -X main.date=${g_date}"

echo "building ${g_out} v${g_version} ${g_commit} ${g_date}"
exec go build -ldflags "${g_ldflags}" -o "${g_out}" ./cmd/tlsrouter/
