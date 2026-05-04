#!/bin/sh
set -e

# Build tlsrouter for linux/amd64 and deploy to a remote host.
# Usage: ./scripts/build-and-deploy.sh <host>

if test -z "$1"; then
	echo "Usage: $0 <host>" >&2
	exit 1
fi

g_host="$1"
g_out="./agents/tmp/tlsrouter-linux-amd64"

mkdir -p ./agents/tmp

g_ldflags="-X main.version=$(git describe --tags --always) -X main.commit=$(git rev-parse --short HEAD) -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v2 go build -ldflags "$g_ldflags" -o "$g_out" ./cmd/tlsrouter/

echo "Built: $(file "$g_out" | cut -d: -f2)"

scp "$g_out" "${g_host}:~/bin/tlsrouter.new"
ssh "$g_host" "mv ~/bin/tlsrouter.new ~/bin/tlsrouter && chmod +x ~/bin/tlsrouter"

echo ""
echo "Deployed. Remote version:"
ssh "$g_host" "~/bin/tlsrouter --version"
