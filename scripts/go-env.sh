# Source from repository root. All build/cache files stay under build/.
export GOCACHE="$PWD/build/go-cache" GOPATH="$PWD/build/go" GOTMPDIR="$PWD/build/tmp" TMPDIR="$PWD/build/tmp"
mkdir -p "$GOCACHE" "$GOPATH" "$GOTMPDIR"
