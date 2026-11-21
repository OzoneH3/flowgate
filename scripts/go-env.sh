# Source from repository root. All build/cache files stay under build/.
export GOCACHE="$PWD/build/go-cache" GOPATH="$PWD/build/go" GOTMPDIR="$PWD/build/tmp" TMPDIR="$PWD/build/tmp"
mkdir -p "$GOCACHE" "$GOPATH/pkg" "$GOTMPDIR"
# Stop ./... at the cache boundary, including in already populated checkouts.
# A nested module works with the oldest supported Go toolchain.
if [ ! -f "$GOPATH/pkg/go.mod" ]; then
  printf '%s\n' 'module flowgate-build-cache' > "$GOPATH/pkg/go.mod"
fi
