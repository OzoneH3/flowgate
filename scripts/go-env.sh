# Source from repository root. All build/cache files stay in the workspace.
export GOCACHE="$PWD/.workspace/go-cache" GOPATH="$PWD/.workspace/go" GOTMPDIR="$PWD/.workspace/tmp" TMPDIR="$PWD/.workspace/tmp"
mkdir -p "$GOCACHE" "$GOPATH" "$GOTMPDIR"
