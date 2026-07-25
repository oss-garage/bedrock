#!/usr/bin/env bash
# Fetch the RaceBench target corpus from upstream into the Docker build context,
# pinned to a single commit. Replaces vendoring: the third-party program source
# is no longer committed to this repo, it is downloaded here at build time.
#
# For each target we take variant `.1` (20 injected bugs each) and stage:
#   - the whole code/ tree  -> targets/<name>/code   (compiled FROM SOURCE by the
#     Dockerfile; the build's own Makefiles name their sources explicitly, so the
#     few extra upstream src files this pulls in are ignored and never shipped)
#   - three input files      -> targets/<name>/input/input-{0,1,2}
#
# We deliberately fetch only `<name>.1/code` and `<name>.1/input`, never the
# upstream `install/` dir: RaceBench ships PREBUILT binaries there that are
# explicitly untrusted (see README / Dockerfile). They are never downloaded.
#
# A partial + sparse clone is used so only the small code/input blobs are pulled
# (~2 MB of git objects), not the full 450 MB repo (five variants of every
# program plus prebuilt binaries and traces).
#
# Usage:  ./fetch_targets.sh        # no-op if already fetched at the pinned commit
#         RB_FORCE_FETCH=1 ./fetch_targets.sh   # re-fetch unconditionally
#
# Requires `git` and network access.

set -euo pipefail
cd "$(dirname "$0")"

# RaceBenchData, pinned. Bump this hash (and the README provenance table) to
# move the corpus; nothing else in the tree records the version.
RB_DATA_REPO="https://github.com/rb130/RaceBenchData"
RB_DATA_COMMIT="cb79cc578e064e026e0ed041c8a24501c4d91f58"  # 2023-04-03

TARGETS="blackscholes streamcluster fluidanimate"
INPUTS="input-0 input-1 input-2"

STAMP="targets/.fetched-commit"

# Skip if a previous run already staged this exact commit and every target is
# present. build.sh calls us on every build, so the common case must be cheap.
if [ "${RB_FORCE_FETCH:-0}" != "1" ] && [ -f "$STAMP" ] && \
   [ "$(cat "$STAMP")" = "$RB_DATA_COMMIT" ]; then
	ok=1
	for name in $TARGETS; do
		[ -f "targets/$name/code/Makefile" ] && [ -f "targets/$name/input/input-0" ] || ok=0
	done
	if [ "$ok" = 1 ]; then
		echo "racebench targets already at $RB_DATA_COMMIT; skipping fetch"
		exit 0
	fi
fi

echo "Fetching RaceBench targets from $RB_DATA_REPO @ $RB_DATA_COMMIT"

clone="$(mktemp -d)"
trap 'rm -rf "$clone"' EXIT

git init -q "$clone"
git -C "$clone" remote add origin "$RB_DATA_REPO"
git -C "$clone" config extensions.partialClone origin
git -C "$clone" sparse-checkout init --no-cone

# Restrict the working tree to just the code/ trees and the three inputs we
# stage; this keeps install/ (untrusted binaries) and trace/ out entirely.
sparse_args=""
for name in $TARGETS; do
	sparse_args="$sparse_args $name.1/code"
	for inp in $INPUTS; do
		sparse_args="$sparse_args $name.1/input/$inp"
	done
done
# shellcheck disable=SC2086
git -C "$clone" sparse-checkout set $sparse_args

git -C "$clone" fetch -q --depth 1 --filter=blob:none origin "$RB_DATA_COMMIT"
git -C "$clone" checkout -q "$RB_DATA_COMMIT"

for name in $TARGETS; do
	src="$clone/$name.1"
	if [ ! -d "$src/code" ]; then
		echo "error: upstream is missing $name.1/code at $RB_DATA_COMMIT" >&2
		exit 1
	fi
	rm -rf "targets/$name/code" "targets/$name/input"
	mkdir -p "targets/$name/input"
	cp -a "$src/code" "targets/$name/code"
	for inp in $INPUTS; do
		cp -a "$src/input/$inp" "targets/$name/input/$inp"
	done
done

echo "$RB_DATA_COMMIT" > "$STAMP"
echo "Staged targets: $TARGETS"
