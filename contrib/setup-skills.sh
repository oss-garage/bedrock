#!/usr/bin/env bash
#
# setup-skills.sh — download the external source trees the Claude skills rely on.
#
# The `linux` and `bhyve` skills expect large source trees to be present under
# .claude/skills/. Those trees are gitignored, so a fresh checkout has the skill
# prompts but not the code they search. This script fetches them. (The `sdm`
# skill's PDFs are committed to the repo, so they need no setup.)
#
#   linux  -> .claude/skills/linux/linux/        Linux kernel source (tarball)
#   bhyve  -> .claude/skills/bhyve/freebsd-src/  FreeBSD source (pinned commit)
#
# Usage:
#   contrib/setup-skills.sh [SKILL ...]   # default: all of linux bhyve
#   contrib/setup-skills.sh bhyve         # just the FreeBSD tree
#   contrib/setup-skills.sh --force linux # re-download even if present
#
# Options:
#   --force   re-fetch material that is already present
#   --help    show this help
#
# Idempotent: anything already present is skipped unless --force is given.

set -euo pipefail

# --- pinned versions -------------------------------------------------------
# Linux: the skill describes the 6.18 kernel; bump in lockstep with the skill.
LINUX_VERSION="6.18"
# FreeBSD: the bhyve skill pins this exact commit on main (16.0-CURRENT).
FREEBSD_COMMIT="e5ff8e7977434b150a66bb3e472c6d0e0f644cfa"
FREEBSD_REPO="https://github.com/freebsd/freebsd-src.git"

# --- paths -----------------------------------------------------------------
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILLS_DIR="$ROOT/.claude/skills"

# --- helpers ---------------------------------------------------------------
FORCE=0

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '\033[1;33mwarn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1"; }

usage() { sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d;s/^# \{0,1\}//'; }

# --- skill: linux ----------------------------------------------------------
setup_linux() {
  local dest="$SKILLS_DIR/linux/linux"
  if [[ -d "$dest" && $FORCE -eq 0 ]]; then
    log "linux: already present at $dest (use --force to refresh)"
    return
  fi
  need curl; need tar
  log "linux: fetching Linux $LINUX_VERSION source"
  local url="https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-${LINUX_VERSION}.tar.xz"
  local tmp; tmp="$(mktemp -d "$SKILLS_DIR/linux/.dl.XXXXXX")"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN
  info "downloading $url"
  curl -fSL --retry 3 -o "$tmp/linux.tar.xz" "$url"
  info "extracting (this is large; ~1.5GB unpacked)"
  tar -xJf "$tmp/linux.tar.xz" -C "$tmp"
  rm -rf "$dest"
  mv "$tmp/linux-${LINUX_VERSION}" "$dest"
  log "linux: ready at $dest"
}

# --- skill: bhyve ----------------------------------------------------------
setup_bhyve() {
  local dest="$SKILLS_DIR/bhyve/freebsd-src"
  if [[ -d "$dest" && $FORCE -eq 0 ]]; then
    log "bhyve: already present at $dest (use --force to refresh)"
    return
  fi
  need git
  log "bhyve: fetching FreeBSD source @ ${FREEBSD_COMMIT:0:12}"
  local tmp; tmp="$(mktemp -d "$SKILLS_DIR/bhyve/.dl.XXXXXX")"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN
  info "shallow-fetching the pinned commit (large; ~1.5GB checked out)"
  git -C "$tmp" init -q
  git -C "$tmp" remote add origin "$FREEBSD_REPO"
  git -C "$tmp" fetch -q --depth 1 origin "$FREEBSD_COMMIT"
  git -C "$tmp" checkout -q FETCH_HEAD
  rm -rf "$dest"
  mv "$tmp" "$dest"
  log "bhyve: ready at $dest"
}

# --- main ------------------------------------------------------------------
SKILLS=()
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=1 ;;
    --help|-h) usage; exit 0 ;;
    linux|bhyve) SKILLS+=("$arg") ;;
    *) die "unknown argument: $arg (try --help)" ;;
  esac
done
[[ ${#SKILLS[@]} -eq 0 ]] && SKILLS=(linux bhyve)

[[ -d "$SKILLS_DIR" ]] || die "skills dir not found: $SKILLS_DIR"

for skill in "${SKILLS[@]}"; do
  "setup_$skill"
done

log "done. skill material is under $SKILLS_DIR"
