#!/usr/bin/env bash
#
# make-binary.sh — package keygen.py as a single-file standalone binary.
#
# Output goes to tools/dist/keygen-cbcontroller (or .exe on Windows). No
# Python install needed on the machine that runs the binary; PyInstaller
# bundles its own interpreter + stdlib.
#
# Run on each platform you want to ship a binary for — PyInstaller does
# not cross-compile. The current build host's CPU + OS determines the
# target. Common deployments:
#
#   macOS arm64  →  vendor support running on Apple silicon laptops
#   Linux x86_64 →  CI / vendor portal back-end
#   Linux arm64  →  ops staff working from a Pi
#   Windows x64  →  vendor support on Windows laptops
#
# Run:
#   ./tools/make-binary.sh
#
# Result: ~8 MB single-file executable in tools/dist/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST="${SCRIPT_DIR}/dist"
WORK="${TMPDIR:-/tmp}/cblicense-pyinstaller-work"

# Locate pyinstaller (system, ~/Library, or pip --user).
PYI=""
for cand in \
  "$(command -v pyinstaller || true)" \
  "$HOME/Library/Python/3.14/bin/pyinstaller" \
  "$HOME/Library/Python/3.13/bin/pyinstaller" \
  "$HOME/Library/Python/3.12/bin/pyinstaller" \
  "$HOME/.local/bin/pyinstaller"; do
  if [[ -x "${cand}" ]]; then
    PYI="${cand}"
    break
  fi
done

if [[ -z "${PYI}" ]]; then
  echo "pyinstaller not found. Install with:" >&2
  echo "  python3 -m pip install --user pyinstaller" >&2
  echo "  # or, on Debian-based systems if --user fails:" >&2
  echo "  python3 -m pip install --user --break-system-packages pyinstaller" >&2
  exit 1
fi

echo "→ pyinstaller: ${PYI}"
echo "→ output dir:  ${DIST}"
echo

mkdir -p "${DIST}"

"${PYI}" \
  --onefile \
  --name keygen-cbcontroller \
  --console \
  --clean \
  --noconfirm \
  --distpath "${DIST}" \
  --workpath "${WORK}" \
  --specpath "${WORK}" \
  "${SCRIPT_DIR}/keygen.py"

# Show the result.
echo
echo "✓ built:"
ls -lh "${DIST}/keygen-cbcontroller"* 2>/dev/null

cat <<EOF

The binary embeds its own Python; ship just this file to vendor staff:

    cp ${DIST}/keygen-cbcontroller* ~/Desktop/        # for them to run
    ./keygen-cbcontroller init                       # first-time setup
    ./keygen-cbcontroller mint                       # interactive mint
    ./keygen-cbcontroller --help                     # full subcommands
EOF
