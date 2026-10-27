#!/usr/bin/env bash
# Build released-package.zip: function code plus Linux dependencies, ready to
# run on Flex Consumption (host.json at the zip root, no remote build).
#
# Usage: scripts/build-package.sh [version]
# Output: dist/released-package.zip and dist/released-package.zip.sha256
#
# PYTHON_VERSION must match the runtime version deployed by the template.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:-dev}"
PYTHON_VERSION="${PYTHON_VERSION:-3.13}"
BUILD="$ROOT/dist/build"
ZIP="$ROOT/dist/released-package.zip"

rm -rf "$BUILD" "$ZIP" "$ZIP.sha256"
mkdir -p "$BUILD"

cp "$ROOT/function/function_app.py" "$ROOT/function/host.json" "$BUILD/"

# Wheels only (no builds on the build host), for the Linux runtime of Flex.
python3 -m pip install \
  --requirement "$ROOT/function/requirements.txt" \
  --target "$BUILD/.python_packages/lib/site-packages" \
  --platform manylinux2014_x86_64 \
  --python-version "$PYTHON_VERSION" \
  --implementation cp \
  --only-binary=:all: \
  --no-compile \
  --disable-pip-version-check

COMMIT="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
printf 'version=%s\ncommit=%s\npython=%s\n' "$VERSION" "$COMMIT" "$PYTHON_VERSION" > "$BUILD/BUILD_INFO"

# Reproducible zip: sorted entries, fixed timestamps, fixed permissions.
python3 - "$BUILD" "$ZIP" <<'PY'
import hashlib, os, sys, zipfile

build, out = sys.argv[1], sys.argv[2]
paths = []
for root, dirs, files in os.walk(build):
    dirs[:] = [d for d in dirs if d != "__pycache__"]
    for name in files:
        full = os.path.join(root, name)
        paths.append((os.path.relpath(full, build).replace(os.sep, "/"), full))
paths.sort()
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for rel, full in paths:
        info = zipfile.ZipInfo(rel, date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        with open(full, "rb") as f:
            z.writestr(info, f.read())
digest = hashlib.sha256(open(out, "rb").read()).hexdigest()
with open(out + ".sha256", "w") as f:
    f.write(f"{digest}  released-package.zip\n")
print(f"{len(paths)} files, sha256 {digest}")
PY

echo "Built $ZIP ($(du -h "$ZIP" | cut -f1))"
