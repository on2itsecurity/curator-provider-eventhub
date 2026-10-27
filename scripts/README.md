# scripts/

Build, package and validation scripts, used locally and by CI.

- `build-package.sh [version]`: builds `dist/released-package.zip` (function code, Linux wheels for `PYTHON_VERSION`, default 3.13, `host.json` at the root, no remote build) and `dist/released-package.zip.sha256`. The zip is reproducible: the same inputs give the same checksum. `PYTHON_VERSION` must match the runtime the template deploys.
