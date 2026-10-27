# .github/workflows/

- `ci.yml`: unit tests and a package build on pull requests. Pushes to other branches run nothing.
- `release.yml`: builds `released-package.zip` with `scripts/build-package.sh` and publishes it with its SHA-256 file.
  - On every push to `master` (commits and merges): a release `build-<run number>` marked as latest, so `releases/latest/download/released-package.zip` always serves the newest master.
  - When a release is published (for example `v1.2.0`): the package is attached to that release for pinning at `releases/download/<tag>/released-package.zip`. Mark it as a prerelease to keep it out of `latest`.

Actions are pinned by commit SHA.
