# .github/workflows/

- `ci.yml`: unit tests and a package build on pull requests. Pushes to other branches run nothing.
- `release.yml`: builds `released-package.zip` with `scripts/build-package.sh` and publishes it with its SHA-256 file.
  - On every push to `master` (commits and merges): the single release tagged `latest` is updated. The tag moves to the new commit and the assets are replaced, so `releases/download/latest/released-package.zip` always serves the newest master. It is not flagged as GitHub's "latest release" (`--latest=false`), so it does not compete with versioned releases.
  - When a release is published (for example `v1.2.0`): the package is attached to that release for pinning at `releases/download/<tag>/released-package.zip`.

Actions are pinned by commit SHA.
