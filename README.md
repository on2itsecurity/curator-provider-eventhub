# curator-provider-eventhub

Azure Function that forwards Azure Event Hub logs to an AUXO Curator appliance over syslog (RFC 5424 or 3164) or the Fluentd forward protocol.

Status: in development, no stable release yet.

## Layout

| Path | Contents |
| --- | --- |
| `function/` | The Azure Function app (Python, Flex Consumption). This is the code customers run. |
| `tests/` | Unit tests, integration tests and per-source sample payloads. |
| `scripts/` | Build, package and validation scripts used locally and by CI. |
| `docs/` | Customer, operations and developer documentation, architecture notes and decision records. |
| `dist/` | Build output (generated, not committed). |
| `.github/workflows/` | CI and release workflows. |

## Package and releases

CI builds the function into `released-package.zip` (code plus Linux dependencies, ready to run on Flex Consumption) with `scripts/build-package.sh`.

- Every push to `master` updates the release tagged `latest`, a rolling build of `master`: `releases/download/latest/released-package.zip`.
- Publishing a release (for example `v1.2.0`) attaches the package to that release, so a version can be pinned: `releases/download/<tag>/released-package.zip`. A `.sha256` file is published next to every package.

See `CHANGELOG.md` for release history.

## Contributing, security and license

- Contributions: see [CONTRIBUTING.md](CONTRIBUTING.md). This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
- Security issues: do not use the issue tracker, see [SECURITY.md](SECURITY.md).
- License: [MIT](LICENSE.md).
