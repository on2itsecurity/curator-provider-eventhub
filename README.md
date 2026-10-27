# curator-provider-eventhub

Azure Function that forwards Azure Event Hub logs to an AUXO Curator appliance over syslog (RFC 5424 or 3164) or the Fluentd forward protocol.

Status: work in progress, not released. Source stays private until release.

## Layout

| Path | Contents |
| --- | --- |
| `function/` | The Azure Function app (Python, Flex Consumption). This is the code customers run. |
| `tests/` | Unit tests, integration tests and per-source sample payloads. |
| `scripts/` | Build, package and validation scripts used locally and by CI. |
| `docs/` | Customer, operations and developer documentation, architecture notes and decision records. |
| `dist/` | Build output (generated, not committed). |
| `.github/workflows/` | CI and release workflows. |

## How the pieces connect

1. `function/` is built in CI on every release to `master` into `released-package.zip` (code plus vendored dependencies, no templates) and published as a GitHub release asset.
2. The offer repo's template deploys that package with `onedeploy` from the release URL: `releases/latest/download/released-package.zip` by default, or `releases/download/<tag>/released-package.zip` when a version is pinned.

See `CHANGELOG.md` for release history.
