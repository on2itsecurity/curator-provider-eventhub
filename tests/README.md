# tests/

- `unit/`: pure unit tests, no Azure or network needed
- `integration/`: tests against a real Event Hub and a mock Curator listener (syslog and forward)
- `samples/<source>/`: realistic fake payloads per supported source. `defender-for-cloud/` stays empty until a real payload is captured.

Samples must contain no real tenant, user or IP data.
