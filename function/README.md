# function/

The Azure Function app deployed to the customer.

Planned contents:

- `function_app.py`: the Event Hub trigger and forwarding logic
- `host.json`: Functions host configuration (retry policy, batch and checkpoint settings)
- `requirements.txt`: exact, pinned dependencies (or a lock file)
- `local.settings.json.example`: template for local runs (never commit the real file)

Behavior decisions: syslog and forward protocols, forward tag `azure.<category lowercased>`, records forwarded unmodified, fire-and-forget delivery, identity-based Event Hub connection.
