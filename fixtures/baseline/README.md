# Baseline adversarial fixture laboratory

These definitions are synthetic v0.1.0 release fixtures. They drive the same bounded HTTP/evidence/reporting path used by the operator CLI.

Expected contract:

- `secure.json` → PASS;
- `vulnerable.json` → FAIL;
- `fixed.json` → PASS.

The vulnerable fixture is intentionally deterministic: it returns an unexpected HTTP status for the baseline health contract. The fixed fixture restores the expected behavior.

No production GyLiber target, credential, client record, or private evidence is used.
