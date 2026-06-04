# panos-cert-rotate

A single-file Python tool that uploads a new certificate to a Palo Alto firewall via the PAN-OS XML API and automatically remaps every SSL/TLS service profile (and other references) from the old cert name to the new one, then commits.

Designed for homelab and small-team production use where you rotate certs on a schedule or after a CA change and don't want to manually hunt down every profile that references the old cert.

---

## Features

- Imports a PEM certificate (and optionally its private key) into PAN-OS
- Automatically discovers **all** references to the old cert name across:
  - SSL/TLS service profiles (all vsys + shared)
  - GlobalProtect gateway and portal configs
  - SSL decryption forward-trust / forward-untrust / inbound inspection certs
  - Device management SSL/TLS service profile
- Remaps every discovered reference to the new cert name in a single operation
- Commits and polls the job to completion
- `--dry-run` mode: discovery and reporting only — no changes made

### Safety features

- Acquires a **config lock** before touching anything; releases it (or reverts) on any failure
- Saves a **named snapshot** of the running config on the device before making changes
- **Reverts the candidate config** automatically if any step fails mid-run — no partial state left behind
- Runs a **pre-commit validation** check before the live commit fires
- Supports **admin-scoped commits** (`--commit-admin`) so the commit only includes your changes, not other in-progress admin work
- Guards against **overwriting an existing cert** unless `--force-overwrite` is explicitly passed
- Validates the cert and key **before** any API call: expiry, cert↔key pair match, key file permissions
- Detects **API key rejection** and tells you to regenerate — keys are invalidated whenever the admin account's password changes
- Throttles bulk set calls at **100 ms intervals** to avoid overloading the management plane
- All cert names are **XML/XPath-escaped** before use in API calls — no injection surface

---

## Requirements

- Python 3.11+
- PAN-OS 9.x or later (tested on 10.x / 11.x)
- Python packages:

```
httpx
python-dotenv
cryptography
```

Install:

```bash
pip install httpx python-dotenv cryptography
```

The `cryptography` package is strongly recommended. If it's absent the tool still runs but skips cert/key pre-flight validation with a warning.

---

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
chmod 600 .env
```

```ini
PANOS_HOST=10.250.100.1        # firewall management IP or hostname
PANOS_API_KEY=                 # PAN-OS XML API key (see below)
PANOS_VERIFY_SSL=false         # false | true | /path/to/ca-bundle.pem
```

### Generating an API key

```bash
curl -k "https://<host>/api/?type=keygen&user=<admin>&password=<pass>"
```

**Recommendation:** Create a dedicated service account with a custom admin role scoped to only what this tool needs:

| Operation | Required privilege |
|---|---|
| Import certificate / key | `Import` |
| Read config (discovery) | `Configuration > Read` |
| Set config (remap) | `Configuration > Read/Write` |
| Commit | `Commit` |

API keys are tied to admin credentials. If the admin's password changes, the key is invalidated — regenerate it.

### SSL verification

| Value | Behaviour |
|---|---|
| `false` (default) | Skip TLS verification — safe for self-signed management certs on isolated management networks |
| `true` | Verify against the system CA bundle |
| `/path/to/ca.pem` | Verify against a specific CA bundle (e.g. your internal Step-CA root) |

> **Note:** If you pass `--key` and `PANOS_VERIFY_SSL=false`, the private key is transmitted to an unverified TLS endpoint. This is acceptable on a trusted, isolated management VLAN. If your management plane is accessible over untrusted networks, set `PANOS_VERIFY_SSL` to your CA bundle path.

---

## Usage

### Dry run (always do this first)

```bash
python upload_cert.py \
  --old-name  my-old-cert \
  --new-name  my-new-cert \
  --cert      /path/to/new-cert.pem \
  --dry-run
```

Prints every profile and config section that would be remapped. Makes no changes to the firewall.

### Rotate a leaf / server certificate (cert + key)

```bash
python upload_cert.py \
  --old-name      my-old-cert \
  --new-name      my-new-cert \
  --cert          /path/to/new-cert.pem \
  --key           /path/to/new-key.pem \
  --commit-admin  api-service-account
```

### Rotate a CA / trust certificate (cert only, no key)

```bash
python upload_cert.py \
  --old-name  old-ca-cert \
  --new-name  new-ca-cert \
  --cert      /path/to/new-ca.pem
```

### Overwrite an existing cert object

If a cert named `--new-name` already exists on the firewall, the tool aborts unless you explicitly pass:

```bash
python upload_cert.py \
  --old-name        my-cert \
  --new-name        my-cert \
  --cert            /path/to/renewed-cert.pem \
  --key             /path/to/key.pem \
  --force-overwrite
```

This is the pattern for renewing a cert in-place (same name, new PEM).

### Full option reference

```
python upload_cert.py --help

  --old-name         Cert name currently referenced in profiles (remap FROM)  [required]
  --new-name         Cert object name to import AS (remap TO)                 [required]
  --cert             Path to PEM cert file                                     [required]
  --key              Path to PEM private key (leaf/server certs only)
  --dry-run          Discover and report only — no changes made
  --force-overwrite  Overwrite existing cert named --new-name if present
  --commit-admin     Admin username to scope the commit to (recommended)
  --commit-timeout   Max seconds to wait for commit job (default: 300)
```

---

## What gets scanned

The tool dynamically enumerates all vsys on the device and checks every known location where a cert name can be referenced:

| Scope | XPath |
|---|---|
| SSL/TLS service profiles (per vsys) | `.../vsys/entry[@name='N']/ssl-tls-service-profile` |
| SSL/TLS service profiles (shared) | `/config/shared/ssl-tls-service-profile` |
| GlobalProtect gateway | `.../vsys/entry/global-protect-gateway/entry/...` |
| GlobalProtect portal | `.../vsys/entry/global-protect-portal/entry/...` |
| SSL decryption (forward trust RSA/ECDSA) | `.../vsys/entry/ssl-decrypt/forward-trust-certificate-*` |
| SSL decryption (forward untrust RSA/ECDSA) | `.../vsys/entry/ssl-decrypt/forward-untrust-certificate-*` |
| Device management | `.../deviceconfig/system/ssl-tls-service-profile` |

---

## Rollback

If anything fails after changes begin, the tool automatically issues `type=config&action=revert` to restore the candidate config to the last committed state. No manual intervention needed.

For manual recovery, the tool saves a named snapshot on the device before making any changes (visible under **Device > Setup > Operations > Saved Configurations**). The snapshot name is printed in the output and written to the audit log.

To restore manually in PAN-OS:

```
Device > Setup > Operations > Load Named Configuration Snapshot > pre-cert-rotate-<timestamp>
```

Then commit.

---

## Audit log

Every live run writes a structured log to `/var/log/panos-cert-rotate/<timestamp>.log` containing:

- Invocation arguments
- Discovery results (all scanned scopes and matches)
- Each remap operation
- Pre-commit validation result
- Commit job ID and final status
- Pre-change snapshot name

Dry runs log to stdout only.

---

## Example output

```
2025-01-15 14:32:01 INFO  Mode: LIVE
2025-01-15 14:32:01 INFO  old-name=gp-cert-2023  new-name=gp-cert-2025  cert=gp-cert-2025.pem  key=gp-key-2025.pem
2025-01-15 14:32:01 INFO  Certificate valid until 2026-01-15 (365 days).
2025-01-15 14:32:01 INFO  Certificate and private key validated — they match.
2025-01-15 14:32:02 INFO  Found vsys: ['vsys1']
2025-01-15 14:32:02 INFO  --- Discovery results ---
2025-01-15 14:32:02 INFO    SSL/TLS profile [vsys/vsys1] 'gp-gateway-ssl'
2025-01-15 14:32:02 INFO    SSL/TLS profile [vsys/vsys1] 'mgmt-ssl'
2025-01-15 14:32:02 INFO    GlobalProtect [vsys/vsys1] global-protect-gateway/entry/gw1
2025-01-15 14:32:02 INFO  Config lock acquired.
2025-01-15 14:32:03 INFO  Pre-change snapshot saved: 'pre-cert-rotate-20250115T143203Z'
2025-01-15 14:32:03 INFO  Certificate 'gp-cert-2025' imported.
2025-01-15 14:32:04 INFO  Private key for 'gp-cert-2025' imported.
2025-01-15 14:32:04 INFO  Remapped SSL/TLS profile [vsys/vsys1] 'gp-gateway-ssl'.
2025-01-15 14:32:04 INFO  Remapped SSL/TLS profile [vsys/vsys1] 'mgmt-ssl'.
2025-01-15 14:32:04 INFO  Remapped GlobalProtect global-protect-gateway/entry/gw1.
2025-01-15 14:32:05 INFO  Pre-commit validation passed.
2025-01-15 14:32:05 INFO  Commit job 12 started.
2025-01-15 14:32:12 INFO  Commit job 12 completed successfully.
2025-01-15 14:32:12 INFO  --- Summary ---
2025-01-15 14:32:12 INFO  Certificate imported: 'gp-cert-2025'
2025-01-15 14:32:12 INFO  Key imported: yes
2025-01-15 14:32:12 INFO  Profiles remapped: 3
2025-01-15 14:32:12 INFO  Commit job ID: 12
2025-01-15 14:32:12 INFO  Pre-change snapshot on device: 'pre-cert-rotate-20250115T143203Z'
2025-01-15 14:32:12 INFO  Full audit log: /var/log/panos-cert-rotate/20250115T143203Z.log
2025-01-15 14:32:12 INFO  Config lock released.
```

---

## Known limitations

- **Panorama-managed firewalls:** Changes made directly to a firewall managed by Panorama may be overwritten on the next Panorama push. Run this against Panorama's API or push the cert via Panorama templates instead.
- **Certificate profiles (mTLS):** Cert profiles that reference CA certs for client authentication are not remapped — those reference CA certs by name and typically don't need updating when rotating a leaf cert. If you're rotating a CA cert that's referenced in cert profiles, update those manually.
- **Chain / full-chain PEM files:** If your cert file contains multiple certificates (e.g. a full chain from Let's Encrypt or Step-CA), the tool warns and imports only the first (leaf) certificate. The intermediate and root certs are ignored — PAN-OS handles its own trust chain separately. Import intermediates/roots as separate cert objects if needed.
- **PKCS#12 / DER format:** Only PEM input is supported. Convert first: `openssl pkcs12 -in cert.p12 -out cert.pem -nodes`

---

## License

MIT
