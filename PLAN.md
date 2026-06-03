# Plan: PAN-OS Certificate Upload + Remap Script

**Working directory:** `/mnt/disk2/claude_projects/panos-cert-upload/`

## Context

User provides a new certificate (PEM + key). The script uploads it to the Palo Alto firewall via the PAN-OS XML API, then finds all SSL/TLS service profiles (and other references) that point to the old cert name and remaps them to the new cert name, then commits.

---

## Single File: `panos-cert-lifecycle/upload_cert.py`

Or drop it anywhere — one self-contained Python script, no project structure needed.

### CLI Interface

```
python upload_cert.py \
  --old-name  <current PAN-OS cert object name to remap FROM> \
  --new-name  <PAN-OS cert object name to import AS>          \
  --cert      path/to/cert.pem                                \
  [--key      path/to/key.pem]                                \
  [--dry-run]
```

`--key` is **optional**. Whether it's needed depends on the cert type:
- **Omit `--key`** for CA/trust certs used in certificate profiles or trusted CA bundles — the firewall only needs the public cert for verification, no key.
- **Include `--key`** for leaf/server certs backing SSL/TLS service profiles (management interface, GlobalProtect, etc.) — the firewall must prove ownership, so the private key is required.

Env vars (or `.env` file): `PANOS_HOST`, `PANOS_API_KEY`, `PANOS_VERIFY_SSL` (default `false`).

---

## What the Script Does (in order)

1. **Import cert** — `POST /api/?type=import&category=certificate&certificate-name=<new-name>&format=pem` (multipart, `file` field = cert PEM bytes)
2. **Import key** (only if `--key` was provided) — same but `category=private-key`
3. **Discover SSL/TLS service profiles** — `GET /api/?type=config&action=get&xpath=.../vsys1/ssl-tls-service-profile`; find all profiles where `<certificate>` element matches `--old-name`
4. **Discover shared cert references** (optional, if any profiles use certs in shared scope) — same query against `/config/shared/ssl-tls-service-profile` if it exists
5. **Remap each matched profile** — `GET /api/?type=config&action=set&xpath=<profile xpath>&element=<certificate>new-name</certificate>` for each one
6. **Commit** — `POST /api/?type=commit&cmd=<commit/>`; poll job until done
7. **Print summary** — what was imported, which profiles were remapped, commit result

If `--dry-run`: skip steps 1, 2, 5, 6 — only print what would happen.

---

## Key Implementation Notes

- **XPaths to check for references:**
  - vsys SSL/TLS profiles: `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/ssl-tls-service-profile`
  - shared SSL/TLS profiles: `/config/shared/ssl-tls-service-profile`
  - Certificate profiles (for mTLS): `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/certificate-profile` — these reference CAs, not leaf certs, so likely irrelevant but worth scanning
- **Import is a POST with multipart**: `files={"file": ("cert.pem", data, "application/x-pem-file")}`; API key goes in query params, not headers
- **Set call is a GET** (not POST): `type=config&action=set&xpath=...&element=<certificate>new-name</certificate>`
- **Commit returns a job ID**: poll `type=op&cmd=<show><jobs><id>N</id></jobs></show>` every 5s; `<status>FIN</status>` + `<result>OK</result>` = success
- **SSL verify**: default `False` since the management cert is self-signed; overridable via `PANOS_VERIFY_SSL=true`

---

## Dependencies

`httpx`, `python-dotenv` — both already present in the homelab's Python environments.

---

## Verification

1. `--dry-run` first: confirms API reachability and lists which profiles would be remapped
2. Live run: check PAN-OS Device > Certificates for new cert entry, Device > SSL/TLS Service Profiles for updated references, commit log for clean commit
