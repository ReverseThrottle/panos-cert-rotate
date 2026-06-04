#!/usr/bin/env python3
"""
PAN-OS certificate upload and SSL/TLS service profile remap tool.

Uploads a new cert (and optionally its private key) to a Palo Alto firewall
via the XML API, remaps all SSL/TLS service profiles that reference the old
cert name to the new one, then commits.

Env vars (or .env file):
  PANOS_HOST        Firewall management IP or hostname
  PANOS_API_KEY     PAN-OS XML API key
  PANOS_VERIFY_SSL  Path to CA bundle, or "true"/"false" (default: false)
"""

import argparse
import json
import logging
import os
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET
import xml.sax.saxutils as saxutils

import httpx
from dotenv import load_dotenv

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG_DIR = Path("/var/log/panos-cert-rotate")

def _setup_logging(dry_run: bool) -> tuple[logging.Logger, Path | None]:
    logger = logging.getLogger("panos-cert-rotate")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    log_file = None
    if not dry_run:
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            log_file = LOG_DIR / f"{ts}.log"
            fh = logging.FileHandler(log_file)
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(fmt)
            logger.addHandler(fh)
        except OSError as e:
            logger.warning("Cannot write audit log to %s: %s — logging to stdout only", LOG_DIR, e)

    return logger, log_file


# ---------------------------------------------------------------------------
# PAN-OS API client
# ---------------------------------------------------------------------------

class PanosError(Exception):
    pass


class PanosAuthError(PanosError):
    pass


class PanosClient:
    """Thin wrapper around the PAN-OS XML API."""

    # How long to wait between successive set calls (ms) to avoid mgmt-plane overload.
    SET_CALL_DELAY_S = 0.1

    def __init__(self, host: str, api_key: str, verify_ssl, logger: logging.Logger):
        self._base = f"https://{host}/api/"
        self._key = api_key
        self._logger = logger
        self._client = httpx.Client(verify=verify_ssl, timeout=30)

    def close(self):
        self._client.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_status(self, root: ET.Element, operation: str) -> None:
        status = root.get("status")
        if status == "success":
            return
        code = root.get("code", "unknown")
        msg_el = root.find(".//msg")
        if msg_el is not None:
            # Message may be direct text or nested in <line> children
            msg = msg_el.text or " ".join(
                (line.text or "").strip()
                for line in msg_el.findall("line")
            ) or ET.tostring(root, encoding="unicode")
        else:
            msg = ET.tostring(root, encoding="unicode")
        if code in ("403", "16") or "Invalid credentials" in (msg or "") or "Auth failed" in (msg or ""):
            raise PanosAuthError(
                f"{operation} failed — API key rejected (code {code}). "
                "Regenerate PANOS_API_KEY (keys expire when admin password changes)."
            )
        raise PanosError(f"{operation} failed (code {code}): {msg}")

    def _get(self, params: dict) -> ET.Element:
        params["key"] = self._key
        resp = self._client.get(self._base, params=params)
        resp.raise_for_status()
        root = ET.fromstring(resp.text)
        return root

    def _post(self, params: dict, **kwargs) -> ET.Element:
        params["key"] = self._key
        resp = self._client.post(self._base, params=params, **kwargs)
        resp.raise_for_status()
        root = ET.fromstring(resp.text)
        return root

    # ------------------------------------------------------------------
    # Config operations
    # ------------------------------------------------------------------

    def acquire_config_lock(self) -> None:
        root = self._get({"type": "op", "cmd": "<lock><config></config></lock>"})
        self._check_status(root, "acquire config lock")
        self._logger.info("Config lock acquired.")

    def release_config_lock(self) -> None:
        try:
            root = self._get({"type": "op", "cmd": "<unlock><config></config></unlock>"})
            self._check_status(root, "release config lock")
            self._logger.info("Config lock released.")
        except Exception as e:
            self._logger.warning("Could not release config lock: %s", e)

    def revert_candidate(self) -> None:
        try:
            root = self._get({"type": "op", "cmd": "<revert><config></config></revert>"})
            self._check_status(root, "revert candidate config")
            self._logger.info("Candidate config reverted to last committed state.")
        except Exception as e:
            msg = str(e)
            if "queued" in msg.lower() or "jobs" in msg.lower():
                self._logger.error(
                    "Could not auto-revert: a commit/validate job is still queued on the device. "
                    "Wait for it to finish, then manually revert via: "
                    "Device > Setup > Operations > Revert to last saved configuration."
                )
            else:
                self._logger.error("Failed to revert candidate config: %s", e)

    def save_config_snapshot(self, name: str) -> None:
        safe_name = saxutils.escape(name)
        root = self._get({"type": "op", "cmd": f"<save><config><to>{safe_name}</to></config></save>"})
        self._check_status(root, f"save snapshot '{name}'")
        self._logger.info("Running config saved as '%s' on device.", name)

    def get_config(self, xpath: str) -> ET.Element:
        root = self._get({"type": "config", "action": "get", "xpath": xpath})
        self._check_status(root, f"get config {xpath}")
        return root

    def set_config(self, xpath: str, element_xml: str) -> None:
        root = self._get({
            "type": "config",
            "action": "set",
            "xpath": xpath,
            "element": element_xml,
        })
        try:
            self._check_status(root, f"set config {xpath}")
        except PanosError as e:
            if root.get("code") == "13" and "override" in str(e):
                self._logger.warning(
                    "Object at %s is template-managed; retrying with action=override.", xpath
                )
                root = self._get({
                    "type": "config",
                    "action": "override",
                    "xpath": xpath,
                    "element": element_xml,
                })
                self._check_status(root, f"override config {xpath}")
            else:
                raise
        time.sleep(self.SET_CALL_DELAY_S)

    def edit_config(self, xpath: str, element_xml: str) -> None:
        """Replace the element at xpath entirely (action=edit, not additive like action=set)."""
        root = self._get({
            "type": "config",
            "action": "edit",
            "xpath": xpath,
            "element": element_xml,
        })
        self._check_status(root, f"edit config {xpath}")
        time.sleep(self.SET_CALL_DELAY_S)

    def cert_exists(self, vsys_xpath: str, cert_name: str) -> bool:
        safe_name = saxutils.escape(cert_name)
        xpath = f"{vsys_xpath}/certificate/entry[@name='{safe_name}']"
        try:
            root = self._get({"type": "config", "action": "get", "xpath": xpath})
            return root.get("status") == "success" and root.find(".//entry") is not None
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Import
    # ------------------------------------------------------------------

    def import_certificate(self, cert_name: str, cert_bytes: bytes) -> None:
        """Import a certificate only (no private key)."""
        root = self._post(
            {"type": "import", "category": "certificate", "certificate-name": cert_name, "format": "pem"},
            files={"file": ("cert.pem", cert_bytes, "application/x-pem-file")},
        )
        self._check_status(root, "import certificate")
        self._logger.info("Certificate '%s' imported.", cert_name)

    def import_keypair(self, cert_name: str, cert_bytes: bytes, key_bytes: bytes, passphrase: bytes = b"") -> None:
        """Import a certificate and private key together using category=keypair."""
        combined = cert_bytes + b"\n" + key_bytes
        files: dict = {"file": ("keypair.pem", combined, "application/x-pem-file")}
        if passphrase:
            # Send passphrase in the multipart body so it does not appear in the
            # request URI (and therefore not in firewall/proxy access logs).
            files["passphrase"] = (None, passphrase.decode(), "text/plain")
        root = self._post(
            {
                "type": "import",
                "category": "keypair",
                "certificate-name": cert_name,
                "format": "pem",
            },
            files=files,
        )
        self._check_status(root, "import keypair")
        self._logger.info("Certificate and private key '%s' imported.", cert_name)

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def is_multi_vsys(self) -> bool:
        """Return True if multi-vsys is enabled on this device."""
        try:
            root = self._get({"type": "op", "cmd": "<show><system><info></info></system></show>"})
            el = root.find(".//multi-vsys")
            return el is not None and el.text == "on"
        except Exception:
            return True  # safe default: treat as multi-vsys

    def list_vsys(self) -> list[str]:
        try:
            root = self.get_config("/config/devices/entry[@name='localhost.localdomain']/vsys")
            vsys = [e.get("name") for e in root.findall(".//vsys/entry") if e.get("name")]
            return vsys or ["vsys1"]
        except Exception as e:
            self._logger.warning(
                "Could not enumerate vsys (falling back to vsys1 only): %s — "
                "cert refs in other vsys will NOT be discovered or remapped.", e
            )
            return ["vsys1"]

    def find_ssl_profile_refs(self, xpath: str, old_cert: str) -> list[str]:
        """Return list of profile @name values whose <certificate> equals old_cert."""
        try:
            root = self.get_config(xpath)
        except PanosError:
            return []
        matches = []
        for entry in root.findall(".//entry"):
            cert_el = entry.find("certificate")
            if cert_el is not None and cert_el.text == old_cert:
                name = entry.get("name")
                if name:
                    matches.append(name)
        return matches

    def find_gp_refs(self, vsys: str, old_cert: str) -> list[tuple[str, str]]:
        """Return list of (type_label, xpath_to_set) for GP gateway/portal cert refs."""
        base = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{saxutils.escape(vsys)}']"
        hits = []
        for gp_type in ("global-protect/global-protect-gateway/entry", "global-protect/global-protect-portal/entry"):
            try:
                root = self.get_config(f"{base}/{gp_type}")
            except PanosError:
                continue
            for entry in root.findall(".//entry"):
                gw_name = entry.get("name", "")
                for ssl_el in entry.findall(".//ssl-tls-service-profile"):
                    if ssl_el.text == old_cert:
                        full_xpath = f"{base}/{gp_type}[@name='{saxutils.escape(gw_name)}']/ssl-tls-service-profile"
                        hits.append((f"{gp_type}/{gw_name}", full_xpath))
        return hits

    def find_gp_cookie_refs(self, vsys: str, old_cert: str) -> list[dict]:
        """Return list of {vsys, label, set_xpath} for GP cookie-encrypt-decrypt-cert refs.

        The set_xpath points to the <authentication-override> parent so that
        action=set with element <cookie-encrypt-decrypt-cert>...</cookie-encrypt-decrypt-cert>
        replaces the text value correctly.
        """
        base = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{saxutils.escape(vsys)}']"
        hits = []
        for gp_type in ("global-protect/global-protect-portal/entry", "global-protect/global-protect-gateway/entry"):
            try:
                root = self.get_config(f"{base}/{gp_type}")
            except PanosError:
                continue
            for entry in root.findall(".//entry"):
                gp_name = entry.get("name", "")
                for cfg_entry in entry.findall(".//client-config/configs/entry"):
                    cfg_name = cfg_entry.get("name", "")
                    for cookie_el in cfg_entry.findall("authentication-override/cookie-encrypt-decrypt-cert"):
                        if cookie_el.text == old_cert:
                            auth_xpath = (
                                f"{base}/{gp_type}[@name='{saxutils.escape(gp_name)}']"
                                f"/client-config/configs/entry[@name='{saxutils.escape(cfg_name)}']"
                                f"/authentication-override"
                            )
                            hits.append({
                                "vsys": vsys,
                                "label": f"{gp_type}/{gp_name}/config/{cfg_name}",
                                "set_xpath": auth_xpath,
                            })
        return hits

    def find_decrypt_refs(self, vsys: str, old_cert: str) -> list[tuple[str, str]]:
        """Return list of (label, xpath) for SSL decryption cert refs."""
        base = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{saxutils.escape(vsys)}']/ssl-decrypt"
        hits = []
        for field in ("forward-trust-certificate-rsa", "forward-untrust-certificate-rsa",
                      "forward-trust-certificate-ecdsa", "forward-untrust-certificate-ecdsa"):
            try:
                root = self.get_config(f"{base}/{field}")
                if root.find(".//" + field) is not None:
                    el = root.find(".//" + field)
                    if el is not None and el.text == old_cert:
                        hits.append((f"ssl-decrypt/{field}", f"{base}/{field}"))
            except PanosError:
                pass
        return hits

    def find_shared_decrypt_refs(self, old_cert: str) -> list[dict]:
        """Return list of {label, set_xpath, element_tag} for shared ssl-decrypt forward-trust cert refs.

        PAN-OS 11.x stores these under /config/shared/ssl-decrypt/forward-trust-certificate
        with nested <rsa> and <ecdsa> children (not flat hyphenated names).
        """
        base = "/config/shared/ssl-decrypt/forward-trust-certificate"
        hits = []
        try:
            root = self.get_config(base)
        except PanosError:
            return hits
        for tag in ("rsa", "ecdsa"):
            el = root.find(f".//{tag}")
            if el is not None and el.text == old_cert:
                hits.append({
                    "label": f"shared/ssl-decrypt/forward-trust-certificate/{tag}",
                    "set_xpath": base,
                    "element_tag": tag,
                })
        return hits

    def find_cert_profile_refs(self, xpath: str, old_cert: str) -> list[dict]:
        """Return list of {name, ca_names, set_xpath} for cert profiles whose CA list contains old_cert.

        PAN-OS stores CA entries as <CA><entry name="cert-name"/></CA>.
        """
        try:
            root = self.get_config(xpath)
        except PanosError:
            return []
        matches = []
        for entry in root.findall(".//entry"):
            name = entry.get("name")
            if not name:
                continue
            ca_el = entry.find("CA")
            if ca_el is None:
                continue
            ca_names = [e.get("name") for e in ca_el.findall("entry") if e.get("name")]
            if old_cert in ca_names:
                safe_n = saxutils.escape(name)
                matches.append({
                    "name": name,
                    "ca_names": ca_names,
                    "entry_xpath": f"{xpath}/entry[@name='{safe_n}']",
                })
        return matches

    def delete_certificate(self, cert_name: str) -> bool:
        """Delete a certificate by name; searches vsys then shared scope.

        Returns True if deleted, False if not found in either scope.
        """
        dev_base = "/config/devices/entry[@name='localhost.localdomain']"
        safe_name = saxutils.escape(cert_name)
        for scope, xpath in [
            ("vsys1", f"{dev_base}/vsys/entry[@name='vsys1']/certificate/entry[@name='{safe_name}']"),
            ("shared", f"/config/shared/certificate/entry[@name='{safe_name}']"),
        ]:
            try:
                check = self._get({"type": "config", "action": "get", "xpath": xpath})
            except PanosError:
                continue
            if check.get("status") == "success" and check.find(".//entry") is not None:
                root = self._get({"type": "config", "action": "delete", "xpath": xpath})
                self._check_status(root, f"delete certificate '{cert_name}'")
                self._logger.info("Certificate '%s' deleted from %s.", cert_name, scope)
                return True
        return False

    def find_device_mgmt_ref(self, old_cert: str) -> str | None:
        """Return xpath if the device mgmt SSL profile references old_cert, else None."""
        xpath = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/ssl-tls-service-profile"
        try:
            root = self.get_config(xpath)
            el = root.find(".//ssl-tls-service-profile")
            if el is not None and el.text == old_cert:
                return xpath
        except PanosError:
            pass
        return None

    # ------------------------------------------------------------------
    # Commit
    # ------------------------------------------------------------------

    def validate_commit(self, admin: str | None = None, timeout_s: int = 300) -> None:
        cmd = self._build_commit_cmd(validate=True, admin=admin)
        root = self._get({"type": "commit", "action": "validate", "cmd": cmd})
        self._check_status(root, "commit validate")
        job_id = self._extract_job_id(root)
        if job_id:
            self._poll_job(job_id, "validate", timeout_s=timeout_s)
        self._logger.info("Pre-commit validation passed.")

    def commit(self, admin: str | None = None, timeout_s: int = 300) -> str:
        cmd = self._build_commit_cmd(validate=False, admin=admin)
        root = self._post({"type": "commit", "cmd": cmd})
        self._check_status(root, "commit")
        job_id = self._extract_job_id(root)
        if not job_id:
            raise PanosError("Commit succeeded but returned no job ID.")
        self._logger.info("Commit job %s started.", job_id)
        return self._poll_job(job_id, "commit", timeout_s=timeout_s)

    def _build_commit_cmd(self, validate: bool, admin: str | None) -> str:
        if admin:
            inner = f"<partial><admin><member>{saxutils.escape(admin)}</member></admin></partial>"
        else:
            inner = ""
        if validate:
            return f"<commit><partial>{inner}</partial></commit>" if admin else "<commit/>"
        return f"<commit>{inner}</commit>"

    def _extract_job_id(self, root: ET.Element) -> str | None:
        el = root.find(".//job")
        return el.text if el is not None else None

    def _poll_job(self, job_id: str, operation: str, timeout_s: int) -> str:
        deadline = time.monotonic() + timeout_s
        while True:
            if time.monotonic() > deadline:
                raise PanosError(
                    f"{operation} job {job_id} did not finish within {timeout_s}s. "
                    "Check firewall job status manually."
                )
            time.sleep(5)
            root = self._get({
                "type": "op",
                "cmd": f"<show><jobs><id>{job_id}</id></jobs></show>",
            })
            status_el = root.find(".//status")
            result_el = root.find(".//result")
            status = status_el.text if status_el is not None else ""
            result = result_el.text if result_el is not None else ""
            if status == "FIN":
                if result == "OK":
                    self._logger.info("%s job %s completed successfully.", operation.capitalize(), job_id)
                    return job_id
                raise PanosError(f"{operation} job {job_id} finished with result '{result}'.")
            self._logger.debug("%s job %s status: %s", operation.capitalize(), job_id, status)


# ---------------------------------------------------------------------------
# Certificate / key validation
# ---------------------------------------------------------------------------

def validate_cert_and_key(
    cert_path: Path,
    key_path: Path | None,
    logger: logging.Logger,
    key_passphrase: bytes | None = None,
) -> None:
    if not CRYPTO_AVAILABLE:
        logger.warning("'cryptography' library not installed — skipping cert/key validation.")
        return

    # Load cert
    try:
        cert_pem = cert_path.read_bytes()
        # Handle chain PEM — take only the first certificate block
        certs = _split_pem_certs(cert_pem)
        if len(certs) > 1:
            logger.warning(
                "Cert file contains %d certificates (chain PEM). "
                "Only the first (leaf) cert will be imported; the rest are ignored by PAN-OS.",
                len(certs),
            )
        cert = x509.load_pem_x509_certificate(certs[0])
    except Exception as e:
        raise SystemExit(f"ERROR: Cannot parse cert file '{cert_path}': {e}")

    # Expiry check
    now = datetime.now(timezone.utc)
    if cert.not_valid_after_utc < now:
        raise SystemExit(
            f"ERROR: Certificate expired {cert.not_valid_after_utc.isoformat()}. "
            "Upload an expired cert would break TLS — aborting."
        )
    days_left = (cert.not_valid_after_utc - now).days
    if days_left < 30:
        logger.warning("Certificate expires in %d day(s) (%s).", days_left, cert.not_valid_after_utc.isoformat())
    else:
        logger.info("Certificate valid until %s (%d days).", cert.not_valid_after_utc.date(), days_left)

    if key_path is None:
        return

    # Key file permissions
    st = os.stat(key_path)
    if st.st_mode & (stat.S_IRGRP | stat.S_IROTH):
        raise SystemExit(
            f"ERROR: Key file '{key_path}' is readable by group or others "
            f"(mode {oct(stat.S_IMODE(st.st_mode))}). chmod 600 it first."
        )

    # Load key
    try:
        key_pem = key_path.read_bytes()
        private_key = load_pem_private_key(key_pem, password=key_passphrase)
    except TypeError:
        # cryptography raises TypeError when the wrong passphrase is given
        msg = (
            f"ERROR: Cannot parse key file '{key_path}': wrong passphrase."
            if key_passphrase is not None
            else f"ERROR: Cannot parse key file '{key_path}': key is encrypted — provide --key-passphrase."
        )
        raise SystemExit(msg)
    except Exception as e:
        raise SystemExit(f"ERROR: Cannot parse key file '{key_path}': {e}")

    # Verify cert ↔ key match by comparing public keys
    cert_pub = cert.public_key()
    key_pub = private_key.public_key()

    def _pub_bytes(k):
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        return k.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    if _pub_bytes(cert_pub) != _pub_bytes(key_pub):
        raise SystemExit("ERROR: Certificate and private key do not match. Aborting.")

    logger.info("Certificate and private key validated — they match.")


def _split_pem_certs(pem_bytes: bytes) -> list[bytes]:
    """Split a PEM blob into individual CERTIFICATE blocks."""
    import re
    pattern = re.compile(
        b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        re.DOTALL,
    )
    blocks = pattern.findall(pem_bytes)
    if not blocks:
        raise ValueError("No PEM CERTIFICATE blocks found.")
    return blocks


# ---------------------------------------------------------------------------
# Discovery helpers
# ---------------------------------------------------------------------------

def collect_all_refs(client: PanosClient, old_name: str, logger: logging.Logger) -> dict:
    """Return a structured dict of all places old_name is referenced."""
    refs = {
        "ssl_tls_profiles": [],   # list of {scope, vsys, name, set_xpath}
        "cert_profiles": [],       # list of {scope, vsys, name, ca_names, entry_xpath}
        "gp": [],                  # list of {vsys, label, set_xpath}
        "gp_cookie": [],           # list of {vsys, label, set_xpath} — cookie-encrypt-decrypt-cert
        "ssl_decrypt": [],         # list of {vsys, label, set_xpath}
        "shared_ssl_decrypt": [],  # list of {label, set_xpath, element_tag} — shared forward-trust
        "device_mgmt": None,       # set_xpath or None
    }

    multi_vsys = client.is_multi_vsys()
    if multi_vsys:
        vsys_list = client.list_vsys()
        logger.info("Multi-vsys mode — scanning vsys: %s", vsys_list)
    else:
        vsys_list = ["vsys1"]
        logger.info("Single vsys mode — scanning vsys1 directly")

    dev_base = "/config/devices/entry[@name='localhost.localdomain']"

    for vsys in vsys_list:
        vsys_base = f"{dev_base}/vsys/entry[@name='{saxutils.escape(vsys)}']"

        # SSL/TLS service profiles in vsys
        xpath = f"{vsys_base}/ssl-tls-service-profile"
        names = client.find_ssl_profile_refs(xpath, old_name)
        for n in names:
            safe_n = saxutils.escape(n)
            refs["ssl_tls_profiles"].append({
                "scope": f"vsys/{vsys}",
                "vsys": vsys,
                "name": n,
                "set_xpath": f"{vsys_base}/ssl-tls-service-profile/entry[@name='{safe_n}']",
            })

        # Certificate profiles (CA lists for mTLS)
        cp_xpath = f"{vsys_base}/certificate-profile"
        for r in client.find_cert_profile_refs(cp_xpath, old_name):
            safe_n = saxutils.escape(r["name"])
            refs["cert_profiles"].append({
                "scope": f"vsys/{vsys}",
                "vsys": vsys,
                "name": r["name"],
                "ca_names": r["ca_names"],
                "entry_xpath": f"{cp_xpath}/entry[@name='{safe_n}']",
            })

        # GlobalProtect
        for label, set_xpath in client.find_gp_refs(vsys, old_name):
            refs["gp"].append({"vsys": vsys, "label": label, "set_xpath": set_xpath})

        # SSL decryption
        for label, set_xpath in client.find_decrypt_refs(vsys, old_name):
            refs["ssl_decrypt"].append({"vsys": vsys, "label": label, "set_xpath": set_xpath})

        # GP cookie-encrypt-decrypt-cert
        for r in client.find_gp_cookie_refs(vsys, old_name):
            refs["gp_cookie"].append(r)

    # Shared SSL/TLS profiles
    shared_xpath = "/config/shared/ssl-tls-service-profile"
    names = client.find_ssl_profile_refs(shared_xpath, old_name)
    for n in names:
        safe_n = saxutils.escape(n)
        refs["ssl_tls_profiles"].append({
            "scope": "shared",
            "vsys": None,
            "name": n,
            "set_xpath": f"{shared_xpath}/entry[@name='{safe_n}']",
        })

    # Shared certificate profiles
    for r in client.find_cert_profile_refs("/config/shared/certificate-profile", old_name):
        refs["cert_profiles"].append({"scope": "shared", "vsys": None, **r})

    # Shared SSL decrypt forward-trust certificates
    for r in client.find_shared_decrypt_refs(old_name):
        refs["shared_ssl_decrypt"].append(r)

    # Device management cert
    mgmt_xpath = client.find_device_mgmt_ref(old_name)
    if mgmt_xpath:
        refs["device_mgmt"] = mgmt_xpath

    return refs


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_cert_element(new_name: str) -> str:
    """Build the XML element for the set call — safely escaped."""
    el = ET.Element("certificate")
    el.text = new_name
    return ET.tostring(el, encoding="unicode")


def parse_args():
    p = argparse.ArgumentParser(description="Upload cert to PAN-OS and remap SSL/TLS profiles.")
    p.add_argument("--old-name", required=True, help="Cert name currently referenced in profiles (remap FROM).")
    p.add_argument("--new-name", required=True, help="Cert object name to import AS (remap TO).")
    p.add_argument("--cert", required=True, type=Path, help="Path to PEM cert file.")
    p.add_argument("--key", type=Path, default=None, help="Path to PEM private key (leaf certs only).")
    p.add_argument("--key-passphrase", default=None,
                   help="Passphrase for keypair import. PAN-OS 11.x requires a non-empty value even for "
                        "unencrypted keys. If omitted, a random passphrase is generated automatically.")
    p.add_argument("--dry-run", action="store_true", help="Discover and report; do not modify firewall.")
    p.add_argument("--no-commit", action="store_true",
                   help="Import cert and remap profiles but leave changes staged in candidate config for manual review. "
                        "Overrides PANOS_AUTO_COMMIT env var.")
    p.add_argument("--force-overwrite", action="store_true",
                   help="Overwrite existing cert named --new-name if it already exists on the firewall.")
    p.add_argument("--remove-old-cert", action="store_true",
                   help="After a successful commit, delete the old cert (--old-name) from the device cert store. "
                        "No-op in --no-commit / staged mode.")
    p.add_argument("--commit-admin", default=None,
                   help="Admin username to scope the commit to (recommended: use a service account).")
    p.add_argument("--commit-timeout", type=int, default=300, help="Max seconds to wait for commit job (default 300).")
    return p.parse_args()


def load_env():
    load_dotenv()
    host = os.environ.get("PANOS_HOST", "").strip()
    api_key = os.environ.get("PANOS_API_KEY", "").strip()
    verify_raw = os.environ.get("PANOS_VERIFY_SSL", "false").strip().lower()
    auto_commit_raw = os.environ.get("PANOS_AUTO_COMMIT", "true").strip().lower()
    if not host:
        raise SystemExit("ERROR: PANOS_HOST is not set.")
    if not api_key:
        raise SystemExit("ERROR: PANOS_API_KEY is not set.")
    if verify_raw in ("false", "0", "no"):
        verify_ssl = False
    elif verify_raw in ("true", "1", "yes"):
        verify_ssl = True
    else:
        verify_ssl = verify_raw  # treat as a path to a CA bundle
    auto_commit = auto_commit_raw not in ("false", "0", "no")
    return host, api_key, verify_ssl, auto_commit


def main():
    args = parse_args()
    logger, log_file = _setup_logging(args.dry_run)

    if log_file:
        logger.info("Audit log: %s", log_file)

    # --no-commit flag overrides PANOS_AUTO_COMMIT env var
    host, api_key, verify_ssl, auto_commit = load_env()
    if args.no_commit:
        auto_commit = False

    mode = "DRY RUN" if args.dry_run else ("STAGED" if not auto_commit else "LIVE")
    logger.info("Mode: %s", mode)
    logger.info("old-name=%s  new-name=%s  cert=%s  key=%s",
                args.old_name, args.new_name, args.cert, args.key or "(none)")

    # --- Pre-flight: cert/key validation ---
    if not args.cert.exists():
        raise SystemExit(f"ERROR: Cert file not found: {args.cert}")
    if args.key and not args.key.exists():
        raise SystemExit(f"ERROR: Key file not found: {args.key}")

    passphrase_bytes = args.key_passphrase.encode() if args.key_passphrase else None
    validate_cert_and_key(args.cert, args.key, logger, key_passphrase=passphrase_bytes)

    client = PanosClient(host, api_key, verify_ssl, logger)

    try:
        # --- Check if new-name already exists ---
        dev_base = "/config/devices/entry[@name='localhost.localdomain']"
        vsys_base = f"{dev_base}/vsys/entry[@name='vsys1']"
        if not args.dry_run:
            exists = client.cert_exists(vsys_base, args.new_name)
            if exists and not args.force_overwrite:
                raise SystemExit(
                    f"ERROR: A certificate named '{args.new_name}' already exists on the firewall. "
                    "Pass --force-overwrite to replace it."
                )
            if exists:
                logger.warning("Overwriting existing certificate '%s' (--force-overwrite set).", args.new_name)

        # --- Discover all references ---
        logger.info("Discovering references to '%s'...", args.old_name)
        refs = collect_all_refs(client, args.old_name, logger)

        total_refs = (
            len(refs["ssl_tls_profiles"]) +
            len(refs["cert_profiles"]) +
            len(refs["gp"]) +
            len(refs["gp_cookie"]) +
            len(refs["ssl_decrypt"]) +
            len(refs["shared_ssl_decrypt"]) +
            (1 if refs["device_mgmt"] else 0)
        )

        logger.info("--- Discovery results ---")
        for r in refs["ssl_tls_profiles"]:
            logger.info("  SSL/TLS profile [%s] '%s'", r["scope"], r["name"])
        for r in refs["cert_profiles"]:
            logger.info("  Certificate profile [%s] '%s' (CA list: %s)", r["scope"], r["name"], r["ca_names"])
        for r in refs["gp"]:
            logger.info("  GlobalProtect [vsys/%s] %s", r["vsys"], r["label"])
        for r in refs["gp_cookie"]:
            logger.info("  GP cookie cert [vsys/%s] %s", r["vsys"], r["label"])
        for r in refs["ssl_decrypt"]:
            logger.info("  SSL Decrypt [vsys/%s] %s", r["vsys"], r["label"])
        for r in refs["shared_ssl_decrypt"]:
            logger.info("  Shared SSL decrypt %s", r["label"])
        if refs["device_mgmt"]:
            logger.info("  Device management SSL profile")
        if total_refs == 0:
            logger.warning("No references to '%s' found. Nothing will be remapped.", args.old_name)

        if args.dry_run:
            logger.info("DRY RUN complete. %d reference(s) would be remapped.", total_refs)
            return

        # --- Acquire config lock (best-effort) ---
        config_lock_held = False
        try:
            client.acquire_config_lock()
            config_lock_held = True
        except PanosError as e:
            logger.warning("Config lock unavailable: %s — proceeding without lock.", e)
        snapshot_name = f"pre-cert-rotate-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        changes_made = False

        try:
            # --- Pre-change snapshot ---
            client.save_config_snapshot(snapshot_name)
            logger.info("Pre-change snapshot saved: '%s'", snapshot_name)

            # --- Import cert (and key if provided) ---
            cert_bytes = args.cert.read_bytes()
            if args.key:
                import secrets as _secrets
                passphrase = args.key_passphrase if args.key_passphrase is not None else _secrets.token_hex(15)
                if args.key_passphrase is None:
                    logger.info("No --key-passphrase provided; using auto-generated passphrase for keypair import.")
                key_bytes = args.key.read_bytes()
                client.import_keypair(args.new_name, cert_bytes, key_bytes, passphrase=passphrase.encode())
            else:
                client.import_certificate(args.new_name, cert_bytes)
            changes_made = True

            # --- Remap ---
            cert_element = build_cert_element(args.new_name)
            remapped = []

            for r in refs["ssl_tls_profiles"]:
                client.set_config(r["set_xpath"], cert_element)
                remapped.append(r["set_xpath"])
                logger.info("Remapped SSL/TLS profile [%s] '%s'.", r["scope"], r["name"])

            # Certificate profiles use a multi-entry CA list — must use edit_config (action=edit)
            # so the entire <CA> block is replaced, not merged additively like action=set would do.
            for r in refs["cert_profiles"]:
                new_ca_names = [args.new_name if n == args.old_name else n for n in r["ca_names"]]
                ca_el = ET.Element("CA")
                for n in new_ca_names:
                    e = ET.SubElement(ca_el, "entry")
                    e.set("name", n)
                ca_xpath = r["entry_xpath"] + "/CA"
                client.edit_config(ca_xpath, ET.tostring(ca_el, encoding="unicode"))
                remapped.append(r["entry_xpath"])
                logger.info("Remapped certificate profile [%s] '%s'.", r["scope"], r["name"])

            for r in refs["gp"]:
                client.set_config(r["set_xpath"], cert_element)
                remapped.append(r["set_xpath"])
                logger.info("Remapped GlobalProtect %s.", r["label"])

            for r in refs["gp_cookie"]:
                cookie_el = ET.Element("cookie-encrypt-decrypt-cert")
                cookie_el.text = args.new_name
                client.set_config(r["set_xpath"], ET.tostring(cookie_el, encoding="unicode"))
                remapped.append(r["set_xpath"])
                logger.info("Remapped GP cookie cert %s.", r["label"])

            for r in refs["ssl_decrypt"]:
                client.set_config(r["set_xpath"], cert_element)
                remapped.append(r["set_xpath"])
                logger.info("Remapped SSL decrypt field %s.", r["label"])

            for r in refs["shared_ssl_decrypt"]:
                tag_el = ET.Element(r["element_tag"])
                tag_el.text = args.new_name
                client.set_config(r["set_xpath"], ET.tostring(tag_el, encoding="unicode"))
                remapped.append(r["set_xpath"])
                logger.info("Remapped shared SSL decrypt %s.", r["label"])

            if refs["device_mgmt"]:
                client.set_config(refs["device_mgmt"], cert_element)
                remapped.append(refs["device_mgmt"])
                logger.info("Remapped device management SSL profile.")

            if not auto_commit:
                # --- Staged mode: stage everything for a single manual review + commit ---
                if args.remove_old_cert:
                    logger.info("Staging deletion of old certificate '%s'...", args.old_name)
                    found = client.delete_certificate(args.old_name)
                    if not found:
                        logger.warning(
                            "Old certificate '%s' not found in vsys1 or shared — may have already been removed.",
                            args.old_name,
                        )

                logger.info("--- Staged (PANOS_AUTO_COMMIT=false / --no-commit) ---")
                logger.info("Certificate imported: '%s' (with key: %s)", args.new_name, "yes" if args.key else "no")
                logger.info("Profiles remapped: %d", len(remapped))
                logger.info("Pre-change snapshot on device: '%s'", snapshot_name)
                logger.info(
                    "All changes are staged in candidate config. Review in PAN-OS GUI "
                    "(Monitor > Commit > Preview) then commit manually."
                )
                if log_file:
                    logger.info("Full audit log: %s", log_file)
            else:
                # --- Auto-commit mode ---
                logger.info("Running pre-commit validation...")
                client.validate_commit(admin=args.commit_admin, timeout_s=args.commit_timeout)

                logger.info("Committing...")
                job_id = client.commit(admin=args.commit_admin, timeout_s=args.commit_timeout)

                logger.info("--- Summary ---")
                logger.info("Certificate imported: '%s' (with key: %s)", args.new_name, "yes" if args.key else "no")
                logger.info("Profiles remapped: %d", len(remapped))
                logger.info("Commit job ID: %s", job_id)
                logger.info("Pre-change snapshot on device: '%s'", snapshot_name)
                if log_file:
                    logger.info("Full audit log: %s", log_file)

                if args.remove_old_cert:
                    logger.info("Removing old certificate '%s' from device...", args.old_name)
                    found = client.delete_certificate(args.old_name)
                    if not found:
                        logger.warning(
                            "Old certificate '%s' not found in vsys1 or shared — may have already been removed.",
                            args.old_name,
                        )
                    else:
                        logger.info("Committing certificate deletion...")
                        cleanup_job_id = client.commit(admin=args.commit_admin, timeout_s=args.commit_timeout)
                        logger.info("Certificate deletion commit job ID: %s", cleanup_job_id)

        except (PanosError, Exception) as e:
            logger.error("ERROR during live run: %s", e)
            if changes_made:
                logger.warning("Reverting candidate config to pre-change state...")
                client.revert_candidate()
            if config_lock_held:
                client.release_config_lock()
            raise SystemExit(1) from e

        client.release_config_lock()

    except PanosAuthError as e:
        logger.error("%s", e)
        raise SystemExit(1) from e
    finally:
        client.close()


if __name__ == "__main__":
    main()
