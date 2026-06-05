"""
Tests that PanosAuthError raised inside the live-run inner try block bubbles
up to the outer handler and produces the 'Regenerate PANOS_API_KEY' message
rather than a generic 'ERROR during live run' message.
"""
import logging
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))
import upload_cert
from upload_cert import PanosAuthError


_AUTH_ERR_MSG = (
    "import_certificate failed — API key rejected (code 403). "
    "Regenerate PANOS_API_KEY (keys expire when admin password changes)."
)

_EMPTY_REFS = {
    "ssl_tls_profiles": [],
    "cert_profiles": [],
    "gp_cookie": [],
    "ssl_decrypt": [],
    "shared_ssl_decrypt": [],
    "device_mgmt": None,
    "vsys_list": [],
}


def _make_client_mock(auth_err):
    """Return a PanosClient mock whose import_certificate raises auth_err."""
    m = MagicMock()
    m.cert_exists.return_value = False
    m.acquire_config_lock.return_value = None
    m.save_config_snapshot.return_value = None
    m.import_certificate.side_effect = auth_err
    m.release_config_lock.return_value = None
    m.close.return_value = None
    return m


def test_auth_error_in_live_run_shows_regenerate_message(tmp_path, caplog):
    cert_file = tmp_path / "test.pem"
    cert_file.write_bytes(b"fake cert data")

    auth_err = PanosAuthError(_AUTH_ERR_MSG)
    mock_client = _make_client_mock(auth_err)

    with (
        patch.object(sys, "argv", [
            "upload_cert.py",
            "--old-name", "old-cert",
            "--new-name", "new-cert",
            "--cert", str(cert_file),
            "--no-commit",
        ]),
        patch.dict("os.environ", {"PANOS_HOST": "192.0.2.1", "PANOS_API_KEY": "fake-key"}, clear=False),
        patch("upload_cert.validate_cert_and_key", return_value=None),
        patch("upload_cert.collect_all_refs", return_value=_EMPTY_REFS),
        patch("upload_cert.PanosClient", return_value=mock_client),
        caplog.at_level(logging.ERROR, logger="panos-cert-rotate"),
    ):
        with pytest.raises(SystemExit) as exc_info:
            upload_cert.main()

    assert exc_info.value.code == 1
    assert "Regenerate PANOS_API_KEY" in caplog.text
    assert "ERROR during live run" not in caplog.text


def test_auth_error_in_live_run_does_not_revert(tmp_path, caplog):
    """No revert should be attempted when auth fails before any changes land."""
    cert_file = tmp_path / "test.pem"
    cert_file.write_bytes(b"fake cert data")

    auth_err = PanosAuthError(_AUTH_ERR_MSG)
    mock_client = _make_client_mock(auth_err)

    with (
        patch.object(sys, "argv", [
            "upload_cert.py",
            "--old-name", "old-cert",
            "--new-name", "new-cert",
            "--cert", str(cert_file),
            "--no-commit",
        ]),
        patch.dict("os.environ", {"PANOS_HOST": "192.0.2.1", "PANOS_API_KEY": "fake-key"}, clear=False),
        patch("upload_cert.validate_cert_and_key", return_value=None),
        patch("upload_cert.collect_all_refs", return_value=_EMPTY_REFS),
        patch("upload_cert.PanosClient", return_value=mock_client),
        caplog.at_level(logging.WARNING, logger="panos-cert-rotate"),
    ):
        with pytest.raises(SystemExit):
            upload_cert.main()

    mock_client.revert_candidate.assert_not_called()
    mock_client.release_config_lock.assert_called_once()
