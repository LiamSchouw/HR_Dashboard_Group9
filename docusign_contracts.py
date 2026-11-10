"""Read-only DocuSign access for the HR dashboard (JWT grant).

Lets an authorised HR user look up an employee's envelope and download the
combined signed PDF. Nothing is stored: the PDF is fetched only when asked for.
"""

import logging
import re
import time
from datetime import date, timedelta

import jwt
import requests

logger = logging.getLogger("hr_dashboard.docusign")

SCOPES = "signature impersonation"
TIMEOUT = 20
MAX_PDF_BYTES = 20 * 1024 * 1024
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

_cache = {"token": None, "expires": 0.0, "api": None}


class DocuSignError(Exception):
    """A DocuSign problem with a message that is safe to show on screen."""

    def __init__(self, message: str, status=None):
        super().__init__(message)
        self.message = message
        self.status = status

    def __str__(self) -> str:
        return self.message


def config_from_secrets(secret) -> dict | None:
    """Build the settings dict from Streamlit secrets, or None if anything is missing."""
    cfg = {
        "integration_key": secret("DOCUSIGN_INTEGRATION_KEY"),
        "user_id": secret("DOCUSIGN_USER_ID"),
        "account_id": secret("DOCUSIGN_ACCOUNT_ID"),
        "auth_server": secret("DOCUSIGN_AUTH_SERVER", "account-d.docusign.com"),
        "private_key": secret("DOCUSIGN_PRIVATE_KEY"),
    }
    return cfg if all(cfg.values()) else None


def normalize_key(pem: str) -> str:
    """Tolerate keys pasted with quotes, indentation or literal \\n sequences."""
    text = str(pem).strip().strip('"').strip("'").replace("\\n", "\n")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return "\n".join(lines) + "\n"


def build_assertion(cfg: dict, now: int | None = None) -> str:
    now = int(now or time.time())
    claims = {
        "iss": cfg["integration_key"],
        "sub": cfg["user_id"],
        "aud": cfg["auth_server"],
        "iat": now,
        "exp": now + 3600,
        "scope": SCOPES,
    }
    return jwt.encode(claims, normalize_key(cfg["private_key"]), algorithm="RS256")


def consent_url(cfg: dict, redirect_uri: str) -> str:
    """One-time link the DocuSign account owner opens to grant the app consent."""
    return (f"https://{cfg['auth_server']}/oauth/auth?response_type=code"
            f"&scope=signature%20impersonation&client_id={cfg['integration_key']}"
            f"&redirect_uri={redirect_uri}")


def _call(method: str, url: str, **kwargs):
    try:
        r = requests.request(method, url, timeout=TIMEOUT, **kwargs)
    except requests.exceptions.Timeout:
        raise DocuSignError("DocuSign took too long to respond. Please try again.") from None
    except requests.exceptions.ConnectionError:
        raise DocuSignError("Could not reach DocuSign. Check the internet connection "
                            "and try again.") from None
    except requests.exceptions.RequestException:
        logger.exception("DocuSign request failed")
        raise DocuSignError("The request to DocuSign failed. Please try again.") from None
    return r


def get_api_base(cfg: dict) -> tuple[str, str]:
    """Return (access_token, account API base URL), cached until shortly before expiry."""
    if _cache["token"] and time.time() < _cache["expires"] - 120:
        return _cache["token"], _cache["api"]

    r = _call("POST", f"https://{cfg['auth_server']}/oauth/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": build_assertion(cfg),
    })
    if r.status_code != 200:
        body = r.text[:200]
        logger.warning("DocuSign token error %s: %s", r.status_code, body)
        if "consent_required" in body:
            raise DocuSignError("DocuSign has not been given permission yet. The account "
                                "owner must grant consent once, then try again.", r.status_code)
        if "invalid_grant" in body:
            raise DocuSignError("DocuSign rejected the sign-in (invalid_grant). The key, "
                                "user ID or consent needs checking.", r.status_code)
        raise DocuSignError(f"DocuSign sign-in failed ({r.status_code}).", r.status_code)
    token = r.json().get("access_token")
    if not token:
        raise DocuSignError("DocuSign did not return an access token.")

    u = _call("GET", f"https://{cfg['auth_server']}/oauth/userinfo",
              headers={"Authorization": f"Bearer {token}"})
    if u.status_code != 200:
        raise DocuSignError(f"Could not read the DocuSign account details ({u.status_code}).",
                            u.status_code)
    accounts = u.json().get("accounts", [])
    match = next((a for a in accounts if a.get("account_id") == cfg["account_id"]), None)
    if not match:
        raise DocuSignError("The DocuSign account ID does not match this user.")
    api = f"{match['base_uri']}/restapi/v2.1/accounts/{cfg['account_id']}"
    _cache.update(token=token, expires=time.time() + 3300, api=api)
    return token, api


def _authed(cfg: dict, method: str, path: str, **kwargs):
    """Call the DocuSign API, refreshing the token once if it has expired."""
    for attempt in (1, 2):
        token, api = get_api_base(cfg)
        r = _call(method, f"{api}{path}", headers={"Authorization": f"Bearer {token}",
                                                  **kwargs.pop("headers", {})}, **kwargs)
        if r.status_code == 401 and attempt == 1:
            _cache.update(token=None, expires=0.0)
            continue
        break
    if r.status_code >= 400:
        logger.warning("DocuSign error %s on %s: %s", r.status_code, path, r.text[:200])
        messages = {
            403: "DocuSign refused access to this document.",
            404: "That contract was not found in DocuSign.",
            429: "DocuSign is rate limiting requests. Please wait a moment and try again.",
        }
        message = messages.get(r.status_code) or (
            "DocuSign is having problems. Please try again shortly." if r.status_code >= 500
            else f"DocuSign returned an error ({r.status_code}).")
        raise DocuSignError(message, r.status_code)
    return r


def find_envelope(cfg: dict, email: str) -> str:
    """Most recent envelope that mentions this email address."""
    r = _authed(cfg, "GET", "/envelopes", params={
        "from_date": (date.today() - timedelta(days=365)).isoformat(),
        "search_text": email,
        "order_by": "last_modified",
        "order": "desc",
        "count": "5",
    })
    envelopes = r.json().get("envelopes") or []
    if not envelopes:
        raise DocuSignError("No contract was found in DocuSign for this employee.")
    return envelopes[0]["envelopeId"]


def fetch_contract(cfg: dict, envelope_id: str | None = None, email: str | None = None) -> dict:
    """Return {"envelope_id", "status", "pdf"} for one employee."""
    if envelope_id:
        envelope_id = str(envelope_id).strip()
        if not UUID_RE.match(envelope_id):
            raise DocuSignError("The stored envelope ID is not valid.")
    elif email:
        envelope_id = find_envelope(cfg, email)
    else:
        raise DocuSignError("This employee has no envelope ID or email to search with.")

    info = _authed(cfg, "GET", f"/envelopes/{envelope_id}").json()
    status = str(info.get("status", "unknown"))
    doc = _authed(cfg, "GET", f"/envelopes/{envelope_id}/documents/combined",
                  headers={"Accept": "application/pdf"})
    if len(doc.content) > MAX_PDF_BYTES:
        raise DocuSignError("The contract file is too large to load here.")
    if not doc.content.startswith(b"%PDF"):
        raise DocuSignError("DocuSign did not return a PDF for this contract.")
    return {"envelope_id": envelope_id, "status": status, "pdf": doc.content}
