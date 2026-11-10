"""Server-side access to completed DocuSign envelopes."""

import time
from urllib.parse import urlsplit
from uuid import UUID

import requests


class ContractError(Exception):
    """An actionable error that is safe to show to dashboard users."""


class AuthenticationExpired(ContractError):
    """The cached access token must be replaced."""


def envelope_id(value) -> str:
    try:
        return str(UUID(str(value).strip()))
    except (ValueError, TypeError, AttributeError):
        raise ContractError("This employee does not have a valid DocuSign envelope ID.") from None


def check_response(response):
    if response.status_code == 401:
        raise AuthenticationExpired("DocuSign authentication expired. Please try again.")
    if response.status_code == 403:
        raise ContractError("The connected DocuSign account cannot access this contract.")
    if response.status_code == 404:
        raise ContractError("This envelope was not found in the connected DocuSign account.")
    if response.status_code == 429:
        raise ContractError("DocuSign is busy. Please wait a moment and try again.")
    if response.status_code != 200:
        raise ContractError("DocuSign could not retrieve the contract. Please try again later.")


def connect(settings):
    """Authenticate with JWT grant and discover this account's API base URI."""
    required = ("DOCUSIGN_INTEGRATION_KEY", "DOCUSIGN_USER_ID",
                "DOCUSIGN_ACCOUNT_ID", "DOCUSIGN_PRIVATE_KEY")
    if any(not settings.get(key) for key in required):
        raise ContractError("DocuSign is not connected yet. Ask the dashboard administrator to configure it.")
    auth_host = settings.get("DOCUSIGN_AUTH_SERVER", "account.docusign.com")
    if auth_host not in ("account.docusign.com", "account-d.docusign.com"):
        raise ContractError("The DocuSign authentication server setting is invalid.")

    import jwt

    now = int(time.time())
    try:
        assertion = jwt.encode(
            {"iss": settings["DOCUSIGN_INTEGRATION_KEY"],
             "sub": settings["DOCUSIGN_USER_ID"], "aud": auth_host,
             "iat": now, "exp": now + 3600, "scope": "signature impersonation"},
            settings["DOCUSIGN_PRIVATE_KEY"], algorithm="RS256",
        )
    except (ValueError, TypeError, jwt.PyJWTError):
        raise ContractError("The DocuSign private key setting is invalid.") from None
    response = requests.post(
        f"https://{auth_host}/oauth/token",
        data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion},
        timeout=20,
    )
    if response.status_code != 200:
        try:
            consent_required = response.json().get("error") == "consent_required"
        except ValueError:
            consent_required = False
        if consent_required:
            raise ContractError("DocuSign requires administrator setup: grant signature and impersonation consent to the integration.")
        raise ContractError("Could not authenticate with DocuSign. Ask the dashboard administrator to check the connection settings.")
    token = response.json()["access_token"]
    response = requests.get(f"https://{auth_host}/oauth/userinfo",
                            headers={"Authorization": f"Bearer {token}"}, timeout=20)
    check_response(response)
    account = next((a for a in response.json().get("accounts", [])
                    if a.get("account_id") == str(settings["DOCUSIGN_ACCOUNT_ID"])), None)
    if account is None:
        raise ContractError("The configured DocuSign account is not accessible to the connected user.")
    base_uri = account.get("base_uri", "").rstrip("/")
    parsed = urlsplit(base_uri)
    if (parsed.scheme != "https" or not (parsed.hostname or "").endswith(".docusign.net")
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path or parsed.netloc != parsed.hostname):
        raise ContractError("DocuSign returned an unexpected account API address.")
    return token, base_uri, account["account_id"]


def fetch_signed_contract(connection, value) -> bytes:
    """Return a combined PDF only after DocuSign reports the envelope completed."""
    identifier = envelope_id(value)
    token, base_uri, account_id = connection
    account_id = envelope_id(account_id)
    url = f"{base_uri}/restapi/v2.1/accounts/{account_id}/envelopes/{identifier}"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, timeout=20)
    check_response(response)
    if response.json().get("status") != "completed":
        raise ContractError("This contract is not completed in DocuSign yet. All recipients must finish signing before it can be viewed here.")
    response = requests.get(f"{url}/documents/combined",
                            headers={**headers, "Accept": "application/pdf"}, timeout=60)
    check_response(response)
    if not response.content.startswith(b"%PDF-"):
        raise ContractError("DocuSign did not return a valid PDF. Please try again later.")
    return response.content
