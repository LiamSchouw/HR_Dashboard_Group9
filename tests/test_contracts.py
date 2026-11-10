import unittest
from unittest.mock import Mock, patch

from contracts import AuthenticationExpired, ContractError, connect, fetch_signed_contract


ACCOUNT = "11111111-1111-1111-1111-111111111111"
ENVELOPE = "22222222-2222-2222-2222-222222222222"
CONNECTION = ("private-access-token", "https://demo.docusign.net", ACCOUNT)
SETTINGS = {
    "DOCUSIGN_INTEGRATION_KEY": "integration-id",
    "DOCUSIGN_USER_ID": "user-id",
    "DOCUSIGN_ACCOUNT_ID": ACCOUNT,
    "DOCUSIGN_PRIVATE_KEY": "private-key",
    "DOCUSIGN_AUTH_SERVER": "account-d.docusign.com",
}


def response(status=200, body=None, content=b""):
    return Mock(status_code=status, json=Mock(return_value=body), content=content)


class ContractTests(unittest.TestCase):
    @patch("contracts.requests.get")
    def test_completed_envelope_returns_combined_pdf(self, get):
        pdf = b"%PDF-1.7\ncompleted contract"
        get.side_effect = [response(body={"status": "completed"}), response(content=pdf)]
        self.assertEqual(fetch_signed_contract(CONNECTION, ENVELOPE), pdf)
        self.assertTrue(get.call_args_list[0].args[0].endswith(f"/envelopes/{ENVELOPE}"))
        self.assertTrue(get.call_args_list[1].args[0].endswith("/documents/combined"))
        self.assertEqual(get.call_args.kwargs["headers"]["Authorization"],
                         "Bearer private-access-token")

    @patch("contracts.requests.get")
    def test_incomplete_envelopes_never_download_documents(self, get):
        for status in ("sent", "delivered", "signed", "declined", "voided"):
            with self.subTest(status=status):
                get.reset_mock()
                get.return_value = response(body={"status": status})
                with self.assertRaisesRegex(ContractError, "not completed"):
                    fetch_signed_contract(CONNECTION, ENVELOPE)
                get.assert_called_once()

    @patch("contracts.requests.get")
    def test_missing_and_malformed_envelope_ids_make_no_requests(self, get):
        for value in (None, "", "../other-envelope", "not-an-envelope"):
            with self.subTest(value=value), self.assertRaisesRegex(ContractError, "valid DocuSign envelope"):
                fetch_signed_contract(CONNECTION, value)
        get.assert_not_called()

    @patch("contracts.requests.get")
    def test_authentication_expiry_is_distinguishable_for_retry(self, get):
        get.return_value = response(status=401)
        with self.assertRaises(AuthenticationExpired):
            fetch_signed_contract(CONNECTION, ENVELOPE)

    @patch("contracts.requests.get")
    def test_api_failures_show_safe_messages(self, get):
        for status, message in ((403, "cannot access"), (404, "not found"),
                                (429, "busy"), (500, "try again later")):
            with self.subTest(status=status):
                get.return_value = response(status=status)
                with self.assertRaisesRegex(ContractError, message):
                    fetch_signed_contract(CONNECTION, ENVELOPE)

    @patch("contracts.requests.get")
    def test_non_pdf_response_is_rejected(self, get):
        get.side_effect = [response(body={"status": "completed"}), response(content=b"<html>error</html>")]
        with self.assertRaisesRegex(ContractError, "valid PDF"):
            fetch_signed_contract(CONNECTION, ENVELOPE)

    def test_missing_configuration_is_actionable(self):
        with self.assertRaisesRegex(ContractError, "not connected yet"):
            connect({})

    @patch("contracts.requests.post")
    @patch("contracts.requests.get")
    @patch("jwt.encode", return_value="signed-jwt")
    def test_jwt_authentication_discovers_account_api_address(self, encode, get, post):
        post.return_value = response(body={"access_token": "token"})
        get.return_value = response(body={"accounts": [
            {"account_id": ACCOUNT, "base_uri": "https://demo.docusign.net"}]})
        self.assertEqual(connect(SETTINGS), ("token", "https://demo.docusign.net", ACCOUNT))
        self.assertEqual(encode.call_args.args[0]["scope"], "signature impersonation")
        self.assertEqual(encode.call_args.args[0]["aud"], "account-d.docusign.com")
        self.assertEqual(post.call_args.args[0], "https://account-d.docusign.com/oauth/token")

    @patch("contracts.requests.post")
    @patch("jwt.encode", return_value="signed-jwt")
    def test_missing_consent_explains_setup_requirement(self, encode, post):
        post.return_value = response(status=400, body={"error": "consent_required"})
        with self.assertRaisesRegex(ContractError, "consent"):
            connect(SETTINGS)

    @patch("contracts.requests.post")
    @patch("contracts.requests.get")
    @patch("jwt.encode", return_value="signed-jwt")
    def test_unexpected_api_host_is_rejected(self, encode, get, post):
        post.return_value = response(body={"access_token": "token"})
        get.return_value = response(body={"accounts": [
            {"account_id": ACCOUNT, "base_uri": "https://docusign.net.attacker.example"}]})
        with self.assertRaisesRegex(ContractError, "unexpected account API"):
            connect(SETTINGS)


if __name__ == "__main__":
    unittest.main()
