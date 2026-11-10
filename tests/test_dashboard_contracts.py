import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import streamlit as st
from streamlit.testing.v1 import AppTest

from contracts import ContractError


EMPLOYEE = {
    "id_no": "1234567890123", "first_name": "Test", "last_name": "Hire",
    "email_address": "hire@example.com", "department": "Engineering",
    "start_date": "2026-11-10", "progress": "Signed",
    "envelope_id": "22222222-2222-2222-2222-222222222222",
}
CONNECTION = ("token", "https://demo.docusign.net", "11111111-1111-1111-1111-111111111111")


class DashboardContractTests(unittest.TestCase):
    def setUp(self):
        st.cache_data.clear()
        self.employee = dict(EMPLOYEE)
        self.completed = True
        self.pdf_requests = 0
        self.expire_once = False
        self.get_patch = patch("requests.get", side_effect=self.get_response)
        self.get_patch.start()
        self.connect_patch = patch("contracts.connect", return_value=CONNECTION)
        self.connection = self.connect_patch.start()
        self.addCleanup(self.get_patch.stop)
        self.addCleanup(self.connect_patch.stop)
        self.app = AppTest.from_file(str(Path(__file__).resolve().parents[1] / "app.py"))
        self.app.secrets = {"SUPABASE_URL": "https://database.example", "SUPABASE_KEY": "test-key"}
        self.app.session_state["user"] = "HR tester"

    def get_response(self, url, **kwargs):
        if url.endswith("/employees"):
            return Mock(status_code=200, json=Mock(return_value=[self.employee]))
        if url.endswith("/documents/combined"):
            self.pdf_requests += 1
            return Mock(status_code=200, content=b"%PDF-1.7\n%%EOF")
        if self.expire_once:
            self.expire_once = False
            return Mock(status_code=401)
        return Mock(status_code=200, json=Mock(return_value={
            "status": "completed" if self.completed else "sent"}))

    def test_waiting_card_opens_pdf_and_download(self):
        self.app.run()
        self.app.button(key=f"view_{EMPLOYEE['id_no']}").click().run()
        self.assertFalse(self.app.exception)
        self.assertEqual(self.pdf_requests, 1)
        self.assertEqual(len(self.app.get("download_button")), 1)

    def test_confirmed_employee_contract_remains_accessible(self):
        self.employee["progress"] = "Confirmed"
        self.app.run()
        self.app.button(key="view_all_contract").click().run()
        self.assertFalse(self.app.exception)
        self.assertEqual(self.pdf_requests, 1)

    def test_incomplete_contract_shows_error_without_download(self):
        self.completed = False
        self.app.run()
        self.app.button(key="view_all_contract").click().run()
        self.assertFalse(self.app.exception)
        self.assertTrue(any("not completed" in error.value for error in self.app.error))
        self.assertEqual(self.pdf_requests, 0)

    def test_missing_envelope_does_not_offer_view_action(self):
        self.employee["envelope_id"] = None
        self.app.run()
        self.assertFalse(self.app.exception)
        self.assertFalse(any(button.label == "View signed contract" for button in self.app.button))
        self.connection.assert_not_called()

    def test_expired_token_is_renewed_and_request_retried(self):
        self.expire_once = True
        self.app.run()
        self.app.button(key="view_all_contract").click().run()
        self.assertFalse(self.app.exception)
        self.assertFalse(self.app.error)
        self.assertEqual(self.connection.call_count, 2)
        self.assertEqual(self.pdf_requests, 1)

    def test_connection_setup_error_is_shown_in_dialog(self):
        self.connection.side_effect = ContractError("DocuSign is not connected yet.")
        self.app.run()
        self.app.button(key="view_all_contract").click().run()
        self.assertFalse(self.app.exception)
        self.assertTrue(any("not connected yet" in error.value for error in self.app.error))
        self.assertEqual(self.pdf_requests, 0)


if __name__ == "__main__":
    unittest.main()
