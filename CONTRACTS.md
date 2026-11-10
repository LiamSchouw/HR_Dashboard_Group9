Signed DocuSign contracts
========================

The dashboard reads the existing `employees.envelope_id` column in Supabase.
No database migration or document URL is needed. Signed contracts are fetched
server-side from DocuSign on demand and shown as a PDF, with a download button.
They are accessible on awaiting-confirmation cards and through the employee
selector under All employees, including after HR confirms a contract.

The dashboard verifies the envelope is `completed` in DocuSign before retrieving
the combined document PDF. Documents are not stored in Supabase or a shared
application cache. The integration user must have access to these envelopes.

Setup
-----

Install the updated `requirements.txt`, then configure these values in
Streamlit deployment secrets (or local `.streamlit/secrets.toml`):

```toml
DOCUSIGN_INTEGRATION_KEY = "your-integration-client-id"
DOCUSIGN_USER_ID = "your-impersonated-user-id"
DOCUSIGN_ACCOUNT_ID = "your-api-account-id"
# Production: account.docusign.com; sandbox: account-d.docusign.com
DOCUSIGN_AUTH_SERVER = "account.docusign.com"
DOCUSIGN_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
your-RSA-private-key
-----END RSA PRIVATE KEY-----"""
```

Use credentials from the same DocuSign environment as the saved envelopes.
Configure an RSA key pair for the integration and grant the impersonated user
one-time consent for the `signature` and `impersonation` scopes. Never commit
the private key or put it in an employee record. The app renews JWT access tokens
automatically and discovers the configured account's API address via userinfo.
All authenticated dashboard users can view contracts using this connection.

DocuSign references:

- [JWT grant and consent setup](https://developers.docusign.com/platform/auth/jwt-get-token)
- [Download envelope documents](https://developers.docusign.com/docs/esign-rest-api/how-to/download-envelope-documents/)
- [Streamlit PDF viewer](https://docs.streamlit.io/develop/api-reference/media/st.pdf)
