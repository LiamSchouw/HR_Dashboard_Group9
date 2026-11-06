import hashlib
import hmac
import os
from pathlib import Path

import requests
import streamlit as st

# ---- Settings you may need to adjust to match your database ----
TABLE = "employees"
ID_COL = "id_no"
STATUS_NOT_STARTED = "Not Started"
STATUS_SIGNED = "Signed"
STATUS_CONFIRMED = "Confirmed"
STATUS_COMPLETE = "Complete"
USERS_TABLE = "dashboard_users"
# -----------------------------------------------------------------

st.set_page_config(page_title="HR Onboarding Dashboard", layout="wide")


def load_css():
    css_file = Path(__file__).parent / "style.css"
    if css_file.exists():
        css = "\n".join(
            line for line in css_file.read_text(encoding="utf-8").splitlines() if line.strip()
        )
        st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)


load_css()


def api_url() -> str:
    return f"{st.secrets['SUPABASE_URL'].rstrip('/')}/rest/v1/{TABLE}"


def users_url() -> str:
    return f"{st.secrets['SUPABASE_URL'].rstrip('/')}/rest/v1/{USERS_TABLE}"


def api_headers() -> dict:
    return {"apikey": st.secrets["SUPABASE_KEY"], "Content-Type": "application/json"}


def mask_id(id_no) -> str:
    """Show only the last 4 digits so the screen does not expose full ID numbers."""
    s = str(id_no or "")
    return "*" * max(len(s) - 4, 0) + s[-4:]


def same(a, b) -> bool:
    return str(a or "").strip().lower() == str(b or "").strip().lower()


def safe_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(str(a).encode(), str(b).encode())


def hash_pw(password: str, salt_hex: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt_hex), 200_000
    ).hex()


def create_profile(username: str, display_name: str, password: str):
    """Create a dashboard login. Only a salted hash is stored, never the password."""
    salt = os.urandom(16).hex()
    r = requests.post(
        users_url(),
        headers={**api_headers(), "Prefer": "return=minimal"},
        json={
            "username": username.strip().lower(),
            "display_name": display_name.strip(),
            "salt": salt,
            "pw_hash": hash_pw(password, salt),
        },
        timeout=15,
    )
    if r.status_code in (200, 201, 204):
        return True, ""
    if r.status_code == 409:
        return False, "That username is already taken."
    return False, f"Could not create the profile (error {r.status_code})."


def check_login(username: str, password: str):
    """Return the display name if the username and password match, else None."""
    r = requests.get(
        users_url(),
        headers=api_headers(),
        params={
            "username": f"eq.{username.strip().lower()}",
            "select": "display_name,salt,pw_hash",
        },
        timeout=15,
    )
    r.raise_for_status()
    rows = r.json()
    if rows and safe_eq(hash_pw(password, rows[0]["salt"]), rows[0]["pw_hash"]):
        return rows[0]["display_name"]
    return None


@st.cache_data(ttl=10)
def load_employees() -> list:
    r = requests.get(api_url(), headers=api_headers(),
                     params={"select": "*", "order": ID_COL}, timeout=15)
    r.raise_for_status()
    return r.json()


def confirm_contract(id_no) -> bool:
    """Set progress to Confirmed for one employee. Returns True if a row changed."""
    r = requests.patch(
        api_url(),
        headers={**api_headers(), "Prefer": "return=representation"},
        params={ID_COL: f"eq.{id_no}"},
        json={"progress": STATUS_CONFIRMED},
        timeout=15,
    )
    r.raise_for_status()
    return len(r.json()) > 0  # empty list = Supabase refused silently (RLS policy)


def login_gate() -> bool:
    if st.session_state.get("user"):
        return True

    st.title("HR Onboarding Dashboard")
    tab_in, tab_new = st.tabs(["Log in", "Create profile"])

    with tab_in:
        with st.form("login"):
            username = st.text_input("Username")
            pw = st.text_input("Password", type="password")
            if st.form_submit_button("Log in"):
                name = None
                # Backup admin login using the original dashboard password
                if username.strip().lower() == "admin" and safe_eq(
                    pw, st.secrets["DASHBOARD_PASSWORD"]
                ):
                    name = "Admin"
                else:
                    try:
                        name = check_login(username, pw)
                    except Exception:
                        name = None
                if name:
                    st.session_state["user"] = name
                    st.rerun()
                else:
                    st.error("Wrong username or password.")

    with tab_new:
        with st.form("signup"):
            display = st.text_input("Your name")
            new_user = st.text_input("Choose a username")
            p1 = st.text_input("Password (10+ characters)", type="password")
            p2 = st.text_input("Repeat password", type="password")
            code = st.text_input("Invite code", type="password")
            if st.form_submit_button("Create profile"):
                if not (display.strip() and new_user.strip() and p1):
                    st.error("Please fill in every field.")
                elif len(p1) < 10:
                    st.error("Use a password of at least 10 characters.")
                elif p1 != p2:
                    st.error("The passwords do not match.")
                elif not safe_eq(code, st.secrets["INVITE_CODE"]):
                    st.error("Wrong invite code.")
                else:
                    try:
                        ok, msg = create_profile(new_user, display, p1)
                    except Exception as e:
                        ok, msg = False, f"Could not reach the database: {e}"
                    if ok:
                        st.success("Profile created. Go to the Log in tab.")
                    else:
                        st.error(msg)
    return False


def main():
    if not login_gate():
        return

    st.sidebar.write(f"Signed in as {st.session_state['user']}")
    if st.sidebar.button("Log out"):
        st.session_state.clear()
        st.rerun()

    st.title("HR Onboarding Dashboard")

    top_l, top_r = st.columns([5, 1])
    top_l.caption("Employees going through onboarding.")
    if top_r.button("Refresh"):
        load_employees.clear()
        st.rerun()

    try:
        rows = load_employees()
    except Exception as e:
        st.error(f"Could not load employees: {e}")
        return

    waiting = [r for r in rows if same(r.get("progress"), STATUS_SIGNED)]
    not_started = [r for r in rows if same(r.get("progress"), STATUS_NOT_STARTED)]
    confirmed = [r for r in rows if same(r.get("progress"), STATUS_CONFIRMED)]

    m1, m2, m3 = st.columns(3)
    m1.metric("Not started", len(not_started))
    m2.metric("Signed - awaiting confirmation", len(waiting))
    m3.metric("Confirmed", len(confirmed))

    tab_wait, tab_all = st.tabs(["Awaiting confirmation", "All employees"])

    with tab_wait:
        if not waiting:
            st.success("Nothing waiting. All signed contracts are confirmed.")
        for r in waiting:
            id_no = r.get(ID_COL)
            with st.container(key=f"card_{id_no}"):
                left, right = st.columns([4, 1])
                left.subheader(f"{r.get('first_name', '')} {r.get('last_name', '')}")
                left.write(
                    f" {r.get('email_address', '-')}  \n"
                    f" {r.get('department', '-')}  \n"
                    f" Start date: {r.get('start_date', '-')}  \n"
                    f" ID: {mask_id(id_no)}"
                )
                if right.button(" Confirm contract", key=f"confirm_{id_no}", type="primary"):
                    try:
                        if confirm_contract(id_no):
                            load_employees.clear()
                            st.toast(f"Confirmed {r.get('first_name', '')}'s contract.")
                            st.rerun()
                        else:
                            st.error("Supabase accepted the request but changed no rows. "
                                     "Check the table's update policy (RLS).")
                    except Exception as e:
                        st.error(f"Could not confirm: {e}")

    with tab_all:
        search = st.text_input("Search by name or email")
        view = []
        for r in rows:
            text = f"{r.get('first_name', '')} {r.get('last_name', '')} {r.get('email_address', '')}".lower()
            if search.strip().lower() in text:
                view.append({
                    "ID": mask_id(r.get(ID_COL)),
                    "First name": r.get("first_name"),
                    "Last name": r.get("last_name"),
                    "Email": r.get("email_address"),
                    "Department": r.get("department"),
                    "Start date": r.get("start_date"),
                    "Progress": r.get("progress"),
                })
        st.dataframe(view, use_container_width=True, hide_index=True)


main()
