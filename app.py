import hashlib
import hmac
import logging
import os
import re
import time
from datetime import date
from pathlib import Path

import requests
import streamlit as st
import streamlit.components.v1 as components

from docusign_contracts import DocuSignError, config_from_secrets, fetch_contract
from masked_ids import copyable_html, employee_table, id_input, mask_id

# ---- Settings you may need to adjust to match your database ----
TABLE = "employees"
ID_COL = "id_no"
STATUS_NOT_STARTED = "Not Started"
STATUS_SIGNED = "Signed"
STATUS_CONFIRMED = "Confirmed"
STATUS_COMPLETE = "Complete"
USERS_TABLE = "dashboard_users"
MAX_ATTEMPTS = 5      # failed logins (or wrong invite codes) before a short lock
LOCK_SECONDS = 60
# -----------------------------------------------------------------

logger = logging.getLogger("hr_dashboard")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_RE = re.compile(r"^[a-z0-9._-]{3,30}$")

st.set_page_config(page_title="HR Onboarding Dashboard", layout="wide")


def load_css():
    try:
        css_file = Path(__file__).parent / "style.css"
        if css_file.exists():
            css = "\n".join(
                line for line in css_file.read_text(encoding="utf-8").splitlines() if line.strip()
            )
            st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)
    except Exception:
        # A styling problem must never stop the dashboard from working.
        logger.warning("Could not load style.css", exc_info=True)


load_css()


# ---------------------------------------------------------------
# Settings and database access
# ---------------------------------------------------------------
def secret(name: str, default=None):
    """Read a Streamlit secret without crashing if it is missing."""
    try:
        value = st.secrets[name]
    except Exception:
        return default
    return value if value not in (None, "") else default


def config_ok() -> bool:
    """Stop early with a clear message if the database settings are missing."""
    missing = [k for k in ("SUPABASE_URL", "SUPABASE_KEY") if not secret(k)]
    if missing:
        st.title("HR Onboarding Dashboard")
        st.error("The dashboard is not set up yet. Missing settings: "
                 + ", ".join(missing)
                 + ". Add them in the app's Secrets settings, then reboot the app.")
        return False
    return True


def api_url() -> str:
    return f"{str(secret('SUPABASE_URL', '')).rstrip('/')}/rest/v1/{TABLE}"


def users_url() -> str:
    return f"{str(secret('SUPABASE_URL', '')).rstrip('/')}/rest/v1/{USERS_TABLE}"


def api_headers() -> dict:
    return {"apikey": str(secret("SUPABASE_KEY", "")), "Content-Type": "application/json"}


class DBError(Exception):
    """A database problem with a message that is safe to show on screen."""

    def __init__(self, message: str, status=None):
        super().__init__(message)
        self.message = message
        self.status = status

    def __str__(self) -> str:
        return self.message


STATUS_MESSAGES = {
    400: "The database rejected the data. Check that every field is filled in correctly.",
    401: "The database refused the request. The access key may be wrong or expired.",
    403: "The database refused the request. The table's permissions (RLS) need checking.",
    404: "The database table was not found. Check the table name and the database address.",
    409: "That record already exists.",
    429: "Too many requests were sent. Please wait a moment and try again.",
}


def db_request(method: str, url: str, *, params=None, json=None, prefer=None):
    """Call the database. Returns the parsed JSON, or raises DBError with a safe message."""
    headers = api_headers()
    if prefer:
        headers["Prefer"] = prefer
    try:
        r = requests.request(method, url, headers=headers, params=params, json=json, timeout=15)
    except requests.exceptions.Timeout:
        raise DBError("The database took too long to respond. Please try again.") from None
    except requests.exceptions.ConnectionError:
        raise DBError("Could not reach the database. Check your internet connection "
                      "and try again.") from None
    except requests.exceptions.RequestException:
        logger.exception("Database request failed")
        raise DBError("The request to the database failed. Please try again.") from None

    if r.status_code >= 400:
        logger.warning("Database error %s on %s %s: %s", r.status_code, method, url, r.text[:200])
        if r.status_code in STATUS_MESSAGES:
            message = STATUS_MESSAGES[r.status_code]
        elif r.status_code >= 500:
            message = "The database service is having problems. Please try again shortly."
        else:
            message = f"The database returned an error ({r.status_code})."
        raise DBError(message, status=r.status_code)

    if not r.content:
        return []
    try:
        return r.json()
    except ValueError:
        raise DBError("The database sent back something unexpected. Please try again.") from None


@st.cache_data(ttl=10)
def load_employees() -> list:
    data = db_request("GET", api_url(), params={"select": "*", "order": ID_COL})
    if not isinstance(data, list):
        raise DBError("The database sent back data in an unexpected format.")
    return [row for row in data if isinstance(row, dict)]


def confirm_contract(id_no):
    """Set progress to Confirmed for one employee. Returns (ok, message)."""
    try:
        data = db_request("PATCH", api_url(), params={ID_COL: f"eq.{id_no}"},
                          json={"progress": STATUS_CONFIRMED},
                          prefer="return=representation")
    except DBError as e:
        return False, e.message
    if not data:
        return False, ("No rows were changed. The employee may no longer exist, or the "
                       "table's update policy (RLS) blocked the change.")
    return True, ""


def add_employee(record: dict):
    """Insert one new employee row. Returns (ok, message)."""
    try:
        db_request("POST", api_url(), json=record, prefer="return=representation")
    except DBError as e:
        if e.status == 409:
            return False, "An employee with that ID already exists."
        return False, e.message
    return True, ""


def update_employee(id_no, changes: dict):
    """Update details for one employee (matched by ID). Returns (ok, message)."""
    try:
        data = db_request("PATCH", api_url(), params={ID_COL: f"eq.{id_no}"},
                          json=changes, prefer="return=representation")
    except DBError as e:
        return False, e.message
    if not data:
        return False, ("No rows were changed. The ID may not exist, or the table's "
                       "update policy (RLS) blocked the change.")
    return True, ""


# ---------------------------------------------------------------
# Logins and profiles
# ---------------------------------------------------------------
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
    try:
        db_request(
            "POST", users_url(), prefer="return=minimal",
            json={
                "username": username.strip().lower(),
                "display_name": display_name.strip(),
                "salt": salt,
                "pw_hash": hash_pw(password, salt),
            },
        )
    except DBError as e:
        if e.status == 409:
            return False, "That username is already taken."
        return False, f"Could not create the profile. {e.message}"
    return True, ""


def check_login(username: str, password: str):
    """Return (display_name, error). display_name is None if the login does not match."""
    try:
        rows = db_request(
            "GET", users_url(),
            params={"username": f"eq.{username.strip().lower()}",
                    "select": "display_name,salt,pw_hash"},
        )
    except DBError as e:
        return None, f"Could not check your login. {e.message}"
    try:
        if isinstance(rows, list) and rows and safe_eq(
            hash_pw(password, rows[0]["salt"]), rows[0]["pw_hash"]
        ):
            return rows[0]["display_name"], ""
    except (KeyError, ValueError, TypeError):
        logger.warning("A stored profile has a missing or damaged password record")
        return None, "This profile could not be checked. Please ask an administrator."
    return None, ""


def can_view_contracts() -> bool:
    """Any logged-in user (including new profiles) may open contracts.

    To limit it later, add CONTRACT_VIEWERS = "admin,hrmanager" (usernames) to the Secrets.
    """
    allowed = {u.strip().lower() for u in str(secret("CONTRACT_VIEWERS", "")).split(",")
               if u.strip()}
    return not allowed or st.session_state.get("username", "") in allowed


def lock_remaining() -> int:
    """Seconds left on the short lock after too many failed attempts (0 = not locked)."""
    left = st.session_state.get("lock_until", 0) - time.time()
    return int(left) + 1 if left > 0 else 0


def register_failure():
    fails = st.session_state.get("fails", 0) + 1
    if fails >= MAX_ATTEMPTS:
        st.session_state["lock_until"] = time.time() + LOCK_SECONDS
        fails = 0
    st.session_state["fails"] = fails


# ---------------------------------------------------------------
# Input checks
# ---------------------------------------------------------------
def validate_employee(id_no: str, first: str, last: str, email: str, dept: str,
                      check_id: bool = True) -> str:
    """Return an error message, or an empty string if everything is valid."""
    if check_id:
        if not id_no:
            return "Please enter the ID number."
        if not id_no.isdigit():
            return "The ID number must contain digits only."
        if not 4 <= len(id_no) <= 20:
            return "The ID number must be between 4 and 20 digits."
    for label, value in (("First name", first), ("Last name", last), ("Department", dept)):
        if not value:
            return f"{label} cannot be empty."
        if len(value) > 60:
            return f"{label} must be 60 characters or fewer."
    if not email:
        return "Email address cannot be empty."
    if len(email) > 120 or not EMAIL_RE.match(email):
        return "Please enter a valid email address."
    return ""


def validate_signup(display: str, username: str, p1: str, p2: str) -> str:
    if not (display and username and p1):
        return "Please fill in every field."
    if len(display) > 60:
        return "Your name must be 60 characters or fewer."
    if not USERNAME_RE.match(username):
        return ("The username must be 3 to 30 characters: lowercase letters, numbers, "
                "dots, dashes or underscores.")
    if len(p1) < 10:
        return "Use a password of at least 10 characters."
    if len(p1) > 128:
        return "The password must be 128 characters or fewer."
    if p1 != p2:
        return "The passwords do not match."
    return ""


# ---------------------------------------------------------------
# Screens
# ---------------------------------------------------------------
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
                wait = lock_remaining()
                if wait:
                    st.warning(f"Too many failed attempts. Please wait {wait} seconds "
                               "and try again.")
                elif not username.strip() or not pw:
                    st.error("Please enter your username and password.")
                else:
                    name, err = None, ""
                    admin_pw = secret("DASHBOARD_PASSWORD")
                    # Backup admin login using the original dashboard password
                    if admin_pw and username.strip().lower() == "admin" and safe_eq(pw, admin_pw):
                        name = "Admin"
                    else:
                        name, err = check_login(username, pw)
                    if name:
                        st.session_state["user"] = name
                        st.session_state["username"] = username.strip().lower()
                        st.session_state["fails"] = 0
                        st.rerun()
                    elif err:
                        st.error(err)
                    else:
                        register_failure()
                        st.error("Wrong username or password.")

    with tab_new:
        invite = secret("INVITE_CODE")
        if not invite:
            st.info("Creating a profile is not available right now. "
                    "Please ask an administrator.")
        else:
            with st.form("signup"):
                display = st.text_input("Your name")
                new_user = st.text_input("Choose a username")
                p1 = st.text_input("Password (10+ characters)", type="password")
                p2 = st.text_input("Repeat password", type="password")
                code = st.text_input("Invite code", type="password")
                if st.form_submit_button("Create profile"):
                    wait = lock_remaining()
                    problem = validate_signup(display.strip(), new_user.strip().lower(), p1, p2)
                    if wait:
                        st.warning(f"Too many failed attempts. Please wait {wait} seconds "
                                   "and try again.")
                    elif problem:
                        st.error(problem)
                    elif not safe_eq(code, invite):
                        register_failure()
                        st.error("Wrong invite code.")
                    else:
                        ok, msg = create_profile(new_user, display, p1)
                        if ok:
                            st.success("Profile created. Go to the Log in tab.")
                        else:
                            st.error(msg)
    return False


def main():
    if not config_ok():
        return
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
    except DBError as e:
        st.error(f"Could not load employees. {e.message}")
        st.caption("Press Refresh to try again. If it keeps happening, tell your administrator.")
        return
    except Exception:
        logger.exception("Unexpected error while loading employees")
        st.error("Could not load employees. Please press Refresh to try again.")
        return

    waiting = [r for r in rows if same(r.get("progress"), STATUS_SIGNED)]
    not_started = [r for r in rows if same(r.get("progress"), STATUS_NOT_STARTED)]
    confirmed = [r for r in rows if same(r.get("progress"), STATUS_CONFIRMED)]

    m1, m2, m3 = st.columns(3)
    m1.metric("Not started", len(not_started))
    m2.metric("Signed - awaiting confirmation", len(waiting))
    m3.metric("Confirmed", len(confirmed))

    tab_wait, tab_all, tab_add, tab_edit, tab_contracts = st.tabs(
        ["Awaiting confirmation", "All employees", "Add employee", "Edit employee", "Contracts"]
    )

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
                    f" Start date: {r.get('start_date', '-')}"
                )
                with left:
                    components.html(copyable_html('ID: ' + id_input(id_no)), height=36)
                if right.button(" Confirm contract", key=f"confirm_{id_no}", type="primary"):
                    ok, msg = confirm_contract(id_no)
                    if ok:
                        load_employees.clear()
                        st.toast(f"Confirmed {r.get('first_name', '')}'s contract.")
                        st.rerun()
                    else:
                        st.error(f"Could not confirm. {msg}")

    with tab_all:
        search = st.text_input("Search by name or email")
        view = []
        for r in rows:
            text = f"{r.get('first_name', '')} {r.get('last_name', '')} {r.get('email_address', '')}".lower()
            if search.strip().lower() in text:
                view.append(r)
        st.caption("Click an ID, then press Ctrl+C (Command+C on Mac) to copy the full number.")
        if view:
            components.html(employee_table(view), height=min(400, 45 + 42 * len(view)))
        else:
            st.info("No employees match your search.")

    with tab_add:
        st.subheader("Add a new employee")
        st.caption("Type the full ID number (not the masked version shown in the tables).")
        with st.form("add_employee"):
            c1, c2 = st.columns(2)
            new_id = c1.text_input("ID number")
            first = c2.text_input("First name")
            last = c1.text_input("Last name")
            email = c2.text_input("Email address")
            dept = c1.text_input("Department")
            start = c2.date_input("Start date", value=date.today())
            progress = c1.selectbox(
                "Onboarding progress",
                [STATUS_NOT_STARTED, STATUS_SIGNED, STATUS_CONFIRMED, STATUS_COMPLETE],
            )
            submitted = st.form_submit_button("Add employee", type="primary")

        if submitted:
            new_id, first, last = new_id.strip(), first.strip(), last.strip()
            email, dept = email.strip(), dept.strip()
            existing = {str(r.get(ID_COL) or "").strip() for r in rows}
            problem = validate_employee(new_id, first, last, email, dept)
            if problem:
                st.error(problem)
            elif new_id in existing:
                st.error("An employee with that ID already exists.")
            else:
                ok, msg = add_employee({
                    ID_COL: new_id,
                    "first_name": first,
                    "last_name": last,
                    "email_address": email,
                    "department": dept,
                    "start_date": start.isoformat(),
                    "progress": progress,
                })
                if ok:
                    load_employees.clear()
                    st.toast(f"Added {first} {last}.")
                    st.rerun()
                else:
                    st.error(f"Could not add the employee. {msg}")

    with tab_edit:
        st.subheader("Edit employee details")
        if not rows:
            st.info("There are no employees to edit yet.")
        else:
            def label(r):
                return (f"{r.get('first_name', '')} {r.get('last_name', '')} "
                        f"({mask_id(r.get(ID_COL))})")

            idx = st.selectbox("Choose an employee", range(len(rows)),
                               format_func=lambda i: label(rows[i]))
            sel = rows[idx]
            sel_id = sel.get(ID_COL)

            statuses = [STATUS_NOT_STARTED, STATUS_SIGNED, STATUS_CONFIRMED, STATUS_COMPLETE]
            current = str(sel.get("progress") or STATUS_NOT_STARTED)
            if current not in statuses:
                statuses.append(current)
            try:
                start_default = date.fromisoformat(str(sel.get("start_date"))[:10])
            except ValueError:
                start_default = date.today()

            with st.form(f"edit_form_{sel_id}"):
                e1, e2 = st.columns(2)
                with e1:
                    components.html(copyable_html(
                        '<label>ID number (cannot be changed)<br>'
                        + id_input(sel_id) + '</label>'
                    ), height=74)
                e_first = e2.text_input("First name", value=sel.get("first_name") or "",
                                        key=f"e_first_{sel_id}")
                e_last = e1.text_input("Last name", value=sel.get("last_name") or "",
                                       key=f"e_last_{sel_id}")
                e_email = e2.text_input("Email address", value=sel.get("email_address") or "",
                                        key=f"e_email_{sel_id}")
                e_dept = e1.text_input("Department", value=sel.get("department") or "",
                                       key=f"e_dept_{sel_id}")
                e_start = e2.date_input("Start date", value=start_default,
                                        key=f"e_start_{sel_id}")
                e_prog = e1.selectbox("Onboarding progress", statuses,
                                      index=statuses.index(current), key=f"e_prog_{sel_id}")
                save = st.form_submit_button("Save changes", type="primary")

            if save:
                new_vals = {
                    "first_name": e_first.strip(),
                    "last_name": e_last.strip(),
                    "email_address": e_email.strip(),
                    "department": e_dept.strip(),
                    "start_date": e_start.isoformat(),
                    "progress": e_prog,
                }
                old_vals = {
                    "first_name": str(sel.get("first_name") or ""),
                    "last_name": str(sel.get("last_name") or ""),
                    "email_address": str(sel.get("email_address") or ""),
                    "department": str(sel.get("department") or ""),
                    "start_date": str(sel.get("start_date") or "")[:10],
                    "progress": current,
                }
                changes = {k: v for k, v in new_vals.items() if v != old_vals[k]}
                problem = validate_employee(
                    "", new_vals["first_name"], new_vals["last_name"],
                    new_vals["email_address"], new_vals["department"], check_id=False,
                )
                if problem:
                    st.error(problem)
                elif not changes:
                    st.info("No changes to save.")
                else:
                    ok, msg = update_employee(sel_id, changes)
                    if ok:
                        load_employees.clear()
                        st.toast(f"Saved changes for {new_vals['first_name']} {new_vals['last_name']}.")
                        st.rerun()
                    else:
                        st.error(f"Could not save the changes. {msg}")


    with tab_contracts:
        st.subheader("Employee contracts")
        ds_cfg = config_from_secrets(secret)
        if not can_view_contracts():
            st.info("Your account is not allowed to view contracts.")
        elif not ds_cfg:
            st.info("Contract viewing is not set up yet. Add the DocuSign settings in the "
                    "app's Secrets, then reboot the app.")
        elif not rows:
            st.info("There are no employees yet.")
        else:
            cidx = st.selectbox(
                "Choose an employee", range(len(rows)), key="contract_pick",
                format_func=lambda i: (f"{rows[i].get('first_name', '')} "
                                       f"{rows[i].get('last_name', '')} "
                                       f"({mask_id(rows[i].get(ID_COL))})"),
            )
            emp = rows[cidx]
            emp_id = emp.get(ID_COL)
            if st.button("Load contract", key="load_contract"):
                try:
                    with st.spinner("Contacting DocuSign..."):
                        result = fetch_contract(ds_cfg, envelope_id=emp.get("envelope_id"),
                                                email=emp.get("email_address"))
                    st.session_state["contract"] = {"emp": emp_id, **result}
                    logger.info("Contract opened by %s for employee ending %s",
                                st.session_state.get("username"), str(emp_id)[-4:])
                except DocuSignError as e:
                    st.session_state.pop("contract", None)
                    st.error(e.message)
                except Exception:
                    logger.exception("Unexpected error while loading a contract")
                    st.session_state.pop("contract", None)
                    st.error("Could not load the contract. Please try again.")
            data = st.session_state.get("contract")
            if data and data.get("emp") == emp_id:
                st.write(f"DocuSign status: **{data['status']}**")
                st.download_button(
                    "Download contract (PDF)", data=data["pdf"],
                    file_name=f"contract_{str(emp_id)[-4:]}.pdf", mime="application/pdf",
                    key=f"dl_{emp_id}",
                )
                if str(data["status"]).lower() != "completed":
                    st.warning("This contract is not fully signed in DocuSign yet.")


def run():
    """Last safety net: show a friendly message instead of a raw error page."""
    try:
        main()
    except Exception as e:
        # Streamlit uses special exceptions internally for st.rerun() and st.stop().
        if type(e).__name__ in ("RerunException", "StopException"):
            raise
        logger.exception("Unexpected error in the dashboard")
        st.error("Something went wrong. Please refresh the page and try again. "
                 "If it keeps happening, tell your administrator.")


run()
