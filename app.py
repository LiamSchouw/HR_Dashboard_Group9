import hashlib
import hmac
import os
from datetime import date
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


def add_employee(record: dict):
    """Insert one new employee row. Returns (ok, message)."""
    r = requests.post(
        api_url(),
        headers={**api_headers(), "Prefer": "return=representation"},
        json=record,
        timeout=15,
    )
    if r.status_code in (200, 201):
        return True, ""
    if r.status_code == 409:
        return False, "An employee with that ID already exists."
    if r.status_code in (401, 403):
        return False, ("The database refused the insert. The employees table "
                       "needs an insert policy (RLS) for this key.")
    return False, f"Could not add the employee (error {r.status_code}): {r.text[:200]}"


def update_employee(id_no, changes: dict):
    """Update details for one employee (matched by ID). Returns (ok, message)."""
    r = requests.patch(
        api_url(),
        headers={**api_headers(), "Prefer": "return=representation"},
        params={ID_COL: f"eq.{id_no}"},
        json=changes,
        timeout=15,
    )
    if r.status_code in (401, 403):
        return False, "The database refused the update. Check the update policy (RLS)."
    if r.status_code >= 400:
        return False, f"Could not save the changes (error {r.status_code}): {r.text[:200]}"
    if len(r.json()) == 0:
        return False, ("No rows were changed. The ID may not exist, or the table's "
                       "update policy (RLS) blocked the change.")
    return True, ""


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

    tab_wait, tab_all, tab_add, tab_edit = st.tabs(
        ["Awaiting confirmation", "All employees", "Add employee", "Edit employee"]
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
            new_id = new_id.strip()
            existing = {str(r.get(ID_COL) or "").strip() for r in rows}
            if not all([new_id, first.strip(), last.strip(), email.strip(), dept.strip()]):
                st.error("Please fill in every field.")
            elif not new_id.isdigit():
                st.error("The ID number must contain digits only.")
            elif "@" not in email or "." not in email.split("@")[-1]:
                st.error("Please enter a valid email address.")
            elif new_id in existing:
                st.error("An employee with that ID already exists.")
            else:
                try:
                    ok, msg = add_employee({
                        ID_COL: new_id,
                        "first_name": first.strip(),
                        "last_name": last.strip(),
                        "email_address": email.strip(),
                        "department": dept.strip(),
                        "start_date": start.isoformat(),
                        "progress": progress,
                    })
                except Exception as e:
                    ok, msg = False, f"Could not reach the database: {e}"
                if ok:
                    load_employees.clear()
                    st.toast(f"Added {first.strip()} {last.strip()}.")
                    st.rerun()
                else:
                    st.error(msg)


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
                e1.text_input("ID number (cannot be changed)", value=mask_id(sel_id),
                              disabled=True, key=f"e_id_{sel_id}")
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
                if not all(new_vals[k] for k in
                           ("first_name", "last_name", "email_address", "department")):
                    st.error("First name, last name, email and department cannot be empty.")
                elif "@" not in new_vals["email_address"] or \
                        "." not in new_vals["email_address"].split("@")[-1]:
                    st.error("Please enter a valid email address.")
                elif not changes:
                    st.info("No changes to save.")
                else:
                    try:
                        ok, msg = update_employee(sel_id, changes)
                    except Exception as e:
                        ok, msg = False, f"Could not reach the database: {e}"
                    if ok:
                        load_employees.clear()
                        st.toast(f"Saved changes for {new_vals['first_name']} {new_vals['last_name']}.")
                        st.rerun()
                    else:
                        st.error(msg)


main()
