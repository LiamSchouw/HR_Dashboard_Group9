from pathlib import Path
import hmac

import requests
import streamlit as st

# ---- Settings you may need to adjust to match your database ----
TABLE = "employees"
ID_COL = "id_no"
STATUS_NOT_STARTED = "Not Started"
STATUS_SIGNED = "Signed"
STATUS_CONFIRMED = "Confirmed"
STATUS_COMPLETE = "Complete"
# -----------------------------------------------------------------

st.set_page_config(page_title="HR Onboarding Dashboard", layout="wide")
def load_css():
    css_file = Path(__file__).parent / "style.css"
    if css_file.exists():
        css = "\n".join(l for l in css_file.read_text(encoding="utf-8").splitlines() if l.strip())
        st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)


load_css()

def api_url() -> str:
    return f"{st.secrets['SUPABASE_URL'].rstrip('/')}/rest/v1/{TABLE}"


def api_headers() -> dict:
    return {"apikey": st.secrets["SUPABASE_KEY"], "Content-Type": "application/json"}


def mask_id(id_no) -> str:
    """Show only the last 4 digits so the screen does not expose full ID numbers."""
    s = str(id_no or "")
    return "*" * max(len(s) - 4, 0) + s[-4:]


def same(a, b) -> bool:
    return str(a or "").strip().lower() == str(b or "").strip().lower()


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
    if st.session_state.get("auth"):
        return True
    st.title("HR Onboarding Dashboard")
    with st.form("login"):
        pw = st.text_input("Password", type="password")
        if st.form_submit_button("Log in"):
            if hmac.compare_digest(pw, st.secrets["DASHBOARD_PASSWORD"]):
                st.session_state["auth"] = True
                st.rerun()
            else:
                st.error("Wrong password.")
    return False


def main():
    if not login_gate():
        return

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
