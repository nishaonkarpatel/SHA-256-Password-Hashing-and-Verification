
import streamlit as st
import sqlite3
import os, base64, time, secrets, string, hashlib, hmac
from datetime import datetime

# -------------------- Config --------------------
DB_PATH = "auth_portal.db"
DEFAULT_ITERS = 100_000
SALT_LEN = 16
LOGO_PATH = "bmsitLogo.png"  # place your logo in the app working directory

PRIMARY = "#0E1A3B"   # deep navy
ACCENT  = "#D9252A"   # BMS red
MUTED   = "#EEF1F7"   # soft background

# -------------------- Secrets / Pepper --------------------
def _pepper_bytes() -> bytes:
    pep = os.environ.get("AUTH_PEP", "") or st.secrets.get("AUTH_PEP", "")
    if not pep:
        return b""
    try:
        return base64.b64decode(pep)
    except Exception:
        return pep.encode("utf-8")

# -------------------- DB --------------------
def init_db():
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users(
            username    TEXT PRIMARY KEY,
            salt        BLOB NOT NULL,
            hash        BLOB NOT NULL,
            iterations  INTEGER NOT NULL,
            created_at  TEXT NOT NULL
        )
        """)
        conn.commit()

def insert_user(username: str, salt: bytes, pw_hash: bytes, iterations: int):
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        conn.execute(
            "INSERT INTO users(username, salt, hash, iterations, created_at) VALUES (?, ?, ?, ?, ?)",
            (username, salt, pw_hash, iterations, datetime.utcnow().isoformat(timespec="seconds")+"Z"),
        )
        conn.commit()

def get_user(username: str):
    with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
        cur = conn.execute(
            "SELECT username, salt, hash, iterations FROM users WHERE username=?",
            (username,),
        )
        row = cur.fetchone()
        if not row: return None
        return {"username": row[0], "salt": row[1], "hash": row[2], "iterations": int(row[3])}

# -------------------- Crypto --------------------
def pbkdf2_sha256(password: str, salt: bytes, iterations: int) -> bytes:
    pepper = _pepper_bytes()
    full_salt = salt + pepper
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), full_salt, iterations, dklen=32)

def gen_salt(n: int = SALT_LEN) -> bytes:
    return secrets.token_bytes(n)


# -------------------- Styling --------------------
def inject_css():
    st.markdown(f"""
    <style>
    .stApp {{
        background: radial-gradient(1400px circle at 10% 5%, {MUTED} 0%, #ffffff 40%);
    }}
    .portal-header {{
        background: linear-gradient(90deg, {PRIMARY} 0%, #182A67 60%);
        padding: 16px 20px;
        color: white;
        border-radius: 14px;
        box-shadow: 0 8px 24px rgba(0,0,0,0.18);
        margin-bottom: 22px;
    }}
    .portal-title {{
        font-size: 28px; font-weight: 800; letter-spacing: 0.2px; margin: 0;
    }}
    .portal-subtitle {{
        margin: 2px 0 0 0; font-size: 14px; opacity: 0.9;
    }}
    .card {{
        background: white; border-radius: 14px; padding: 18px;
        border: 1px solid #e6eaf0;
        box-shadow: 0 6px 18px rgba(22, 29, 58, 0.08);
    }}
    .accent {{
        color: {ACCENT};
    }}
    .footer-note {{
        color: #5d6b8a; font-size: 12px; text-align:center; margin-top: 24px;
    }}
    </style>
    """, unsafe_allow_html=True)

def header_with_logo():
    cols = st.columns([1,5])
    with cols[0]:
        if os.path.exists(LOGO_PATH):
            st.image(LOGO_PATH, use_container_width=True)
        else:
            st.write("")
    with cols[1]:
        st.markdown(f"""
        <div class="portal-header">
            <div class="portal-title">BMSIT Student Portal</div>
        </div>
        """, unsafe_allow_html=True)

# -------------------- App --------------------
st.set_page_config(page_title="BMSIT Student Portal", page_icon="🎓", layout="centered")
inject_css()
header_with_logo()
init_db()

tab_signup, tab_login = st.tabs(["📝 Student Sign Up", "🔓 Student Log In"])

with tab_signup:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.subheader("Create your campus account")
    col1, col2 = st.columns(2)
    with col1:
        username = st.text_input("College Email / USN").strip()
    with col2:
        iterations = st.number_input("Hashing iterations", min_value=10_000, max_value=2_000_000,
                                     value=DEFAULT_ITERS, step=10_000,
                                     help="Higher = stronger (but slower).")
    pw = st.text_input("Password", type="password", help="Use 14+ chars, mix of cases, digits & symbols.")
    pw2 = st.text_input("Re-enter Password", type="password")
    if st.button("Create Account", type="primary"):
        if not username or not pw:
            st.error("Username and password are required.")
        elif pw != pw2:
            st.error("Passwords do not match.")
        elif get_user(username):
            st.error("An account with this username already exists.")
        else:
            salt = gen_salt()
            h = pbkdf2_sha256(pw, salt, int(iterations))
            insert_user(username, salt, h, int(iterations))
            st.success("Account created successfully. You can log in now.")

    st.markdown('</div>', unsafe_allow_html=True)

with tab_login:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.subheader("Access your portal")
    u = st.text_input("College Email / USN", key="login_user").strip()
    p = st.text_input("Password", type="password", key="login_pw")
    colA, colB = st.columns([1,1])
    with colA:
        remember = st.checkbox("Remember me", value=False, help="For demo only (no cookies stored).")
    with colB:
        st.caption("Forgot password? Contact the department admin.")

    if st.button("Log In"):
        user = get_user(u)
        if not user:
            st.error("No such account found.")
        else:
            t0 = time.perf_counter()
            test_hash = pbkdf2_sha256(p, user["salt"], user["iterations"])
            t1 = time.perf_counter()
            ok = hmac.compare_digest(test_hash, user["hash"])
            if ok:
                st.success(f"Welcome, {u}! ✅ (Hashing time: {(t1 - t0)*1000:.1f} ms)")
                st.balloons()
            else:
                st.error("Incorrect password. Please try again.")
    st.markdown('</div>', unsafe_allow_html=True)

st.markdown('<p class="footer-note">© BMS Institute of Technology & Management • Yelahanka, Bengaluru</p>', unsafe_allow_html=True)
