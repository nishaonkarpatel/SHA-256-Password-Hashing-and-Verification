import streamlit as st
import sqlite3, os, base64, time, secrets, string, hashlib, hmac, csv
from datetime import datetime

# -------------------- Config --------------------
DB_PATH = "auth_portal.db"
DEFAULT_ITERS = 100_000
SALT_LEN = 16
LOGO_PATH = "bmsitLogo.png"  # place your logo in the same folder

# -------------------- Styling --------------------
def inject_css():
    st.markdown("""
    <style>
    .stApp {
        background: radial-gradient(1400px circle at 10% 5%, #EEF1F7 0%, #ffffff 40%);
    }
    .footer-note {
        color: #5d6b8a; font-size: 12px; text-align:center; margin-top: 24px;
    }
    .top-divider {
        border: none;
        border-top: 2px solid rgba(0,0,0,0.04);
        margin: 6px 0 8px 0;
    }
    </style>
    """, unsafe_allow_html=True)

# -------------------- Logo Header --------------------
def header_with_logo():
    # full-width, centered image, bigger
    if os.path.exists(LOGO_PATH):
        st.image(LOGO_PATH, width=820)
    else:
        st.write("BMS Institute of Technology & Management")

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
        if not row:
            return None
        return {"username": row[0], "salt": row[1], "hash": row[2], "iterations": int(row[3])}

# -------------------- Crypto --------------------
def pbkdf2_sha256(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)

def gen_salt(n: int = SALT_LEN) -> bytes:
    return secrets.token_bytes(n)

# -------------------- App --------------------
st.set_page_config(page_title="BMSIT Student Portal", page_icon="🎓", layout="centered")
inject_css()
header_with_logo()
init_db()

tab_signup, tab_login = st.tabs(["📝 Student Sign Up", "🔓 Student Log In"])

# ---------- SIGN UP ----------
with tab_signup:
    st.subheader("Create your campus account")

    col1, col2 = st.columns(2)
    with col1:
        username = st.text_input("College Email / USN").strip()
    with col2:
        iterations = st.number_input(
            "Hashing iterations",
            min_value=10_000,
            max_value=2_000_000,
            value=DEFAULT_ITERS,
            step=10_000,
            help="Higher = stronger (but slower)."
        )

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

    # ---------- CSV EXPORT (Teacher Demo) ----------
    st.markdown("Evidence of Password Hashing & Database Security")
    
    with st.expander("CSV Export:"):
        st.info("This section demonstrates that passwords are stored only as salted SHA-256 hashes.")
        project_dir = os.path.abspath(os.path.dirname(__file__))
        export_path = os.path.join(project_dir, "auth_portal_all_dump.csv")
    
        if st.button("Export user database to CSV"):
            try:
                rows_written = 0
                with sqlite3.connect(DB_PATH, check_same_thread=False) as conn:
                    cur = conn.execute("SELECT username, salt, hash, iterations, created_at FROM users")
                    with open(export_path, "w", newline='', encoding="utf-8") as f:
                        writer = csv.writer(f)
                        writer.writerow(["username", "salt_base64", "hash_hex", "iterations", "created_at"])
                        for r in cur.fetchall():
                            username = r[0]
                            salt_b64 = base64.b64encode(r[1]).decode("utf-8")
                            hash_hex = r[2].hex()
                            writer.writerow([username, salt_b64, hash_hex, r[3], r[4]])
                            rows_written += 1
                st.success(f"Exported {rows_written} rows to {os.path.basename(export_path)}")
    
                # Download button for the teacher
                with open(export_path, "rb") as f:
                    data = f.read()
                st.download_button(
                    "Download CSV (view salted hashes)",
                    data,
                    file_name=os.path.basename(export_path),
                    mime="text/csv"
                )
            except Exception as e:
                st.error(f"Export failed: {e}")
#------------LOG IN------------
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

# ---------- FOOTER ----------
st.markdown('<p class="footer-note">© BMS Institute of Technology & Management • Yelahanka, Bengaluru</p>', unsafe_allow_html=True)
