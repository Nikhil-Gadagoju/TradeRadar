import streamlit as st
import yfinance as yf
import pandas as pd
import numpy as np
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import os
import hashlib
import secrets
from streamlit_autorefresh import st_autorefresh

st.set_page_config(page_title="TradeRadar", page_icon="📡", layout="wide")

# ══════════════════════════════════════════════════════════════════════════════
# CONFIG (API keys etc.)
# ══════════════════════════════════════════════════════════════════════════════
_APP_DIR   = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(_APP_DIR, "config.json")

def load_config() -> dict:
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_config(cfg: dict):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)

# ══════════════════════════════════════════════════════════════════════════════
# SESSION TOKENS  (persist login across browser refresh)
# ══════════════════════════════════════════════════════════════════════════════
SESSIONS_FILE          = os.path.join(_APP_DIR, "sessions.json")
SESSION_TIMEOUT_DAYS   = 7   # inactivity timeout — change to taste

from datetime import datetime, timedelta, timezone as _tz

def _now_iso() -> str:
    return datetime.now(_tz.utc).isoformat()

def _load_sessions() -> dict:
    if os.path.exists(SESSIONS_FILE):
        try:
            with open(SESSIONS_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {"sessions": {}}

def _save_sessions(data: dict):
    with open(SESSIONS_FILE, "w") as f:
        json.dump(data, f, indent=2)

def _create_session(username: str) -> str:
    """Generate a token, store it server-side, return it."""
    token    = secrets.token_urlsafe(32)
    sessions = _load_sessions()
    expiry   = (datetime.now(_tz.utc) + timedelta(days=SESSION_TIMEOUT_DAYS)).isoformat()
    sessions["sessions"][token] = {
        "username":  username,
        "created":   _now_iso(),
        "last_seen": _now_iso(),
        "expires":   expiry,
    }
    # Prune expired tokens while we're here
    now = _now_iso()
    sessions["sessions"] = {t: s for t, s in sessions["sessions"].items()
                            if s["expires"] > now}
    _save_sessions(sessions)
    return token

def _validate_session(token: str):
    """
    Return (username, user_rec) if valid; (None, None) if expired/missing.
    Refreshes the expiry window on each valid call (sliding timeout).
    """
    sessions = _load_sessions()
    session  = sessions["sessions"].get(token)
    if not session:
        return None, None
    if session["expires"] < _now_iso():
        sessions["sessions"].pop(token, None)
        _save_sessions(sessions)
        return None, None
    # Slide the expiry forward
    session["last_seen"] = _now_iso()
    session["expires"]   = (datetime.now(_tz.utc) + timedelta(days=SESSION_TIMEOUT_DAYS)).isoformat()
    sessions["sessions"][token] = session
    _save_sessions(sessions)
    users_db = _load_users()
    username = session["username"]
    user_rec = users_db["users"].get(username)
    return username, user_rec

def _delete_session(token: str):
    sessions = _load_sessions()
    sessions["sessions"].pop(token, None)
    _save_sessions(sessions)

# ══════════════════════════════════════════════════════════════════════════════
# AUTH SYSTEM
# ══════════════════════════════════════════════════════════════════════════════
USERS_FILE = os.path.join(_APP_DIR, "users.json")

def _hash_password(password: str, salt: str = None):
    """Return (hash_hex, salt). Uses PBKDF2-HMAC-SHA256 with 260k iterations."""
    if salt is None:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return key.hex(), salt

def _verify_password(password: str, stored_hash: str, salt: str) -> bool:
    computed, _ = _hash_password(password, salt)
    return secrets.compare_digest(computed, stored_hash)

def _load_users() -> dict:
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    # First run — create default admin account
    pwd_hash, salt = _hash_password("admin123")
    default = {"users": {"admin": {"name": "Admin", "hash": pwd_hash, "salt": salt, "role": "admin"}}}
    with open(USERS_FILE, "w") as f:
        json.dump(default, f, indent=2)
    return default

def _save_users(data: dict):
    with open(USERS_FILE, "w") as f:
        json.dump(data, f, indent=2)

def _show_login():
    """Full-page login form. Stops the app if credentials are wrong."""
    # Centre the card
    _, col, _ = st.columns([1, 1.2, 1])
    with col:
        st.markdown("""
<div style="border:1px solid #333;border-radius:14px;padding:36px 32px;
            background:#111;margin-top:60px;text-align:center;">
  <div style="font-size:2.4em;margin-bottom:4px;">📈</div>
  <div style="font-size:1.5em;font-weight:bold;margin-bottom:2px;">Stock Analyzer</div>
  <div style="color:#888;font-size:0.85em;margin-bottom:24px;">Sign in to your account</div>
</div>
""", unsafe_allow_html=True)

        with st.form("login_form"):
            username = st.text_input("Username", placeholder="Enter your username")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            submitted = st.form_submit_button("Sign In", use_container_width=True, type="primary")

        if submitted:
            users_db = _load_users()
            ukey     = username.lower().strip()
            user_rec = users_db["users"].get(ukey)
            if user_rec and _verify_password(password, user_rec["hash"], user_rec["salt"]):
                token = _create_session(ukey)
                st.session_state["logged_in"]      = True
                st.session_state["username"]       = ukey
                st.session_state["user_name"]      = user_rec["name"]
                st.session_state["user_role"]      = user_rec["role"]
                st.session_state["session_token"]  = token
                st.query_params["t"] = token
                st.rerun()
            elif submitted:
                st.error("Incorrect username or password.")

        st.markdown("<div style='text-align:center;color:#555;font-size:0.78em;margin-top:16px;'>Not financial advice · Data from Yahoo Finance</div>",
                    unsafe_allow_html=True)

def _check_auth():
    """
    Gate the app. Returns only if the user is authenticated.
    Priority:
      1. session_state already set (same Streamlit session, no refresh)
      2. URL token ?t=<token> — validates server-side, restores session after refresh
      3. Show login form
    """
    if st.session_state.get("logged_in"):
        return

    # Try to restore from URL token
    token = st.query_params.get("t", "")
    if token:
        username, user_rec = _validate_session(token)
        if user_rec:
            st.session_state["logged_in"]     = True
            st.session_state["username"]      = username
            st.session_state["user_name"]     = user_rec["name"]
            st.session_state["user_role"]     = user_rec["role"]
            st.session_state["session_token"] = token
            return
        else:
            # Token expired or invalid — clear it and force login
            st.query_params.clear()

    _show_login()
    st.stop()

def _show_user_management():
    """Admin-only page to add/delete users and reset passwords."""
    st.markdown("## 👥 User Management")
    st.caption("Admin only · Changes saved immediately to users.json on the server")

    users_db = _load_users()
    users    = users_db["users"]

    # Current users table
    st.subheader("Current Users")
    rows = [{"Username": u, "Display Name": v["name"], "Role": v["role"]}
            for u, v in users.items()]
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    st.markdown("---")
    # Add new user
    st.subheader("➕ Add New User")
    with st.form("add_user_form", clear_on_submit=True):
        nc1, nc2, nc3, nc4 = st.columns([2, 2, 2, 1])
        nu_user  = nc1.text_input("Username")
        nu_name  = nc2.text_input("Display Name")
        nu_pass  = nc3.text_input("Password", type="password")
        nu_role  = nc4.selectbox("Role", ["viewer", "admin"])
        if st.form_submit_button("Add User", type="primary"):
            ukey = nu_user.lower().strip()
            if not ukey or not nu_pass:
                st.error("Username and password are required.")
            elif ukey in users:
                st.error(f"Username '{ukey}' already exists.")
            else:
                h, s = _hash_password(nu_pass)
                users[ukey] = {"name": nu_name or nu_user, "hash": h, "salt": s, "role": nu_role}
                _save_users(users_db)
                st.success(f"User '{ukey}' created.")
                st.rerun()

    st.markdown("---")
    # Reset / change password
    st.subheader("🔑 Reset a User's Password")
    with st.form("reset_pw_form", clear_on_submit=True):
        rp1, rp2 = st.columns([2, 2])
        rp_user = rp1.selectbox("User", list(users.keys()))
        rp_pass = rp2.text_input("New Password", type="password")
        if st.form_submit_button("Reset Password"):
            if not rp_pass:
                st.error("Password cannot be empty.")
            else:
                h, s = _hash_password(rp_pass)
                users[rp_user]["hash"] = h
                users[rp_user]["salt"] = s
                _save_users(users_db)
                st.success(f"Password updated for '{rp_user}'.")

    st.markdown("---")
    # Delete user
    st.subheader("🗑️ Delete a User")
    del_candidates = [u for u in users if u != st.session_state.get("username")]
    if del_candidates:
        with st.form("del_user_form"):
            du1, du2 = st.columns([3, 1])
            del_user = du1.selectbox("Select user to delete", del_candidates)
            if du2.form_submit_button("Delete", type="secondary"):
                del users[del_user]
                _save_users(users_db)
                st.success(f"User '{del_user}' deleted.")
                st.rerun()
    else:
        st.info("No other users to delete.")

    # ── Claude API key ────────────────────────────────────────────────────────
    st.markdown("---")
    st.subheader("🤖 Claude AI Settings")
    cfg = load_config()
    cur_key = cfg.get("claude_api_key", "")
    with st.form("claude_key_form"):
        new_key = st.text_input(
            "Claude API Key",
            value=cur_key,
            type="password",
            placeholder="sk-ant-...",
            help="Get your key at console.anthropic.com",
        )
        if st.form_submit_button("Save API Key", type="primary"):
            if new_key.strip():
                cfg["claude_api_key"] = new_key.strip()
                save_config(cfg)
                st.success("API key saved.")
            else:
                st.error("Key cannot be empty.")
    if cur_key:
        st.caption(f"Key on file: `{cur_key[:10]}...{cur_key[-4:]}` · AI chat is **enabled**")
    else:
        st.warning("No API key set — AI chat will not be available until an admin adds one.")


def _show_change_password():
    """Let any logged-in user change their own password."""
    st.markdown("## 🔑 Change Password")
    with st.form("change_pw_form", clear_on_submit=True):
        cur_pw  = st.text_input("Current password", type="password")
        new_pw  = st.text_input("New password",     type="password")
        new_pw2 = st.text_input("Confirm new password", type="password")
        if st.form_submit_button("Update Password", type="primary"):
            users_db = _load_users()
            ukey     = st.session_state["username"]
            rec      = users_db["users"].get(ukey)
            if not rec or not _verify_password(cur_pw, rec["hash"], rec["salt"]):
                st.error("Current password is incorrect.")
            elif new_pw != new_pw2:
                st.error("New passwords don't match.")
            elif len(new_pw) < 6:
                st.error("Password must be at least 6 characters.")
            else:
                h, s = _hash_password(new_pw)
                rec["hash"] = h
                rec["salt"] = s
                _save_users(users_db)
                st.success("Password updated successfully!")

# ══════════════════════════════════════════════════════════════════════════════
# AI CHAT
# ══════════════════════════════════════════════════════════════════════════════
def _get_claude_key() -> str:
    return load_config().get("claude_api_key", "")


def show_ai_chat(system_context: str = "", chat_key: str = "general"):
    """
    Render a Claude-powered chat panel.
    system_context — extra stock/portfolio data injected into the system prompt.
    chat_key       — unique key so each stock has its own history.
    """
    api_key = _get_claude_key()
    if not api_key:
        st.warning("AI chat is disabled — an admin must add the Claude API key in 👥 Users settings.")
        return

    import anthropic as _anthropic

    state_key = f"ai_messages_{chat_key}"
    if state_key not in st.session_state:
        st.session_state[state_key] = []

    messages = st.session_state[state_key]

    system_prompt = (
        "You are an expert stock market analyst and investment advisor assistant embedded in a personal "
        "stock analysis app. You have deep knowledge of technical analysis, fundamental analysis, "
        "options strategies, dividend investing, portfolio management, and risk management.\n\n"
        "Be concise and direct. Use bullet points where helpful. Always remind the user that this is "
        "not financial advice and they should consult a professional for major decisions.\n\n"
    )
    if system_context:
        system_prompt += f"CURRENT STOCK CONTEXT:\n{system_context}\n\n"
    system_prompt += (
        "Use the context above when answering questions. If asked about the specific stock, "
        "refer to the live data provided. You may also discuss general investing concepts."
    )

    # Render chat history
    for msg in messages:
        with st.chat_message(msg["role"], avatar="🤖" if msg["role"] == "assistant" else "👤"):
            st.markdown(msg["content"])

    # Input
    user_input = st.chat_input("Ask Claude about this stock, your position, strategy…")
    if user_input:
        messages.append({"role": "user", "content": user_input})
        with st.chat_message("user", avatar="👤"):
            st.markdown(user_input)

        with st.chat_message("assistant", avatar="🤖"):
            with st.spinner("Claude is thinking…"):
                try:
                    client = _anthropic.Anthropic(api_key=api_key)
                    response = client.messages.create(
                        model="claude-sonnet-4-6",
                        max_tokens=1024,
                        system=system_prompt,
                        messages=[{"role": m["role"], "content": m["content"]} for m in messages],
                    )
                    reply = response.content[0].text
                except Exception as e:
                    reply = f"⚠️ Error calling Claude API: {e}"

            st.markdown(reply)
            messages.append({"role": "assistant", "content": reply})
            st.session_state[state_key] = messages

    if messages:
        if st.button("🗑️ Clear chat", key=f"clear_{chat_key}"):
            st.session_state[state_key] = []
            st.rerun()


def show_ai_chat_page():
    """Standalone AI chat page — no specific stock context."""
    st.markdown("## 🤖 AI Stock Chat")
    st.caption("Ask Claude anything about stocks, investing, strategy, or your portfolio")
    portfolio  = load_portfolio()
    holdings   = portfolio.get("holdings", [])
    port_ctx   = ""
    if holdings:
        port_ctx = "USER'S PORTFOLIO:\n"
        for h in holdings:
            port_ctx += f"  - {h['ticker']}: {h['shares']} shares @ avg ${h['avg_cost']:.2f} (bought {h.get('date_added','')})\n"
    show_ai_chat(system_context=port_ctx, chat_key="general_page")


# ── Gate: must be logged in to see anything below ─────────────────────────────
_check_auth()

# ── App title (shown only after login) ────────────────────────────────────────
st.title("📡 TradeRadar")
st.caption("Type a ticker (AAPL), company name (Apple), or sector (Technology). Not financial advice.")

# ── Sector definitions ──────────────────────────────────────────────────────
SECTORS = {
    "technology":    {"name": "Technology",        "etf": "XLK",  "tickers": ["AAPL","MSFT","NVDA","GOOGL","META","AMZN","AMD","INTC","CRM","ORCL"]},
    "healthcare":    {"name": "Healthcare",         "etf": "XLV",  "tickers": ["JNJ","UNH","LLY","PFE","ABBV","MRK","TMO","ABT","CVS","BMY"]},
    "finance":       {"name": "Financials",         "etf": "XLF",  "tickers": ["JPM","BAC","WFC","GS","MS","C","BLK","AXP","V","MA"]},
    "financial":     {"name": "Financials",         "etf": "XLF",  "tickers": ["JPM","BAC","WFC","GS","MS","C","BLK","AXP","V","MA"]},
    "energy":        {"name": "Energy",             "etf": "XLE",  "tickers": ["XOM","CVX","COP","EOG","SLB","PXD","MPC","PSX","VLO","OXY"]},
    "consumer":      {"name": "Consumer",           "etf": "XLY",  "tickers": ["AMZN","HD","MCD","NKE","SBUX","TGT","COST","WMT","LOW","TJX"]},
    "retail":        {"name": "Consumer",           "etf": "XLY",  "tickers": ["AMZN","HD","MCD","NKE","SBUX","TGT","COST","WMT","LOW","TJX"]},
    "industrial":    {"name": "Industrials",        "etf": "XLI",  "tickers": ["HON","UPS","CAT","DE","GE","MMM","RTX","LMT","BA","FDX"]},
    "utilities":     {"name": "Utilities",          "etf": "XLU",  "tickers": ["NEE","DUK","SO","D","AEP","EXC","SRE","XEL","ED","ES"]},
    "real estate":   {"name": "Real Estate",        "etf": "XLRE", "tickers": ["AMT","PLD","CCI","EQIX","PSA","O","WELL","SPG","DLR","AVB"]},
    "realestate":    {"name": "Real Estate",        "etf": "XLRE", "tickers": ["AMT","PLD","CCI","EQIX","PSA","O","WELL","SPG","DLR","AVB"]},
    "materials":     {"name": "Materials",          "etf": "XLB",  "tickers": ["LIN","APD","ECL","SHW","FCX","NEM","VMC","MLM","NUE","CTVA"]},
    "communication": {"name": "Communication Svcs", "etf": "XLC",  "tickers": ["GOOGL","META","NFLX","DIS","CMCSA","T","VZ","TMUS","CHTR","PARA"]},
    "telecom":       {"name": "Communication Svcs", "etf": "XLC",  "tickers": ["GOOGL","META","NFLX","DIS","CMCSA","T","VZ","TMUS","CHTR","PARA"]},
    "pharma":        {"name": "Healthcare",         "etf": "XLV",  "tickers": ["JNJ","LLY","PFE","ABBV","MRK","BMY","GILD","REGN","BIIB","VRTX"]},
    "semiconductor": {"name": "Semiconductors",     "etf": "SOXX", "tickers": ["NVDA","AMD","INTC","QCOM","AVGO","MU","AMAT","LRCX","KLAC","TXN"]},
    "chip":          {"name": "Semiconductors",     "etf": "SOXX", "tickers": ["NVDA","AMD","INTC","QCOM","AVGO","MU","AMAT","LRCX","KLAC","TXN"]},
    "bank":          {"name": "Banks",              "etf": "KBE",  "tickers": ["JPM","BAC","WFC","C","GS","MS","USB","PNC","TFC","COF"]},
    "banking":       {"name": "Banks",              "etf": "KBE",  "tickers": ["JPM","BAC","WFC","C","GS","MS","USB","PNC","TFC","COF"]},
    "ev":            {"name": "Electric Vehicles",  "etf": "DRIV", "tickers": ["TSLA","RIVN","LCID","NIO","LI","XPEV","GM","F","STLA","FSR"]},
    "electric vehicle": {"name": "Electric Vehicles","etf": "DRIV","tickers": ["TSLA","RIVN","LCID","NIO","LI","XPEV","GM","F","STLA","FSR"]},
    "ai":            {"name": "Artificial Intelligence","etf": "AIQ","tickers": ["NVDA","MSFT","GOOGL","META","AMZN","AMD","CRM","PLTR","SNPS","CDNS"]},
    "artificial intelligence": {"name": "AI",      "etf": "AIQ",  "tickers": ["NVDA","MSFT","GOOGL","META","AMZN","AMD","CRM","PLTR","SNPS","CDNS"]},
    "cloud":         {"name": "Cloud Computing",    "etf": "SKYY", "tickers": ["MSFT","AMZN","GOOGL","CRM","SNOW","NOW","WDAY","MDB","DDOG","ZS"]},
    "cybersecurity": {"name": "Cybersecurity",      "etf": "HACK", "tickers": ["CRWD","ZS","PANW","FTNT","OKTA","S","CYBR","TENB","QLYS","VRNS"]},
}

# ── Input resolution ─────────────────────────────────────────────────────────
def resolve_sector(query: str):
    q = query.lower().strip().rstrip("s")
    for key, data in SECTORS.items():
        if q == key or q in key or key in q:
            return data
    return None

def resolve_portfolio(query: str) -> bool:
    q = query.lower().strip()
    return any(k in q for k in ["portfolio", "my stocks", "my holdings", "holdings", "my portfolio", "positions", "my position"])

def resolve_dividend(query: str) -> bool:
    """Returns True if the user is asking about dividend / income stocks."""
    q = query.lower().strip()
    keywords = ["dividend", "income", "yield", "dividend stock", "dividend king",
                "dividend aristocrat", "high yield", "reit", "passive income"]
    return any(k in q for k in keywords)

@st.cache_data(ttl=600, show_spinner=False)
def search_ticker(query: str) -> str:
    query = query.strip()
    if query.upper() == query and len(query) <= 5:
        return query.upper()
    try:
        results = yf.Search(query, max_results=5).quotes
        if results:
            for r in results:
                if r.get("quoteType") == "EQUITY":
                    return r["symbol"]
            return results[0]["symbol"]
    except Exception:
        pass
    return query.upper()

# ── Technical indicators ──────────────────────────────────────────────────────
def calculate_indicators(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    # Moving averages
    df["SMA_20"] = df["Close"].rolling(20).mean()
    df["SMA_50"] = df["Close"].rolling(50).mean()
    df["EMA_12"] = df["Close"].ewm(span=12, adjust=False).mean()
    df["EMA_26"] = df["Close"].ewm(span=26, adjust=False).mean()
    # MACD
    df["MACD"] = df["EMA_12"] - df["EMA_26"]
    df["Signal_Line"] = df["MACD"].ewm(span=9, adjust=False).mean()
    df["MACD_Hist"] = df["MACD"] - df["Signal_Line"]
    # RSI
    delta = df["Close"].diff()
    gain  = delta.clip(lower=0)
    loss  = -delta.clip(upper=0)
    df["RSI"] = 100 - (100 / (1 + gain.rolling(14).mean() / loss.rolling(14).mean()))
    # Bollinger Bands
    std = df["Close"].rolling(20).std()
    df["BB_mid"]   = df["Close"].rolling(20).mean()
    df["BB_upper"] = df["BB_mid"] + 2 * std
    df["BB_lower"] = df["BB_mid"] - 2 * std
    # ATR (14-day)
    hl  = df["High"] - df["Low"]
    hc  = (df["High"] - df["Close"].shift()).abs()
    lc  = (df["Low"]  - df["Close"].shift()).abs()
    df["ATR"] = pd.concat([hl, hc, lc], axis=1).max(axis=1).rolling(14).mean()
    # Volume MA + confirmation flag
    df["Vol_MA20"] = df["Volume"].rolling(20).mean()
    df["Vol_Ratio"] = df["Volume"] / df["Vol_MA20"].replace(0, np.nan)
    # 5-day Rate of Change
    df["ROC_5"] = df["Close"].pct_change(5) * 100
    # MACD histogram direction (rising = bullish momentum)
    df["MACD_Rising"] = df["MACD_Hist"] > df["MACD_Hist"].shift(1)
    return df


def _news_sentiment_score(ticker: str):
    """
    Keyword-based news sentiment with category weighting.
    Categories: earnings, M&A, legal/regulatory, macro, general.
    Returns (score, detail_str). score: -2 to +2
    """
    try:
        news = yf.Ticker(ticker).news or []
        headlines = [n.get("title", "").lower() for n in news[:15]]
        if not headlines:
            return 0, "No recent news found"

        score = 0
        flags = []

        # High-impact: earnings beat/miss in news
        earnings_pos = ["beat", "topped", "exceeded expectations", "record earnings", "earnings beat", "eps beat", "profit surge"]
        earnings_neg = ["missed", "earnings miss", "eps miss", "profit warning", "cut guidance", "lowered outlook", "revenue miss"]

        # M&A signals
        ma_pos = ["acquisition", "merger", "buyout", "takeover bid", "deal", "acquired by", "strategic partnership"]
        ma_neg = ["breakup", "deal collapses", "failed merger", "antitrust block", "rejected bid"]

        # Legal / regulatory
        legal_neg = ["lawsuit", "sec investigation", "fraud", "fine", "penalty", "class action", "regulatory ban",
                     "doj probe", "subpoena", "criminal charges", "fda rejection", "recall"]
        legal_pos = ["fda approval", "cleared", "settlement reached", "charges dropped", "won lawsuit"]

        # Macro / market
        macro_pos = ["rate cut", "fed pivot", "stimulus", "strong gdp", "soft landing"]
        macro_neg = ["rate hike", "recession", "tariff", "inflation surge", "fed tightening", "geopolitical"]

        # General bullish/bearish
        gen_pos = ["upgrade", "buy rating", "outperform", "strong buy", "price target raised", "bullish", "rally", "soar", "surge"]
        gen_neg = ["downgrade", "sell rating", "underperform", "price target cut", "bearish", "plunge", "crash", "layoff", "bankruptcy"]

        for h in headlines:
            if any(w in h for w in earnings_pos):  score += 2; flags.append("Earnings beat signal")
            if any(w in h for w in earnings_neg):  score -= 2; flags.append("Earnings miss/warning signal")
            if any(w in h for w in ma_pos):        score += 1; flags.append("M&A / deal activity")
            if any(w in h for w in ma_neg):        score -= 1; flags.append("Deal breakdown / blocked")
            if any(w in h for w in legal_neg):     score -= 2; flags.append("Legal / regulatory risk")
            if any(w in h for w in legal_pos):     score += 1; flags.append("Legal / regulatory positive")
            if any(w in h for w in macro_pos):     score += 1; flags.append("Macro tailwind")
            if any(w in h for w in macro_neg):     score -= 1; flags.append("Macro headwind")
            if any(w in h for w in gen_pos):       score += 1; flags.append("Analyst upgrade / bullish coverage")
            if any(w in h for w in gen_neg):       score -= 1; flags.append("Analyst downgrade / bearish coverage")

        score = max(-2, min(2, score))
        unique_flags = list(dict.fromkeys(flags))[:3]  # top 3 unique
        detail = (", ".join(unique_flags) if unique_flags else "No significant news events") + f" (score {score:+d})"
        lbl_map = {2: "strongly bullish", 1: "bullish", 0: "neutral", -1: "bearish", -2: "strongly bearish"}
        return score, f"News {lbl_map.get(score, 'neutral')}: {detail}"
    except Exception:
        return 0, "News sentiment unavailable"


def _earnings_signal(ticker: str, info: dict):
    """
    Two signals:
    1. Upcoming earnings — flag as volatility event (±1 if within 14 days)
    2. Last earnings surprise — beat (+1) or miss (-1)
    Returns (score, detail_str)
    """
    from datetime import datetime, timezone as _tz2
    score, parts = 0, []
    try:
        stock = yf.Ticker(ticker)

        # Upcoming earnings date
        ed = info.get("earningsTimestamp") or info.get("earningsDate")
        if ed:
            if isinstance(ed, (list, tuple)):
                ed = ed[0]
            # Convert timestamp int to datetime if needed
            if isinstance(ed, (int, float)):
                ed_dt = datetime.fromtimestamp(ed, tz=_tz2.utc)
            else:
                ed_dt = ed
            days_away = (ed_dt - datetime.now(_tz2.utc)).days
            if 0 <= days_away <= 7:
                score += 1
                parts.append(f"⚡ Earnings in {days_away}d — high volatility expected, consider sizing down")
            elif 8 <= days_away <= 14:
                parts.append(f"📅 Earnings in {days_away}d — watch for guidance changes")

        # Earnings surprise from financials
        try:
            earnings_hist = stock.earnings_history
            if earnings_hist is not None and not earnings_hist.empty:
                latest_e = earnings_hist.iloc[-1]
                surprise_pct = latest_e.get("surprisePercent", None)
                if surprise_pct is not None:
                    if surprise_pct > 5:
                        score += 1
                        parts.append(f"Last earnings beat by {surprise_pct:.1f}% — strong execution")
                    elif surprise_pct < -5:
                        score -= 1
                        parts.append(f"Last earnings missed by {abs(surprise_pct):.1f}% — execution concern")
                    else:
                        parts.append(f"Last earnings in line ({surprise_pct:+.1f}% surprise)")
        except Exception:
            pass

        detail = " · ".join(parts) if parts else "No earnings event data"
        return max(-1, min(1, score)), detail
    except Exception:
        return 0, "Earnings data unavailable"


def _macro_regime_score():
    """
    Market regime filter using VIX + S&P 500 trend.
    Returns (score, detail_str). score: -2 (risk-off) to +1 (risk-on)
    Penalises BUY signals in high-fear / downtrending markets.
    """
    try:
        import yfinance as _yf
        vix_hist  = _yf.download("^VIX",  period="1mo", interval="1d", progress=False, auto_adjust=True)
        spy_hist  = _yf.download("SPY",   period="3mo", interval="1d", progress=False, auto_adjust=True)

        parts, score = [], 0

        # VIX level
        if not vix_hist.empty:
            vix = float(vix_hist["Close"].iloc[-1])
            if vix > 35:
                score -= 2; parts.append(f"VIX={vix:.1f} — extreme fear, market highly unstable")
            elif vix > 25:
                score -= 1; parts.append(f"VIX={vix:.1f} — elevated fear, caution warranted")
            elif vix < 15:
                score += 1; parts.append(f"VIX={vix:.1f} — low fear, calm market conditions")
            else:
                parts.append(f"VIX={vix:.1f} — moderate volatility")

        # S&P 500 trend (20-day vs 50-day SMA)
        if not spy_hist.empty and len(spy_hist) >= 50:
            spy_close = spy_hist["Close"]
            sma20 = float(spy_close.iloc[-20:].mean())
            sma50 = float(spy_close.iloc[-50:].mean())
            spy_now = float(spy_close.iloc[-1])
            if spy_now < sma20 and sma20 < sma50:
                score -= 1; parts.append("S&P 500 in downtrend (price < SMA20 < SMA50) — broad market headwind")
            elif spy_now > sma20 and sma20 > sma50:
                parts.append("S&P 500 in uptrend — broad market tailwind")
            else:
                parts.append("S&P 500 mixed trend")

        score = max(-2, min(1, score))
        return score, "Macro: " + " · ".join(parts)
    except Exception:
        return 0, "Macro regime data unavailable"


def _short_interest_score(info: dict):
    """
    High short interest = contrarian squeeze potential (bullish) OR justified bearish conviction.
    Returns (score, detail_str). Combines with other signals for context.
    """
    try:
        short_pct = info.get("shortPercentOfFloat")  # e.g. 0.15 = 15%
        short_ratio = info.get("shortRatio")          # days to cover
        if short_pct is None:
            return 0, "Short interest data unavailable"

        pct = short_pct * 100
        parts = [f"Short interest: {pct:.1f}% of float"]
        score = 0

        if short_ratio:
            parts.append(f"{short_ratio:.1f} days to cover")

        if pct > 25:
            score += 1  # high squeeze potential
            parts.append("— very high short interest, squeeze risk elevated (contrarian bullish)")
        elif pct > 15:
            parts.append("— elevated short interest, watch for short squeeze")
        elif pct < 3:
            parts.append("— low short interest, no squeeze catalyst")

        return score, " ".join(parts)
    except Exception:
        return 0, "Short interest data unavailable"


def _insider_activity_score(ticker: str):
    """
    Recent insider buying = bullish signal. Insider selling = mild bearish.
    Returns (score, detail_str)
    """
    try:
        stock = yf.Ticker(ticker)
        insiders = stock.insider_transactions
        if insiders is None or insiders.empty:
            return 0, "No recent insider activity"

        recent = insiders.head(10)
        buys  = recent[recent["Text"].str.contains("Purchase|Buy", case=False, na=False)]
        sells = recent[recent["Text"].str.contains("Sale|Sell", case=False, na=False)]

        if len(buys) > len(sells) and len(buys) >= 2:
            return 1, f"Insider buying: {len(buys)} recent purchases vs {len(sells)} sales — insiders bullish on own stock"
        elif len(sells) > len(buys) + 2:
            return -1, f"Insider selling: {len(sells)} recent sales vs {len(buys)} purchases — insiders reducing exposure"
        elif len(buys) >= 1:
            return 0, f"Mixed insider activity: {len(buys)} buys, {len(sells)} sells"
        else:
            return 0, f"Mostly insider selling ({len(sells)} sales) — typical for comp/tax planning"
    except Exception:
        return 0, "Insider activity data unavailable"


def _fundamentals_score(info: dict):
    """
    Score based on valuation + earnings health. Returns (score, signals_list).
    score range: -2 to +2
    """
    fsigs, fscore = [], 0
    pe  = info.get("trailingPE")
    fpe = info.get("forwardPE")
    eg  = info.get("earningsGrowth")   # e.g. 0.15 = 15%
    rg  = info.get("revenueGrowth")    # e.g. 0.10 = 10%
    de  = info.get("debtToEquity")     # e.g. 50 = 50%
    peg = info.get("pegRatio")

    # P/E vs forward P/E — earnings expansion signal
    if pe and fpe and fpe > 0 and pe > 0:
        if fpe < pe * 0.85:
            fsigs.append(("Fundamentals", "🟢 BUY", f"Forward P/E ({fpe:.1f}) well below trailing ({pe:.1f}) — earnings expected to grow significantly"))
            fscore += 1
        elif fpe > pe * 1.15:
            fsigs.append(("Fundamentals", "🔴 SELL", f"Forward P/E ({fpe:.1f}) above trailing ({pe:.1f}) — earnings expected to shrink"))
            fscore -= 1

    # PEG ratio (growth-adjusted value)
    if peg and peg > 0:
        if peg < 1.0:
            fsigs.append(("Fundamentals", "🟢 BUY", f"PEG ratio {peg:.2f} < 1.0 — undervalued relative to growth"))
            fscore += 1
        elif peg > 2.5:
            fsigs.append(("Fundamentals", "🔴 SELL", f"PEG ratio {peg:.2f} > 2.5 — expensive relative to growth"))
            fscore -= 1

    # Earnings growth
    if eg is not None:
        if eg > 0.15:
            fsigs.append(("Earnings Growth", "🟢 BUY", f"YoY earnings growth {eg*100:.1f}% — strong expansion"))
            fscore += 1
        elif eg < -0.10:
            fsigs.append(("Earnings Growth", "🔴 SELL", f"YoY earnings growth {eg*100:.1f}% — earnings contracting"))
            fscore -= 1
        else:
            fsigs.append(("Earnings Growth", "⚪ NEUTRAL", f"YoY earnings growth {eg*100:.1f}%"))

    # Revenue growth
    if rg is not None:
        if rg > 0.10:
            fsigs.append(("Revenue Growth", "🟢 BUY", f"Revenue growing {rg*100:.1f}% YoY — business expanding"))
            fscore += 1
        elif rg < -0.05:
            fsigs.append(("Revenue Growth", "🔴 SELL", f"Revenue shrinking {rg*100:.1f}% YoY — business contracting"))
            fscore -= 1

    # Debt health
    if de is not None:
        if de > 200:
            fsigs.append(("Debt/Equity", "🔴 SELL", f"Debt/Equity = {de:.0f}% — highly leveraged, risk elevated"))
            fscore -= 1
        elif de < 50:
            fsigs.append(("Debt/Equity", "🟢 BUY", f"Debt/Equity = {de:.0f}% — low debt, financially healthy"))
            fscore += 1

    fscore = max(-2, min(2, fscore))
    return fscore, fsigs


def _options_sentiment_score(ticker: str, current_price: float):
    """
    Put/Call ratio from nearest options expiry. Returns (score, detail_str).
    score: +1 (bullish — calls dominate), -1 (bearish — puts dominate), 0 (neutral)
    """
    try:
        stock   = yf.Ticker(ticker)
        expiries = stock.options
        if not expiries:
            return 0, "Options data unavailable"
        chain   = stock.option_chain(expiries[0])
        call_vol = chain.calls["volume"].sum()
        put_vol  = chain.puts["volume"].sum()
        if call_vol + put_vol < 100:
            return 0, "Options volume too low to score"
        pc_ratio = put_vol / call_vol if call_vol > 0 else 99
        if pc_ratio < 0.6:
            return 1, f"Options flow bullish — P/C ratio {pc_ratio:.2f} (calls dominating, smart money buying)"
        elif pc_ratio > 1.4:
            return -1, f"Options flow bearish — P/C ratio {pc_ratio:.2f} (puts dominating, smart money hedging)"
        else:
            return 0, f"Options flow neutral — P/C ratio {pc_ratio:.2f}"
    except Exception:
        return 0, "Options data unavailable"


def _sector_momentum_score(ticker: str, info: dict, df: pd.DataFrame):
    """
    Compare 20-day stock return vs sector ETF. Returns (score, detail_str).
    score: +1 (outperforming), -1 (underperforming), 0 (neutral/unavailable)
    """
    SECTOR_ETF = {
        "Technology": "XLK", "Financial Services": "XLF", "Financials": "XLF",
        "Healthcare": "XLV", "Consumer Cyclical": "XLY", "Consumer Defensive": "XLP",
        "Energy": "XLE", "Industrials": "XLI", "Basic Materials": "XLB",
        "Real Estate": "XLRE", "Utilities": "XLU", "Communication Services": "XLC",
    }
    sector = info.get("sector", "")
    etf    = SECTOR_ETF.get(sector)
    if not etf:
        return 0, f"Sector momentum unavailable (sector: {sector or 'unknown'})"
    try:
        etf_hist = yf.download(etf, period="2mo", interval="1d", progress=False, auto_adjust=True)
        if etf_hist.empty or len(etf_hist) < 20:
            return 0, "Sector ETF data unavailable"
        etf_ret  = (etf_hist["Close"].iloc[-1] - etf_hist["Close"].iloc[-20]) / etf_hist["Close"].iloc[-20] * 100
        stk_ret  = (df["Close"].iloc[-1] - df["Close"].iloc[-20]) / df["Close"].iloc[-20] * 100
        diff     = float(stk_ret) - float(etf_ret)
        if diff > 3:
            return 1, f"Outperforming {sector} sector ({etf}) by {diff:+.1f}% over 20 days — relative strength"
        elif diff < -3:
            return -1, f"Underperforming {sector} sector ({etf}) by {diff:+.1f}% over 20 days — relative weakness"
        else:
            return 0, f"In line with {sector} sector ({etf}), {diff:+.1f}% relative to sector"
    except Exception:
        return 0, "Sector momentum unavailable"


def generate_signal(df: pd.DataFrame, info: dict = None, ticker: str = ""):
    """
    Score each stock across 10 criteria. Max score ~+16, min ~-16.
    Technical (6 factors) + Fundamentals + News Sentiment + Options Flow + Sector Momentum.
    """
    if len(df) < 30:
        return [], "HOLD", "gray", 0

    latest = df.iloc[-1]
    prev   = df.iloc[-2]
    signals, score = [], 0

    # ── 1. RSI (max ±3) ─────────────────────────────────────────────────────
    rsi = latest["RSI"]
    if rsi < 30:
        signals.append(("RSI", "🟢 STRONG BUY", f"RSI={rsi:.1f} — deeply oversold (< 30)"))
        score += 3
    elif rsi < 40:
        signals.append(("RSI", "🟢 BUY",        f"RSI={rsi:.1f} — oversold zone (30–40)"))
        score += 1
    elif rsi > 70:
        signals.append(("RSI", "🔴 STRONG SELL", f"RSI={rsi:.1f} — deeply overbought (> 70)"))
        score -= 3
    elif rsi > 60:
        signals.append(("RSI", "🔴 SELL",        f"RSI={rsi:.1f} — overbought zone (60–70)"))
        score -= 1
    else:
        signals.append(("RSI", "⚪ NEUTRAL", f"RSI={rsi:.1f} — neutral range (40–60)"))

    # ── 2. MACD Histogram Momentum (max ±2) ─────────────────────────────────
    hist_vals = df["MACD_Hist"].iloc[-4:].values
    rising3 = all(hist_vals[i] > hist_vals[i-1] for i in range(1, 4))
    falling3 = all(hist_vals[i] < hist_vals[i-1] for i in range(1, 4))
    macd_cross_up   = prev["MACD"] < prev["Signal_Line"] and latest["MACD"] > latest["Signal_Line"]
    macd_cross_down = prev["MACD"] > prev["Signal_Line"] and latest["MACD"] < latest["Signal_Line"]

    if macd_cross_up:
        signals.append(("MACD", "🟢 BUY", "Fresh MACD bullish crossover — momentum just turned up")); score += 2
    elif macd_cross_down:
        signals.append(("MACD", "🔴 SELL", "Fresh MACD bearish crossover — momentum just turned down")); score -= 2
    elif rising3 and latest["MACD_Hist"] > 0:
        signals.append(("MACD", "🟢 BUY", "MACD histogram rising 3 bars — bullish momentum building")); score += 2
    elif falling3 and latest["MACD_Hist"] < 0:
        signals.append(("MACD", "🔴 SELL", "MACD histogram falling 3 bars — bearish momentum building")); score -= 2
    elif latest["MACD"] > latest["Signal_Line"]:
        signals.append(("MACD", "⚪ NEUTRAL-BULL", "MACD above signal but not accelerating")); score += 1
    else:
        signals.append(("MACD", "⚪ NEUTRAL-BEAR", "MACD below signal but not accelerating")); score -= 1

    # ── 3. Moving Average Trend (max ±2) ────────────────────────────────────
    c, s20, s50 = latest["Close"], latest["SMA_20"], latest["SMA_50"]
    sma20_slope = (df["SMA_20"].iloc[-1] - df["SMA_20"].iloc[-5]) / df["SMA_20"].iloc[-5] * 100
    if c > s20 and s20 > s50 and sma20_slope > 0:
        signals.append(("Trend (MA)", "🟢 BUY", f"Price > SMA20 > SMA50, SMA20 rising (+{sma20_slope:.2f}%) — confirmed uptrend")); score += 2
    elif c > s20 and s20 > s50:
        signals.append(("Trend (MA)", "🟢 BUY", "Price > SMA20 > SMA50 — uptrend (SMA20 flattening)")); score += 1
    elif c < s20 and s20 < s50 and sma20_slope < 0:
        signals.append(("Trend (MA)", "🔴 SELL", f"Price < SMA20 < SMA50, SMA20 falling ({sma20_slope:.2f}%) — confirmed downtrend")); score -= 2
    elif c < s20 and s20 < s50:
        signals.append(("Trend (MA)", "🔴 SELL", "Price < SMA20 < SMA50 — downtrend (SMA20 flattening)")); score -= 1
    else:
        signals.append(("Trend (MA)", "⚪ NEUTRAL", "Mixed moving averages — no clear trend"))

    # ── 4. Bollinger Bands (max ±1) ─────────────────────────────────────────
    bb_width = (latest["BB_upper"] - latest["BB_lower"]) / latest["BB_mid"]
    if c < latest["BB_lower"]:
        signals.append(("Bollinger", "🟢 BUY", f"Price below lower band — oversold squeeze, mean reversion likely")); score += 1
    elif c > latest["BB_upper"]:
        signals.append(("Bollinger", "🔴 SELL", f"Price above upper band — overbought, pullback likely")); score -= 1
    else:
        pct_b = (c - latest["BB_lower"]) / (latest["BB_upper"] - latest["BB_lower"])
        pos = "upper half" if pct_b > 0.5 else "lower half"
        signals.append(("Bollinger", "⚪ NEUTRAL", f"Within bands ({pos}, %B={pct_b:.2f})"))

    # ── 5. Volume Confirmation (max ±1) ─────────────────────────────────────
    vol_ratio = latest.get("Vol_Ratio", 1.0) or 1.0
    price_up  = latest["Close"] > prev["Close"]
    if vol_ratio > 1.5 and price_up:
        signals.append(("Volume", "🟢 BUY", f"Volume {vol_ratio:.1f}× above average on UP day — strong buying interest")); score += 1
    elif vol_ratio > 1.5 and not price_up:
        signals.append(("Volume", "🔴 SELL", f"Volume {vol_ratio:.1f}× above average on DOWN day — heavy selling pressure")); score -= 1
    elif vol_ratio < 0.5:
        signals.append(("Volume", "⚪ NEUTRAL", f"Low volume ({vol_ratio:.1f}× avg) — move not confirmed"))
    else:
        signals.append(("Volume", "⚪ NEUTRAL", f"Normal volume ({vol_ratio:.1f}× avg)"))

    # ── 6. 5-day Momentum / ROC (max ±1) ────────────────────────────────────
    roc = latest.get("ROC_5", 0.0) or 0.0
    if roc > 4:
        signals.append(("Momentum (5d)", "🟢 BUY", f"5-day return = +{roc:.1f}% — strong upward momentum")); score += 1
    elif roc < -4:
        signals.append(("Momentum (5d)", "🔴 SELL", f"5-day return = {roc:.1f}% — strong downward momentum")); score -= 1
    else:
        signals.append(("Momentum (5d)", "⚪ NEUTRAL", f"5-day return = {roc:+.1f}% — neutral"))

    # ── 7. Fundamentals (max ±2) — only when info dict provided ─────────────
    if info:
        fscore, fsigs = _fundamentals_score(info)
        score += fscore
        signals.extend(fsigs)

    # ── 8. News Sentiment (max ±2) — earnings/M&A/legal/regulatory/macro ────
    if ticker:
        ns, nd = _news_sentiment_score(ticker)
        score += ns
        lbl = "🟢 BUY" if ns > 0 else ("🔴 SELL" if ns < 0 else "⚪ NEUTRAL")
        signals.append(("News Sentiment", lbl, nd))

    # ── 9. Options Flow P/C Ratio (max ±1) ───────────────────────────────────
    if ticker:
        os_, od = _options_sentiment_score(ticker, float(latest["Close"]))
        score += os_
        lbl = "🟢 BUY" if os_ > 0 else ("🔴 SELL" if os_ < 0 else "⚪ NEUTRAL")
        signals.append(("Options Flow", lbl, od))

    # ── 10. Sector Momentum (max ±1) ─────────────────────────────────────────
    if ticker and info:
        sm, sd = _sector_momentum_score(ticker, info, df)
        score += sm
        lbl = "🟢 BUY" if sm > 0 else ("🔴 SELL" if sm < 0 else "⚪ NEUTRAL")
        signals.append(("Sector Momentum", lbl, sd))

    # ── 11. Earnings Event (max ±1) ──────────────────────────────────────────
    if ticker and info:
        es, ed_str = _earnings_signal(ticker, info)
        score += es
        lbl = "🟢 BUY" if es > 0 else ("🔴 SELL" if es < 0 else "⚪ NEUTRAL")
        signals.append(("Earnings", lbl, ed_str))

    # ── 12. Macro Regime — VIX + S&P500 trend (max -2 / +1) ─────────────────
    if ticker:
        mr, md = _macro_regime_score()
        score += mr
        lbl = "🟢 BUY" if mr > 0 else ("🔴 SELL" if mr < 0 else "⚪ NEUTRAL")
        signals.append(("Macro Regime", lbl, md))

    # ── 13. Short Interest — squeeze potential (max ±1) ──────────────────────
    if info:
        si, sid = _short_interest_score(info)
        score += si
        lbl = "🟢 BUY" if si > 0 else ("🔴 SELL" if si < 0 else "⚪ NEUTRAL")
        signals.append(("Short Interest", lbl, sid))

    # ── 14. Insider Activity (max ±1) ────────────────────────────────────────
    if ticker:
        ia, iad = _insider_activity_score(ticker)
        score += ia
        lbl = "🟢 BUY" if ia > 0 else ("🔴 SELL" if ia < 0 else "⚪ NEUTRAL")
        signals.append(("Insider Activity", lbl, iad))

    # ── Score → Label (expanded scale, max ~±20) ─────────────────────────────
    if   score >= 10: label, color = "STRONG BUY",  "green"
    elif score >= 5:  label, color = "BUY",          "green"
    elif score >= 1:  label, color = "WEAK BUY",     "green"
    elif score == 0:  label, color = "HOLD",         "gray"
    elif score >= -4: label, color = "WEAK SELL",    "red"
    elif score >= -9: label, color = "SELL",         "red"
    else:             label, color = "STRONG SELL",  "red"

    return signals, label, color, score


def get_trade_setup(df: pd.DataFrame, signal: str, current_price: float):
    """
    Return concrete ATR-based entry zone, target, stop-loss, and risk/reward.
    Returns None if signal is HOLD or WEAK.
    """
    if signal not in ("STRONG BUY", "BUY", "STRONG SELL", "SELL"):
        return None

    atr = df["ATR"].iloc[-1]
    is_long = "BUY" in signal

    if is_long:
        entry_low  = round(current_price - 0.25 * atr, 2)
        entry_high = round(current_price + 0.25 * atr, 2)
        stop_loss  = round(current_price - 1.5 * atr, 2)
        target1    = round(current_price + 2.0 * atr, 2)
        target2    = round(current_price + 3.5 * atr, 2)
    else:
        entry_low  = round(current_price - 0.25 * atr, 2)
        entry_high = round(current_price + 0.25 * atr, 2)
        stop_loss  = round(current_price + 1.5 * atr, 2)
        target1    = round(current_price - 2.0 * atr, 2)
        target2    = round(current_price - 3.5 * atr, 2)

    entry_mid  = (entry_low + entry_high) / 2
    risk_per_share   = abs(entry_mid - stop_loss)
    reward_per_share = abs(target1 - entry_mid)
    rr = round(reward_per_share / risk_per_share, 2) if risk_per_share > 0 else 0

    return {
        "is_long":    is_long,
        "entry_low":  entry_low,
        "entry_high": entry_high,
        "stop_loss":  stop_loss,
        "target1":    target1,
        "target2":    target2,
        "atr":        round(atr, 2),
        "rr":         rr,
    }


@st.cache_data(ttl=300, show_spinner=False)
def get_stock_data(ticker: str, period: str):
    stock = yf.Ticker(ticker)
    return stock.history(period=period), stock.info


# ── Live Scrolling Ticker Bar ─────────────────────────────────────────────────
_TICKER_SYMBOLS = [
    "NVDA","AAPL","MSFT","GOOGL","META","AMZN","TSLA","AMD","JPM","V",
    "LMT","RTX","NFLX","BAC","XOM","COIN","PLTR","GS","UNH","LLY",
]

@st.cache_data(ttl=300)
def _get_ticker_prices():
    try:
        raw = yf.download(_TICKER_SYMBOLS, period="2d", interval="1d",
                          group_by="ticker", progress=False, auto_adjust=True)
        items = []
        for sym in _TICKER_SYMBOLS:
            try:
                hist = raw[sym].dropna() if len(_TICKER_SYMBOLS) > 1 else raw.dropna()
                if len(hist) < 2:
                    continue
                price = float(hist["Close"].iloc[-1])
                prev  = float(hist["Close"].iloc[-2])
                chg   = (price - prev) / prev * 100
                items.append((sym, price, chg))
            except Exception:
                continue
        return items
    except Exception:
        return []

def render_ticker_bar():
    prices = _get_ticker_prices()
    if not prices:
        return

    parts = []
    for sym, price, chg in prices:
        color = "#00e676" if chg >= 0 else "#ff5252"
        arrow = "▲" if chg >= 0 else "▼"
        parts.append(
            f'<span style="color:#ffffff;font-weight:bold;margin-right:4px;">{sym}</span>'
            f'<span style="color:#cccccc;">${price:.2f}</span>'
            f'<span style="color:{color};margin-left:4px;">{arrow}{abs(chg):.2f}%</span>'
            f'<span style="color:#444;margin:0 18px;">|</span>'
        )

    content = "".join(parts) * 2  # duplicate for seamless loop

    st.markdown(f"""
<style>
.ticker-wrap {{
    width: 100%;
    background: #111827;
    border-top: 1px solid #1f2937;
    border-bottom: 1px solid #1f2937;
    overflow: hidden;
    padding: 6px 0;
    margin-bottom: 12px;
    box-sizing: border-box;
}}
.ticker-content {{
    display: inline-block;
    white-space: nowrap;
    font-size: 0.82em;
    font-family: monospace;
    animation: ticker-scroll 60s linear infinite;
}}
.ticker-content:hover {{ animation-play-state: paused; }}
@keyframes ticker-scroll {{
    0%   {{ transform: translateX(0); }}
    100% {{ transform: translateX(-50%); }}
}}
</style>
<div class="ticker-wrap">
  <div class="ticker-content">{content}</div>
</div>
""", unsafe_allow_html=True)


# ── Top 5 Picks ───────────────────────────────────────────────────────────────
WATCHLIST = [
    # ── Mega-cap Tech ──────────────────────────────────────────────────────────
    "NVDA","AAPL","MSFT","GOOGL","META","AMZN","TSLA","AMD","PLTR","CRM",
    "ORCL","SNOW","NOW","DDOG","SHOP","UBER","COIN","MSTR","ARM","SMCI",
    # ── Financials / Banks ─────────────────────────────────────────────────────
    "JPM","V","MA","GS","BAC","MS","C","WFC","AXP","BLK","SCHW",
    # ── Healthcare / Pharma ────────────────────────────────────────────────────
    "LLY","JNJ","UNH","ABBV","PFE","MRK","BMY","AMGN","GILD","REGN","VRTX",
    # ── Energy / Oil & Gas ────────────────────────────────────────────────────
    "XOM","CVX","COP","SLB","OXY","BP","FANG","PSX","VLO",
    # ── Consumer / Retail ─────────────────────────────────────────────────────
    "COST","WMT","HD","MCD","NKE","SBUX","TGT","LULU","ROST","TJX","LOW",
    # ── Defense & Aerospace / Weapons Manufacturing ───────────────────────────
    "LMT","RTX","NOC","GD","BA","HII","LHX","LDOS","KTOS","AVAV","AXON",
    # ── Aircraft Manufacturing & Airlines ─────────────────────────────────────
    "BA","AIR.PA","DAL","UAL","AAL","LUV","JBLU","ALK","SAVE","HA",
    # ── Cruise Lines ──────────────────────────────────────────────────────────
    "CCL","RCL","NCLH","VIK",
    # ── Industrials / Machinery ───────────────────────────────────────────────
    "CAT","GE","HON","DE","MMM","EMR","ITW","ETN","ROK","PH","IR",
    # ── Entertainment / Media ─────────────────────────────────────────────────
    "NFLX","DIS","PARA","WBD","SPOT","LYV","MSGS",
    # ── Semiconductors ────────────────────────────────────────────────────────
    "TSM","QCOM","INTC","MU","ASML","AMAT","LRCX","KLAC","MRVL","ON",
    # ── EV & Clean Energy ─────────────────────────────────────────────────────
    "RIVN","LCID","NIO","LI","XPEV","ENPH","FSLR","PLUG","NEE","CEG",
    # ── Real Estate / REITs ───────────────────────────────────────────────────
    "AMT","PLD","EQIX","SPG","O","VICI",
    # ── Commodities / Mining ──────────────────────────────────────────────────
    "NEM","GOLD","FCX","BHP","RIO","AA","X","CLF",
    # ── Biotech (high-growth, high-risk) ──────────────────────────────────────
    "MRNA","BNTX","CRSP","BEAM","NTLA","EXAS","INCY","ALNY",
    # ── China / Emerging Markets ──────────────────────────────────────────────
    "BABA","JD","PDD","BIDU","SE","GRAB",
]

# ── Dividend watchlist (income-focused stocks) ────────────────────────────────
DIVIDEND_WATCHLIST = [
    # Dividend Kings / Aristocrats (25+ consecutive years of growth)
    "KO","PG","JNJ","MMM","CLX","GPC","EMR","LOW","TGT","WMT","ABT","BDX",
    # High yield + reliable
    "T","VZ","MO","PM","ABBV","BMY","IBM","CVX","XOM",
    # REITs (high yield by structure)
    "O","STAG","NNN","MAIN","AMT","PLD",
    # Utilities (defensive + steady yield)
    "NEE","DUK","SO","D","ED","XEL",
    # Financials
    "JPM","WFC","V","TFC",
    # Consumer staples
    "GIS","K","HRL","CPB","SJM",
]

@st.cache_data(ttl=1800, show_spinner=False)
def get_top_picks():
    """Scan watchlist, return top 5 with STRONG BUY or BUY signal (score >= 4)."""
    try:
        raw = yf.download(
            WATCHLIST, period="3mo", group_by="ticker",
            auto_adjust=True, progress=False, threads=True
        )
    except Exception:
        return []

    candidates = []
    for ticker in WATCHLIST:
        try:
            hist = raw[ticker].dropna() if len(WATCHLIST) > 1 else raw.dropna()
            if hist.empty or len(hist) < 50:
                continue
            hist = calculate_indicators(hist)
            _, label, _, score = generate_signal(hist)
            # Require score >= 4 (genuine BUY, not just barely positive)
            if score >= 4:
                latest = hist.iloc[-1]
                prev   = hist.iloc[-2]
                chg    = (latest["Close"] - prev["Close"]) / prev["Close"] * 100
                setup  = get_trade_setup(hist, label, float(latest["Close"]))
                candidates.append((ticker, score, label, round(float(latest["Close"]), 2), round(chg, 2), setup))
        except Exception:
            pass

    candidates.sort(key=lambda x: x[1], reverse=True)
    top = candidates[:8]

    results = []
    for ticker, score, label, price, chg, setup in top:
        try:
            stock   = yf.Ticker(ticker)
            info    = stock.info
            news    = stock.news or []
            _ad_markers = ("yptr=yahoo", "src=A00", "how-to-invest", "investors.com/ibd-")
            headline, news_url = "", "#"
            for _n in news:
                _c = _n.get("content", {})
                _u = _c.get("canonicalUrl", {}).get("url", "") or ""
                if any(m in _u for m in _ad_markers):
                    continue
                headline = _c.get("title", "")
                news_url = _u or "#"
                break
            results.append({
                "ticker":   ticker,
                "name":     info.get("shortName", ticker),
                "price":    price,
                "chg":      chg,
                "signal":   label,
                "score":    score,
                "sector":   info.get("sector", "—"),
                "headline": headline,
                "news_url": news_url,
                "target":   info.get("targetMeanPrice"),
                "rec":      info.get("recommendationKey", "").upper(),
                "setup":    setup,
            })
            if len(results) == 5:
                break
        except Exception:
            pass

    return results


def show_top_picks():
    st.markdown("## 🔥 Today's Top 5 Stock Picks")
    st.caption("Scanned every 30 min · Score ≥ 4/10 required · 7 technical criteria · Not financial advice")

    with st.spinner("Scanning market..."):
        picks = get_top_picks()

    if not picks:
        st.info("No clear BUY signals found right now — market may be mixed. Try refreshing in 30 min.")
        return

    cols = st.columns(len(picks))
    for col, p in zip(cols, picks):
        chg_color = "🟢" if p["chg"] >= 0 else "🔴"
        score_bar = "▓" * p["score"] + "░" * (10 - p["score"])
        upside = f"+{((p['target']-p['price'])/p['price']*100):.1f}% analyst target" if p.get("target") else ""
        setup  = p.get("setup")
        stop_line = f"Stop: ${setup['stop_loss']}" if setup else ""
        tgt_line  = f"Target: ${setup['target1']}" if setup else ""

        with col:
            st.markdown(f"""
<div style="border:2px solid #4CAF50;border-radius:12px;padding:14px;text-align:center;background:#0d1f0d;">
  <div style="font-size:1.4em;font-weight:bold;color:#ffffff;">{p['ticker']}</div>
  <div style="font-size:0.75em;color:#cccccc;margin-bottom:6px;">{p['name']}</div>
  <div style="font-size:1.5em;font-weight:bold;color:#ffffff;">${p['price']:.2f}</div>
  <div style="font-size:0.9em;color:#eeeeee;margin:3px 0;">{chg_color} {p['chg']:+.2f}% today</div>
  <div style="margin:6px 0;font-size:0.95em;color:#66ff66;font-weight:bold;">{p['signal']} ({p['score']}/10)</div>
  <div style="font-size:0.7em;color:#aaffaa;font-family:monospace;letter-spacing:2px;">{score_bar}</div>
  <div style="font-size:0.8em;color:#dddddd;margin-top:5px;">{p['sector']}</div>
  {'<div style="font-size:0.8em;color:#66ff66;margin-top:3px;">'+upside+'</div>' if upside else ''}
  {'<div style="font-size:0.8em;color:#ff6666;margin-top:4px;font-weight:bold;">'+stop_line+'</div>' if stop_line else ''}
  {'<div style="font-size:0.8em;color:#66ff66;font-weight:bold;">'+tgt_line+'</div>' if tgt_line else ''}
</div>
""", unsafe_allow_html=True)
            if p["headline"]:
                st.caption(f"📰 [{p['headline'][:55]}{'...' if len(p['headline'])>55 else ''}]({p['news_url']})")

    st.markdown("**Click to analyze:**  " + "  |  ".join(
        [f"[{p['ticker']}](?ticker={p['ticker']})" for p in picks]
    ))
    st.markdown("---")


# ── Dividend analysis ─────────────────────────────────────────────────────────
def get_dividend_metrics(ticker: str, info: dict):
    """
    Compute dividend safety score and key metrics from yfinance.
    Returns a dict with all dividend data needed for display.
    """
    from datetime import datetime, timezone
    try:
        stock = yf.Ticker(ticker)
        divs  = stock.dividends  # pandas Series with DatetimeIndex
    except Exception:
        divs = pd.Series([], dtype=float)

    yield_pct     = (info.get("dividendYield")     or 0) * 100
    rate          = info.get("dividendRate")        or 0
    payout        = (info.get("payoutRatio")        or 0) * 100
    ex_ts         = info.get("exDividendDate")      # unix timestamp or None
    five_yr_yield = info.get("fiveYearAvgDividendYield") or 0

    # Ex-dividend date → readable string + days until
    ex_date_str, days_to_ex = "N/A", None
    if ex_ts:
        try:
            ex_dt = datetime.fromtimestamp(int(ex_ts), tz=timezone.utc).date()
            ex_date_str = str(ex_dt)
            days_to_ex  = (ex_dt - datetime.now(tz=timezone.utc).date()).days
        except Exception:
            pass

    # Dividend growth rate (5-yr CAGR from history)
    growth_rate, consec_years, annual_divs = 0.0, 0, pd.Series([], dtype=float)
    if len(divs) >= 4:
        try:
            annual_divs = divs.resample("YE").sum()
            annual_divs = annual_divs[annual_divs > 0]
            if len(annual_divs) >= 2:
                recent   = float(annual_divs.iloc[-1])
                oldest   = float(annual_divs.iloc[max(-6, -len(annual_divs))])
                yrs      = min(5, len(annual_divs) - 1)
                growth_rate = ((recent / oldest) ** (1 / yrs) - 1) * 100 if oldest > 0 else 0.0
                # Consecutive years of increase
                for i in range(len(annual_divs) - 1, 0, -1):
                    if annual_divs.iloc[i] >= annual_divs.iloc[i - 1] * 0.99:
                        consec_years += 1
                    else:
                        break
        except Exception:
            pass

    # Safety score (0–12)
    safety = 0
    if 2 <= yield_pct <= 4:       safety += 2
    elif 4 < yield_pct <= 6:      safety += 3
    elif yield_pct > 6:           safety += 1   # very high yield can signal distress
    elif yield_pct > 0:           safety += 1

    if 0 < payout < 40:           safety += 3
    elif payout < 60:             safety += 2
    elif payout < 75:             safety += 1
    elif payout > 90:             safety -= 2
    elif payout > 75:             safety -= 1

    if growth_rate > 7:           safety += 2
    elif growth_rate > 3:         safety += 1
    elif growth_rate < 0:         safety -= 2

    if consec_years >= 50:        safety += 3
    elif consec_years >= 25:      safety += 2
    elif consec_years >= 10:      safety += 1

    # Status label
    if consec_years >= 50:   div_status = "👑 Dividend King (50+ yrs)"
    elif consec_years >= 25: div_status = "🏆 Dividend Aristocrat (25+ yrs)"
    elif consec_years >= 10: div_status = "⭐ Dividend Achiever (10+ yrs)"
    elif yield_pct > 0:      div_status = "📊 Dividend Payer"
    else:                    div_status = "❌ No Dividend"

    return {
        "yield_pct":    round(yield_pct, 2),
        "rate":         round(rate, 4),
        "payout":       round(payout, 1),
        "ex_date":      ex_date_str,
        "days_to_ex":   days_to_ex,
        "five_yr_yield":round(five_yr_yield, 2),
        "growth_rate":  round(growth_rate, 2),
        "consec_years": consec_years,
        "div_status":   div_status,
        "safety_score": max(0, safety),
        "divs":         divs,
        "annual_divs":  annual_divs,
    }


def show_dividend_analysis(ticker: str, info: dict, current_price: float):
    """Render the dividend deep-dive section inside a stock page."""
    dm = get_dividend_metrics(ticker, info)

    if dm["yield_pct"] == 0:
        st.info("This stock does not currently pay a dividend.")
        return

    st.markdown("### 💰 Dividend Analysis")

    # Top metrics
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Annual Yield",     f"{dm['yield_pct']:.2f}%",
              help="Dividend / current price")
    c2.metric("Annual Dividend",  f"${dm['rate']:.4f}/share",
              help="Dividend paid per share per year")
    c3.metric("Payout Ratio",     f"{dm['payout']:.1f}%",
              help="% of earnings paid as dividends. Under 60% = healthy.")
    c4.metric("5-yr Avg Yield",   f"{dm['five_yr_yield']:.2f}%",
              help="How today's yield compares to the stock's own history")
    if dm["days_to_ex"] is not None:
        days_label = f"in {dm['days_to_ex']}d" if dm["days_to_ex"] > 0 else "PASSED"
        c5.metric("Ex-Dividend Date", dm["ex_date"], days_label,
                  help="Own shares BEFORE this date to receive the next dividend")
    else:
        c5.metric("Ex-Dividend Date", dm["ex_date"])

    # Status + safety score
    safety = dm["safety_score"]
    bar    = "▓" * safety + "░" * max(0, 12 - safety)
    if safety >= 8:    scolor = "green"
    elif safety >= 5:  scolor = "orange"
    else:              scolor = "red"

    st.markdown(f"""
<div style="border:1px solid #333;border-radius:8px;padding:14px;background:#1a1a1a;margin-bottom:10px;">
  <span style="font-size:1.1em;">{dm['div_status']}</span> &nbsp;
  <span style="color:#888;">Safety Score: </span>
  <span style="color:{'#4CAF50' if scolor=='green' else ('#FF9800' if scolor=='orange' else '#f44336')};font-weight:bold;">{safety}/12</span>
  &nbsp; <span style="font-family:monospace;color:#666;">{bar}</span>
  <br><span style="font-size:0.85em;color:#aaa;">
    {dm['consec_years']} consecutive years of dividend growth &nbsp;·&nbsp;
    5-yr growth rate: {dm['growth_rate']:+.1f}%/yr
  </span>
</div>
""", unsafe_allow_html=True)

    # Safety score explanation
    with st.expander("📋 How is the safety score calculated?"):
        rows = []
        if dm["yield_pct"] > 0:
            if 2 <= dm["yield_pct"] <= 4:     rows.append(("Yield (2–4%)",  "+2", "Sweet spot — attractive without distress signal"))
            elif 4 < dm["yield_pct"] <= 6:    rows.append(("Yield (4–6%)",  "+3", "High yield — rewarding if sustainable"))
            elif dm["yield_pct"] > 6:         rows.append(("Yield (>6%)",   "+1", "Very high — could signal dividend at risk"))
            else:                             rows.append(("Yield (<2%)",   "+1", "Low but positive"))
        if dm["payout"] > 0:
            if dm["payout"] < 40:             rows.append(("Payout <40%",   "+3", "Very healthy — plenty of room to grow"))
            elif dm["payout"] < 60:           rows.append(("Payout 40–60%", "+2", "Healthy — sustainable"))
            elif dm["payout"] < 75:           rows.append(("Payout 60–75%", "+1", "Moderate — watch for pressure"))
            elif dm["payout"] > 90:           rows.append(("Payout >90%",   "-2", "Danger — nearly all earnings go to dividend"))
            else:                             rows.append(("Payout 75–90%", "-1", "High — leaves little buffer"))
        if dm["growth_rate"] > 7:             rows.append(("Growth >7%/yr", "+2", "Strong, consistent dividend growth"))
        elif dm["growth_rate"] > 3:           rows.append(("Growth 3–7%/yr","+1", "Moderate growth"))
        elif dm["growth_rate"] < 0:           rows.append(("Growth negative","-2","Dividend has been cut or stagnant"))
        if dm["consec_years"] >= 50:          rows.append(("50+ yrs streak","+3", "Dividend King — elite reliability"))
        elif dm["consec_years"] >= 25:        rows.append(("25+ yrs streak","+2", "Dividend Aristocrat"))
        elif dm["consec_years"] >= 10:        rows.append(("10+ yrs streak","+1", "Dividend Achiever"))
        st.dataframe(pd.DataFrame(rows, columns=["Factor","Points","Why"]),
                     use_container_width=True, hide_index=True)

    # Income calculator
    st.markdown("#### 💵 Income Calculator — How much will you earn?")
    shares = st.number_input("How many shares do you plan to buy?",
                             min_value=1, max_value=100000, value=100,
                             key=f"div_calc_{ticker}")
    total_cost  = shares * current_price
    annual_inc  = shares * dm["rate"]
    monthly_inc = annual_inc / 12
    qtr_inc     = annual_inc / 4
    yrs_to_recover = total_cost / annual_inc if annual_inc > 0 else float("inf")

    ic1, ic2, ic3, ic4 = st.columns(4)
    ic1.metric("Investment",          f"${total_cost:,.2f}")
    ic2.metric("Annual Income",       f"${annual_inc:,.2f}")
    ic3.metric("Monthly Income",      f"${monthly_inc:,.2f}")
    ic4.metric("Quarterly Dividend",  f"${qtr_inc:,.2f}")
    if yrs_to_recover < 100:
        st.caption(f"At current yield, dividends alone would pay back your investment in **{yrs_to_recover:.1f} years** (ignoring price appreciation and dividend growth).")

    # Dividend history chart
    if len(dm["divs"]) >= 4:
        st.markdown("#### 📈 Dividend History")
        annual = dm["annual_divs"]
        if len(annual) >= 2:
            fig = go.Figure()
            fig.add_trace(go.Bar(
                x=annual.index.year.astype(str),
                y=annual.values,
                marker_color=["#4CAF50" if i == len(annual) - 1 else "#2196F3"
                               for i in range(len(annual))],
                name="Annual Dividend/Share"
            ))
            fig.update_layout(
                title=f"{ticker} — Annual Dividend Per Share",
                template="plotly_dark", height=280,
                yaxis_title="$/share", xaxis_title="Year",
                margin=dict(t=40, b=20)
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            # Fall back to raw quarterly history
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=dm["divs"].index, y=dm["divs"].values,
                                     mode="lines+markers", line=dict(color="#4CAF50"),
                                     name="Dividend/Share"))
            fig.update_layout(title=f"{ticker} — Dividend History",
                              template="plotly_dark", height=250,
                              yaxis_title="$/share", margin=dict(t=40, b=20))
            st.plotly_chart(fig, use_container_width=True)


@st.cache_data(ttl=1800, show_spinner=False)
def get_top_dividend_picks():
    """Scan dividend watchlist, return top 10 by safety score + yield."""
    try:
        raw = yf.download(
            DIVIDEND_WATCHLIST, period="3mo", group_by="ticker",
            auto_adjust=True, progress=False, threads=True
        )
    except Exception:
        return []

    results = []
    for ticker in DIVIDEND_WATCHLIST:
        try:
            hist = raw[ticker].dropna() if len(DIVIDEND_WATCHLIST) > 1 else raw.dropna()
            if hist.empty or len(hist) < 20:
                continue
            stock = yf.Ticker(ticker)
            info  = stock.info
            dm    = get_dividend_metrics(ticker, info)
            if dm["yield_pct"] == 0:
                continue
            hist_ind = calculate_indicators(hist)
            _, tech_label, _, tech_score = generate_signal(hist_ind)
            latest = hist.iloc[-1]
            prev   = hist.iloc[-2]
            chg    = (float(latest["Close"]) - float(prev["Close"])) / float(prev["Close"]) * 100
            results.append({
                "ticker":       ticker,
                "name":         info.get("shortName", ticker),
                "price":        round(float(latest["Close"]), 2),
                "chg":          round(chg, 2),
                "yield_pct":    dm["yield_pct"],
                "rate":         dm["rate"],
                "payout":       dm["payout"],
                "safety":       dm["safety_score"],
                "div_status":   dm["div_status"],
                "consec_years": dm["consec_years"],
                "growth_rate":  dm["growth_rate"],
                "ex_date":      dm["ex_date"],
                "days_to_ex":   dm["days_to_ex"],
                "sector":       info.get("sector", "—"),
                "tech_signal":  tech_label,
                "tech_score":   tech_score,
            })
        except Exception:
            pass

    # Sort by: safety score first, then yield
    results.sort(key=lambda x: (x["safety"], x["yield_pct"]), reverse=True)
    return results


# ── Portfolio persistence ─────────────────────────────────────────────────────
PORTFOLIO_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "portfolio.json")

def load_portfolio() -> dict:
    if os.path.exists(PORTFOLIO_FILE):
        try:
            with open(PORTFOLIO_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {"holdings": []}

def save_portfolio(data: dict):
    with open(PORTFOLIO_FILE, "w") as f:
        json.dump(data, f, indent=2, default=str)


def show_portfolio():
    """Portfolio tracker — add holdings, track value, gain/loss, signals."""
    st.markdown("## 📂 My Portfolio")
    st.caption("Track your holdings · live value · gain/loss · dividend income · buy/sell signals")

    portfolio = load_portfolio()
    holdings  = portfolio.get("holdings", [])

    # ── Add / update a holding ────────────────────────────────────────────────
    with st.expander("➕ Add or Update a Holding", expanded=(len(holdings) == 0)):
        with st.form("add_holding_form", clear_on_submit=True):
            fc1, fc2, fc3, fc4 = st.columns([2, 1, 2, 2])
            new_ticker = fc1.text_input("Ticker symbol", placeholder="AAPL")
            new_shares = fc2.number_input("Shares", min_value=0.001, value=1.0, step=1.0, format="%.3f")
            new_cost   = fc3.number_input("Avg purchase price ($)", min_value=0.01, value=100.00, step=0.01)
            new_date   = fc4.date_input("Purchase date")
            submitted  = st.form_submit_button("Add to Portfolio", type="primary")
            if submitted and new_ticker.strip():
                t_up = new_ticker.strip().upper()
                existing = next((h for h in holdings if h["ticker"] == t_up), None)
                if existing:
                    # Weighted average cost
                    total  = existing["shares"] + new_shares
                    new_avg = (existing["shares"] * existing["avg_cost"] + new_shares * new_cost) / total
                    existing["shares"]   = total
                    existing["avg_cost"] = round(new_avg, 4)
                    st.success(f"Updated **{t_up}**: {total:.3f} shares @ avg ${new_avg:.2f}")
                else:
                    holdings.append({
                        "ticker":     t_up,
                        "shares":     new_shares,
                        "avg_cost":   round(new_cost, 4),
                        "date_added": str(new_date),
                    })
                    st.success(f"Added **{t_up}** to portfolio")
                portfolio["holdings"] = holdings
                save_portfolio(portfolio)
                st.rerun()

    if not holdings:
        st.info("No holdings yet. Use the form above to add your first stock.")
        return

    # ── Load live prices + signals ────────────────────────────────────────────
    tickers = [h["ticker"] for h in holdings]
    live_data = {}
    with st.spinner("Loading live prices and signals..."):
        for t in tickers:
            try:
                hist, info = get_stock_data(t, "3mo")
                if not hist.empty:
                    hist_ind = calculate_indicators(hist)
                    _, sig_lbl, _, sig_score = generate_signal(hist_ind, info=info, ticker=t)
                    live_data[t] = {
                        "price":     float(hist_ind.iloc[-1]["Close"]),
                        "info":      info,
                        "sig_label": sig_lbl,
                        "sig_score": sig_score,
                    }
            except Exception:
                pass

    # ── Build portfolio rows ──────────────────────────────────────────────────
    rows         = []
    total_invest = 0.0
    total_value  = 0.0
    total_divs   = 0.0

    for h in holdings:
        t    = h["ticker"]
        d    = live_data.get(t, {})
        price     = d.get("price", 0.0)
        info      = d.get("info", {})
        sig_lbl   = d.get("sig_label", "N/A")
        sig_score = d.get("sig_score", 0)

        invested = h["shares"] * h["avg_cost"]
        value    = h["shares"] * price if price else 0.0
        gain     = value - invested
        gain_pct = (gain / invested * 100) if invested else 0.0

        ann_div = (info.get("dividendRate") or 0) * h["shares"]

        total_invest += invested
        total_value  += value
        total_divs   += ann_div

        rows.append({
            "ticker":     t,
            "shares":     h["shares"],
            "avg_cost":   h["avg_cost"],
            "price":      price,
            "invested":   invested,
            "value":      value,
            "gain":       gain,
            "gain_pct":   gain_pct,
            "ann_div":    ann_div,
            "sig_label":  sig_lbl,
            "sig_score":  sig_score,
            "date_added": h.get("date_added", ""),
        })

    total_gain    = total_value - total_invest
    total_pct     = (total_gain / total_invest * 100) if total_invest else 0.0

    # ── Summary strip ─────────────────────────────────────────────────────────
    s1, s2, s3, s4, s5 = st.columns(5)
    s1.metric("Total Invested",     f"${total_invest:,.2f}")
    s2.metric("Current Value",      f"${total_value:,.2f}",  f"{total_pct:+.2f}%")
    s3.metric("Unrealized Gain",    f"${total_gain:+,.2f}",  f"{total_pct:+.2f}%")
    s4.metric("Ann. Dividend Income", f"${total_divs:,.2f}", f"${total_divs/12:,.2f}/mo")
    s5.metric("Positions",          len(rows))
    st.markdown("---")

    # ── Portfolio Signals Dashboard ───────────────────────────────────────────
    urgent_sells  = [r for r in rows if r["sig_score"] <= -2]
    strong_buys   = [r for r in rows if r["sig_score"] >= 2]
    overbought    = [r for r in rows if r["price"] > 0 and r["sig_score"] <= -1 and r["gain_pct"] > 5]
    deep_losses   = [r for r in rows if r["gain_pct"] < -8]
    # Remove overlap: don't show a stock in both buys and sells
    sell_tickers  = {r["ticker"] for r in urgent_sells}
    strong_buys   = [r for r in strong_buys if r["ticker"] not in sell_tickers]

    has_alerts = urgent_sells or strong_buys or overbought or deep_losses
    if has_alerts:
        st.subheader("🚨 Portfolio Action Alerts")
        st.caption("Live signals for your holdings — check these before the market closes")

        if urgent_sells:
            with st.container(border=True):
                st.markdown("#### 🔴 Sell Signals — Consider Exiting")
                for r in sorted(urgent_sells, key=lambda x: x["sig_score"]):
                    profit_tag = f"{'🟢 +' if r['gain_pct'] >= 0 else '🔴 '}{r['gain_pct']:.1f}%"
                    cols = st.columns([1, 2, 2, 2, 3])
                    cols[0].markdown(f"**{r['ticker']}**")
                    cols[1].markdown(f"Signal: **{r['sig_label']}** ({r['sig_score']}/10)")
                    cols[2].markdown(f"P&L: {profit_tag} (${r['gain']:+,.0f})")
                    cols[3].markdown(f"Now: **${r['price']:.2f}** · Avg: ${r['avg_cost']:.2f}")
                    reason = "Strong bearish technicals — exit now" if r["sig_score"] <= -6 else ("Bearish momentum — consider selling" if r["sig_score"] <= -4 else "Early sell signal — watch closely")
                    cols[4].markdown(f"⚠️ {reason}")

        if strong_buys:
            with st.container(border=True):
                st.markdown("#### 🟢 Buy Signals — Good Time to Add")
                for r in sorted(strong_buys, key=lambda x: -x["sig_score"]):
                    profit_tag = f"{'🟢 +' if r['gain_pct'] >= 0 else '🔴 '}{r['gain_pct']:.1f}%"
                    cols = st.columns([1, 2, 2, 2, 3])
                    cols[0].markdown(f"**{r['ticker']}**")
                    cols[1].markdown(f"Signal: **{r['sig_label']}** ({r['sig_score']}/10)")
                    cols[2].markdown(f"P&L: {profit_tag} (${r['gain']:+,.0f})")
                    cols[3].markdown(f"Now: **${r['price']:.2f}** · Avg: ${r['avg_cost']:.2f}")
                    reason = "Strong bullish technicals — add aggressively" if r["sig_score"] >= 6 else ("Good entry forming — consider adding" if r["sig_score"] >= 4 else "Early buy signal — good time to scale in")
                    cols[4].markdown(f"✅ {reason}")

        if overbought:
            with st.container(border=True):
                st.markdown("#### 💰 Take Profit? — Up Nicely but Showing Weakness")
                for r in sorted(overbought, key=lambda x: -x["gain_pct"]):
                    cols = st.columns([1, 2, 2, 2, 3])
                    cols[0].markdown(f"**{r['ticker']}**")
                    cols[1].markdown(f"Signal: **{r['sig_label']}** ({r['sig_score']}/10)")
                    cols[2].markdown(f"Gain: 🟢 +{r['gain_pct']:.1f}% (${r['gain']:+,.0f})")
                    cols[3].markdown(f"Now: **${r['price']:.2f}** · Avg: ${r['avg_cost']:.2f}")
                    cols[4].markdown("💡 Up >5% but technicals softening — lock in partial profit now, let rest run")

        if deep_losses:
            with st.container(border=True):
                st.markdown("#### 🩹 Deep Losses — Review Needed")
                for r in sorted(deep_losses, key=lambda x: x["gain_pct"]):
                    cols = st.columns([1, 2, 2, 2, 3])
                    cols[0].markdown(f"**{r['ticker']}**")
                    cols[1].markdown(f"Signal: **{r['sig_label']}** ({r['sig_score']}/10)")
                    cols[2].markdown(f"Loss: 🔴 {r['gain_pct']:.1f}% (${r['gain']:+,.0f})")
                    cols[3].markdown(f"Now: **${r['price']:.2f}** · Avg: ${r['avg_cost']:.2f}")
                    action = "Cut loss — signal is bearish, stop bleeding" if r["sig_score"] <= -2 else "Average down now while price is low"
                    cols[4].markdown(f"📋 {action} · see Recovery Advisor below")

        st.markdown("---")

    # ── Holdings table ────────────────────────────────────────────────────────
    st.subheader("📋 Holdings")
    table = []
    for r in rows:
        g_emoji = "🟢" if r["gain"] >= 0 else "🔴"
        t_emoji = "🟢" if "BUY"  in r["sig_label"] else ("🔴" if "SELL" in r["sig_label"] else "⚪")
        table.append({
            "Ticker":        r["ticker"],
            "Shares":        f"{r['shares']:.3f}",
            "Avg Cost":      f"${r['avg_cost']:.2f}",
            "Current":       f"${r['price']:.2f}",
            "Invested":      f"${r['invested']:,.2f}",
            "Value":         f"${r['value']:,.2f}",
            "Gain / Loss":   f"{g_emoji} ${r['gain']:+,.2f}",
            "Return %":      f"{r['gain_pct']:+.2f}%",
            "Ann. Dividend": f"${r['ann_div']:.2f}" if r["ann_div"] > 0 else "—",
            "Signal":        f"{t_emoji} {r['sig_label']} ({r['sig_score']}/10)",
            "Date Bought":   r["date_added"],
        })
    st.dataframe(pd.DataFrame(table), use_container_width=True, hide_index=True)

    # ── Charts ────────────────────────────────────────────────────────────────
    st.markdown("---")
    ch1, ch2 = st.columns(2)

    with ch1:
        fig_pie = go.Figure(go.Pie(
            labels=[r["ticker"] for r in rows],
            values=[max(r["value"], 0.01) for r in rows],
            hole=0.4,
            textinfo="label+percent",
        ))
        fig_pie.update_layout(
            title="Portfolio Allocation (by current value)",
            template="plotly_dark", height=340, margin=dict(t=50, b=0),
        )
        st.plotly_chart(fig_pie, use_container_width=True)

    with ch2:
        bar_colors = ["#4CAF50" if r["gain"] >= 0 else "#f44336" for r in rows]
        fig_bar = go.Figure(go.Bar(
            x=[r["ticker"] for r in rows],
            y=[r["gain"] for r in rows],
            marker_color=bar_colors,
            text=[f"${r['gain']:+,.0f}\n{r['gain_pct']:+.1f}%" for r in rows],
            textposition="outside",
        ))
        fig_bar.update_layout(
            title="Unrealized Gain / Loss ($)",
            template="plotly_dark", height=340,
            yaxis_title="$", margin=dict(t=50, b=0),
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    # ── Signal summary ────────────────────────────────────────────────────────
    st.markdown("---")
    st.subheader("📡 What Should You Do With Each Position?")
    buys  = sorted([r for r in rows if "BUY"  in r["sig_label"]], key=lambda x: -x["sig_score"])
    sells = sorted([r for r in rows if "SELL" in r["sig_label"]], key=lambda x: x["sig_score"])
    holds = [r for r in rows if r["sig_label"] in ("HOLD","WEAK BUY","WEAK SELL","N/A")]

    sc1, sc2, sc3 = st.columns(3)
    with sc1:
        st.markdown("**🟢 Consider Adding More**")
        for r in buys:
            st.markdown(f"- **{r['ticker']}** — {r['sig_label']} ({r['sig_score']}/10)  \n"
                        f"  Avg cost ${r['avg_cost']:.2f} · Now ${r['price']:.2f} · {r['gain_pct']:+.1f}%")
        if not buys: st.markdown("*None at the moment*")
    with sc2:
        st.markdown("**⚪ Hold — no clear action**")
        for r in holds:
            st.markdown(f"- **{r['ticker']}** ({r['sig_label']}) · {r['gain_pct']:+.1f}%")
        if not holds: st.markdown("*None*")
    with sc3:
        st.markdown("**🔴 Consider Trimming / Selling**")
        for r in sells:
            st.markdown(f"- **{r['ticker']}** — {r['sig_label']} ({r['sig_score']}/10)  \n"
                        f"  Avg cost ${r['avg_cost']:.2f} · Now ${r['price']:.2f} · {r['gain_pct']:+.1f}%")
        if not sells: st.markdown("*None at the moment*")

    # ── Loss Recovery Advisor ─────────────────────────────────────────────────
    losing_rows = [r for r in rows if r["gain"] < 0]
    if losing_rows:
        import math
        st.markdown("---")
        st.subheader("🩹 Loss Recovery Advisor")
        st.caption("Personalised recovery strategies for every position currently in the red")

        for r in losing_rows:
            ticker    = r["ticker"]
            avg_cost  = r["avg_cost"]
            cur_price = r["price"]
            shares    = r["shares"]
            loss_amt  = r["gain"]          # negative number
            loss_pct  = r["gain_pct"]      # negative number
            sig       = r["sig_label"]
            sig_score = r["sig_score"]

            # How much must price rise to break even?
            pct_to_breakeven = ((avg_cost - cur_price) / cur_price * 100) if cur_price else 0
            # Recovery timeline at 10 %/yr compound (market historical average)
            years_10pct = (math.log(avg_cost / cur_price) / math.log(1.10)) if cur_price and avg_cost > cur_price else 0

            # Pick strategy
            if sig_score >= 4 and loss_pct > -30:
                strategy = "avg_down"
                strat_color = "#4CAF50"
                strat_icon  = "📉➕"
                strat_title = "Consider Averaging Down"
                strat_desc  = (
                    f"Technical signal is **{sig}** ({sig_score}/10) and the loss is manageable. "
                    "Buying additional shares at the current price lowers your break-even and lets you recover faster once the stock turns."
                )
            elif sig_score <= -4 or loss_pct < -35:
                strategy = "cut"
                strat_color = "#f44336"
                strat_icon  = "✂️"
                strat_title = "Consider Cutting the Loss"
                strat_desc  = (
                    f"Signal is **{sig}** ({sig_score}/10)" +
                    (f" and the position is down {loss_pct:.1f}%." if loss_pct < -35 else ".") +
                    " Holding a deteriorating position can turn a recoverable loss into a permanent one. "
                    "Realising the loss now also creates a **tax deduction** you can use against other gains."
                )
            else:
                strategy = "hold"
                strat_color = "#FF9800"
                strat_icon  = "⏳"
                strat_title = "Hold & Monitor"
                strat_desc  = (
                    f"Signal is **{sig}** ({sig_score}/10) — no strong directional conviction either way. "
                    "Watch for the signal to improve before adding, or to deteriorate before cutting."
                )

            with st.expander(
                f"{strat_icon} **{ticker}** — down ${abs(loss_amt):,.2f} ({loss_pct:.1f}%) · {strat_title}",
                expanded=True,
            ):
                col_l, col_r = st.columns([1.6, 1])

                with col_l:
                    st.markdown(f"**Strategy:** {strat_desc}")
                    st.markdown("---")

                    # Break-even snapshot
                    bc1, bc2, bc3 = st.columns(3)
                    bc1.metric("Your Avg Cost",     f"${avg_cost:.2f}")
                    bc2.metric("Current Price",      f"${cur_price:.2f}", f"{loss_pct:+.1f}%")
                    bc3.metric("Price Must Rise",    f"{pct_to_breakeven:.1f}% to break even")

                    if years_10pct > 0:
                        st.caption(
                            f"At the stock market's historical average return (~10 %/yr), "
                            f"this position would need roughly **{years_10pct:.1f} year{'s' if years_10pct > 1 else ''}** "
                            "to recover — assuming the stock tracks the market."
                        )

                    # Tax-loss harvest callout
                    if strategy in ("cut", "hold"):
                        tax_saving_est = abs(loss_amt) * 0.22   # rough 22% bracket
                        st.info(
                            f"**Tax-loss harvest opportunity:** Selling now locks in a **${abs(loss_amt):,.2f} capital loss**. "
                            f"At a 22% tax rate this could offset ~**${tax_saving_est:,.2f}** of tax on other gains this year. "
                            "Consult a tax advisor for your specific situation."
                        )

                with col_r:
                    if strategy == "avg_down":
                        st.markdown("**📊 Averaging-Down Calculator**")
                        extra_shares = st.number_input(
                            f"Additional shares to buy at ${cur_price:.2f}",
                            min_value=0.001,
                            value=round(shares * 0.5, 3),
                            step=1.0,
                            key=f"avg_down_{ticker}",
                            format="%.3f",
                        )
                        new_total_shares = shares + extra_shares
                        new_total_cost   = (shares * avg_cost) + (extra_shares * cur_price)
                        new_avg          = new_total_cost / new_total_shares
                        new_pct_needed   = ((new_avg - cur_price) / cur_price * 100) if cur_price else 0
                        breakeven_reduction = avg_cost - new_avg
                        extra_invest     = extra_shares * cur_price

                        st.metric("New Avg Cost",       f"${new_avg:.2f}", f"-${breakeven_reduction:.2f}")
                        st.metric("New Break-even Drop", f"{new_pct_needed:.1f}% needed to recover",
                                  f"was {pct_to_breakeven:.1f}%")
                        st.metric("Additional Capital",  f"${extra_invest:,.2f}")
                        if years_10pct > 0:
                            new_years = (math.log(new_avg / cur_price) / math.log(1.10)) if new_avg > cur_price else 0
                            st.metric("Recovery Timeline", f"~{new_years:.1f} yrs", f"was {years_10pct:.1f} yrs")
                    else:
                        st.markdown("**📌 Quick Summary**")
                        st.metric("Loss Amount",        f"${abs(loss_amt):,.2f}")
                        st.metric("Shares Held",        f"{shares:.3f}")
                        st.metric("Cost Basis",         f"${shares * avg_cost:,.2f}")
                        st.metric("Current Value",      f"${r['value']:,.2f}")

    # ── Performance over time chart ───────────────────────────────────────────
    st.markdown("---")
    st.subheader("📈 Portfolio Value Over Time (past year)")
    fig_perf = go.Figure()
    portfolio_value_series = None
    for h in holdings:
        try:
            hist_full, _ = get_stock_data(h["ticker"], "1y")
            if hist_full.empty:
                continue
            pos_value = hist_full["Close"] * h["shares"]
            pos_value.name = h["ticker"]
            if portfolio_value_series is None:
                portfolio_value_series = pos_value
            else:
                portfolio_value_series = portfolio_value_series.add(pos_value, fill_value=0)
            fig_perf.add_trace(go.Scatter(
                x=hist_full.index, y=pos_value,
                name=h["ticker"], mode="lines", stackgroup="one",
            ))
        except Exception:
            pass

    if portfolio_value_series is not None:
        fig_perf.update_layout(
            title="Stacked position value (1 year)",
            template="plotly_dark", height=380,
            yaxis_title="Total Value ($)", margin=dict(t=50),
        )
        st.plotly_chart(fig_perf, use_container_width=True)

    # ── Dividend income breakdown ─────────────────────────────────────────────
    div_rows = [r for r in rows if r["ann_div"] > 0]
    if div_rows:
        st.markdown("---")
        st.subheader("💰 Dividend Income Breakdown")
        div_table = []
        for r in div_rows:
            div_table.append({
                "Ticker":       r["ticker"],
                "Shares":       f"{r['shares']:.3f}",
                "Yield":        f"{(r['ann_div']/r['value']*100):.2f}%" if r["value"] else "—",
                "Annual Income":f"${r['ann_div']:.2f}",
                "Monthly":      f"${r['ann_div']/12:.2f}",
                "Quarterly":    f"${r['ann_div']/4:.2f}",
            })
        st.dataframe(pd.DataFrame(div_table), use_container_width=True, hide_index=True)
        st.success(f"Total projected annual dividend income from your portfolio: **${total_divs:,.2f}** (${total_divs/12:,.2f}/month)")

    # ── Remove a holding ─────────────────────────────────────────────────────
    st.markdown("---")
    st.subheader("🗑️ Remove a Holding")
    rd1, rd2 = st.columns([3, 1])
    to_remove = rd1.selectbox("Select holding to remove:", [h["ticker"] for h in holdings])
    if rd2.button("Remove", type="secondary"):
        portfolio["holdings"] = [h for h in holdings if h["ticker"] != to_remove]
        save_portfolio(portfolio)
        st.success(f"Removed {to_remove} from portfolio.")
        st.rerun()

    # ── Drill-down ────────────────────────────────────────────────────────────
    st.markdown("---")
    st.subheader("🔍 Full Analysis for a Holding")
    pick = st.selectbox("Select a stock for detailed analysis:", [h["ticker"] for h in holdings],
                        key="portfolio_drill")
    if pick:
        show_single_stock(pick, period)


def show_dividend_stocks():
    """Full dividend screener page."""
    st.markdown("## 💰 Dividend Stock Screener")
    st.caption("Income-focused stocks ranked by dividend safety · yield · consecutive growth years")

    with st.spinner("Loading dividend data for all stocks..."):
        picks = get_top_dividend_picks()

    if not picks:
        st.error("Could not load dividend data. Try refreshing.")
        return

    # ── Summary metrics ───────────────────────────────────────────────────────
    kings       = sum(1 for p in picks if p["consec_years"] >= 50)
    aristocrats = sum(1 for p in picks if 25 <= p["consec_years"] < 50)
    safe        = sum(1 for p in picks if p["safety"] >= 8)
    avg_yield   = sum(p["yield_pct"] for p in picks) / len(picks)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("👑 Dividend Kings",       kings)
    m2.metric("🏆 Dividend Aristocrats", aristocrats)
    m3.metric("✅ High Safety (≥8/12)",  safe)
    m4.metric("Avg Yield",               f"{avg_yield:.2f}%")

    st.markdown("---")

    # ── Filter controls ───────────────────────────────────────────────────────
    col_f1, col_f2, col_f3 = st.columns(3)
    min_yield  = col_f1.slider("Min Yield (%)",   0.0, 10.0, 1.0, 0.5)
    min_safety = col_f2.slider("Min Safety Score", 0, 12, 4, 1)
    max_payout = col_f3.slider("Max Payout Ratio (%)", 0, 150, 90, 5)

    filtered = [p for p in picks
                if p["yield_pct"] >= min_yield
                and p["safety"]   >= min_safety
                and (p["payout"]  <= max_payout or p["payout"] == 0)]

    if not filtered:
        st.warning("No stocks match these filters. Try relaxing the criteria.")
        return

    st.caption(f"Showing {len(filtered)} stocks after filtering.")

    # ── Main table ────────────────────────────────────────────────────────────
    st.subheader("📊 Dividend Leaderboard")
    table_rows = []
    for p in filtered:
        safety_bar = "▓" * p["safety"] + "░" * max(0, 12 - p["safety"])
        tech_emoji = "🟢" if "BUY" in p["tech_signal"] else ("🔴" if "SELL" in p["tech_signal"] else "⚪")
        table_rows.append({
            "Ticker":        p["ticker"],
            "Company":       p["name"],
            "Price":         f"${p['price']:.2f}",
            "Yield":         f"{p['yield_pct']:.2f}%",
            "Annual $/share":f"${p['rate']:.4f}",
            "Payout %":      f"{p['payout']:.1f}%" if p["payout"] > 0 else "N/A",
            "Safety":        f"{p['safety']}/12",
            "Status":        p["div_status"].split("(")[0].strip(),
            "Growth/yr":     f"{p['growth_rate']:+.1f}%",
            "Consec Yrs":    p["consec_years"],
            "Ex-Date":       p["ex_date"],
            "Tech":          f"{tech_emoji} {p['tech_signal']}",
        })

    st.dataframe(pd.DataFrame(table_rows), use_container_width=True, hide_index=True)

    # ── Yield comparison chart ────────────────────────────────────────────────
    st.markdown("---")
    st.subheader("📈 Yield vs Safety Score")
    top20 = filtered[:20]
    colors = []
    for p in top20:
        if p["safety"] >= 8:   colors.append("#4CAF50")
        elif p["safety"] >= 5: colors.append("#FF9800")
        else:                  colors.append("#f44336")

    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=[p["ticker"] for p in top20],
        y=[p["yield_pct"] for p in top20],
        marker_color=colors,
        text=[f"{p['yield_pct']:.1f}%" for p in top20],
        textposition="outside",
        customdata=[[p["safety"], p["div_status"]] for p in top20],
        hovertemplate="<b>%{x}</b><br>Yield: %{y:.2f}%<br>Safety: %{customdata[0]}/12<br>%{customdata[1]}<extra></extra>",
    ))
    fig.update_layout(
        template="plotly_dark", height=350,
        yaxis_title="Annual Yield (%)", xaxis_title="",
        title="Dividend Yield (🟢 safe · 🟠 moderate · 🔴 risky)",
        margin=dict(t=50, b=20),
    )
    st.plotly_chart(fig, use_container_width=True)

    # ── Upcoming ex-dividend dates ────────────────────────────────────────────
    upcoming = sorted(
        [p for p in filtered if p["days_to_ex"] is not None and 0 <= p["days_to_ex"] <= 45],
        key=lambda x: x["days_to_ex"]
    )
    if upcoming:
        st.markdown("---")
        st.subheader("📅 Upcoming Ex-Dividend Dates (next 45 days)")
        st.caption("Own the stock BEFORE the ex-date to qualify for the next dividend payment.")
        for p in upcoming:
            urgency = "🔴" if p["days_to_ex"] <= 5 else ("🟡" if p["days_to_ex"] <= 14 else "🟢")
            st.markdown(
                f"{urgency} **{p['ticker']}** — Ex-date **{p['ex_date']}** "
                f"({p['days_to_ex']} days) · Yield {p['yield_pct']:.2f}% · ${p['rate']:.4f}/share"
            )

    # ── Drill into a dividend stock ───────────────────────────────────────────
    st.markdown("---")
    st.subheader("🔍 Analyze a dividend stock in detail")
    tickers_in_list = [p["ticker"] for p in filtered]
    pick = st.selectbox("Select a stock:", tickers_in_list)
    if pick:
        show_single_stock(pick, "2y")


# ── Options & Futures helper ──────────────────────────────────────────────────
def pick_best_expiry(expirations: list) -> str:
    from datetime import datetime, date
    today = date.today()
    best = None
    for exp in expirations:
        try:
            days = (datetime.strptime(exp, "%Y-%m-%d").date() - today).days
            if 21 <= days <= 50:
                return exp
            if best is None and days > 14:
                best = exp
        except Exception:
            pass
    return best or expirations[0]


def score_option_row(row, current_price: float, is_call: bool) -> float:
    score = 0.0
    strike     = row["strike"]
    moneyness  = (strike - current_price) / current_price

    if is_call:
        if  0.00 <= moneyness <= 0.03:  score += 3
        elif 0.03 < moneyness <= 0.06:  score += 1
    else:
        if -0.03 <= moneyness <= 0.00:  score += 3
        elif -0.06 <= moneyness < -0.03: score += 1

    vol = row.get("volume") or 0
    if vol > 1000:  score += 2
    elif vol > 200: score += 1

    iv = row.get("impliedVolatility") or 0
    if iv < 0.50:  score += 2
    elif iv < 0.80: score += 1

    bid = row.get("bid") or 0
    ask = row.get("ask") or 0
    mid = (bid + ask) / 2 if (bid + ask) > 0 else 1
    spread_pct = (ask - bid) / mid if mid > 0 else 1
    if spread_pct < 0.05:  score += 2
    elif spread_pct < 0.10: score += 1

    return score


def show_options(ticker: str, current_price: float, hist: pd.DataFrame, overall_signal: str):
    from datetime import datetime, date

    stock  = yf.Ticker(ticker)
    latest = hist.iloc[-1]
    atr    = float(hist["ATR"].iloc[-1]) if "ATR" in hist.columns else float((hist["High"] - hist["Low"]).rolling(14).mean().iloc[-1])

    st.markdown("## 🧭 Step 1 — Should you buy a Call or Put?")

    bullish = overall_signal in ("STRONG BUY", "BUY")
    bearish = overall_signal in ("STRONG SELL", "SELL")

    if bullish:
        st.success(f"""
**→ Buy a CALL option**

Technicals say the stock is likely going UP ({overall_signal}).
A **Call** gives you the right to buy at a locked-in price — you profit when the stock rises.
""")
        trade_type = "CALL"
    elif bearish:
        st.error(f"""
**→ Buy a PUT option**

Technicals say the stock is likely going DOWN ({overall_signal}).
A **Put** gives you the right to sell at a locked-in price — you profit when the stock falls.
""")
        trade_type = "PUT"
    else:
        st.warning(f"""
**→ Sit this one out ({overall_signal})**

Signals are mixed or weak. Buying an option here is closer to gambling than investing.
Wait for a STRONG BUY or BUY signal (score ≥ 4) before entering.
""")
        return

    # ── Step 2: Which expiry? ─────────────────────────────────────────────────
    st.markdown("## 📅 Step 2 — Which expiry date?")
    try:
        expirations = stock.options
    except Exception:
        st.warning("Options data not available for this ticker.")
        return

    if not expirations:
        st.warning("No options data available.")
        return

    recommended_exp = pick_best_expiry(expirations)
    rec_days = (datetime.strptime(recommended_exp, "%Y-%m-%d").date() - date.today()).days

    st.info(f"""
**→ Recommended expiry: {recommended_exp} ({rec_days} days away)**

Options lose value every day (time decay). **3–6 weeks is the sweet spot.**
- < 2 weeks = fast decay, no time for the trade to work — risky
- > 3 months = expensive, you pay for time you don't need
""")

    # Price comparison across expiries
    st.markdown("#### 💡 Same strike, different expiries — here's the cost difference:")
    try:
        is_call_preview = (trade_type == "CALL")
        comp_rows = []
        for e in expirations[:8]:
            try:
                d  = (datetime.strptime(e, "%Y-%m-%d").date() - date.today()).days
                ch = stock.option_chain(e)
                opts = ch.calls if is_call_preview else ch.puts
                closest = opts.iloc[(opts["strike"] - current_price).abs().argsort()[:1]]
                if not closest.empty:
                    r    = closest.iloc[0]
                    risk = "⚠️ Very risky" if d < 14 else ("✅ Recommended" if 21 <= d <= 50 else ("💸 Pricey" if d > 90 else "OK"))
                    comp_rows.append({
                        "Expiry":          e,
                        "Days Left":       d,
                        "Strike":          f"${r['strike']:.0f}",
                        "Cost/share":      f"${r['lastPrice']:.2f}",
                        "1 contract":      f"${r['lastPrice']*100:,.0f}",
                        "Breakeven":       f"${r['strike']+r['lastPrice']:.2f}" if is_call_preview else f"${r['strike']-r['lastPrice']:.2f}",
                        "Verdict":         risk,
                    })
            except Exception:
                pass
        if comp_rows:
            st.dataframe(pd.DataFrame(comp_rows), use_container_width=True, hide_index=True)
    except Exception:
        pass

    all_exps_labeled = []
    for e in expirations:
        try:
            d = (datetime.strptime(e, "%Y-%m-%d").date() - date.today()).days
            lbl = f"{e}  ({d}d)"
            if e == recommended_exp: lbl += "  ✅ recommended"
            elif d < 14:             lbl += "  ⚠️ too short"
            elif d > 90:             lbl += "  💸 expensive"
            all_exps_labeled.append((lbl, e))
        except Exception:
            all_exps_labeled.append((e, e))

    selected_label = st.selectbox(
        "Choose expiry date",
        [l for l, _ in all_exps_labeled],
        index=next((i for i, (_, e) in enumerate(all_exps_labeled) if e == recommended_exp), 0),
        key=f"expiry_{ticker}"
    )
    selected_exp  = dict(all_exps_labeled)[selected_label]
    selected_days = (datetime.strptime(selected_exp, "%Y-%m-%d").date() - date.today()).days

    if selected_days < 14:
        st.warning(f"⚠️ Only {selected_days} days to expiry — very high risk. Stock has little time to move.")

    # ── Step 3: Which strike? ─────────────────────────────────────────────────
    st.markdown("## 🎯 Step 3 — Which strike price?")
    try:
        chain   = stock.option_chain(selected_exp)
        is_call = (trade_type == "CALL")
        options = chain.calls.copy() if is_call else chain.puts.copy()
    except Exception as e:
        st.warning(f"Could not load options chain: {e}")
        return

    if options.empty:
        st.warning("No options available for this expiry.")
        return

    if is_call:
        relevant = options[(options["strike"] >= current_price * 0.95) & (options["strike"] <= current_price * 1.12)].copy()
    else:
        relevant = options[(options["strike"] >= current_price * 0.88) & (options["strike"] <= current_price * 1.05)].copy()

    if relevant.empty:
        relevant = options.copy()

    relevant["_score"] = relevant.apply(lambda r: score_option_row(r, current_price, is_call), axis=1)
    best = relevant.loc[relevant["_score"].idxmax()]

    premium   = best["lastPrice"]
    strike    = best["strike"]
    cost      = round(premium * 100, 2)
    breakeven = round(strike + premium, 2) if is_call else round(strike - premium, 2)
    be_move   = round(abs(breakeven - current_price) / current_price * 100, 2)
    # ATR-based take profit: sell when stock reaches 2×ATR from current
    tp_premium  = round(premium * 2.0, 2)
    sl_premium  = round(premium * 0.45, 2)
    iv          = best.get("impliedVolatility", 0)
    volume      = int(best.get("volume") or 0)
    delta       = best.get("delta", None)
    moneyness   = "ATM" if abs(strike - current_price) / current_price < 0.01 else \
                  ("OTM" if (is_call and strike > current_price) or (not is_call and strike < current_price) else "ITM")

    action_box = st.success if is_call else st.error
    emoji      = "📈" if is_call else "📉"
    direction  = "rise above" if is_call else "fall below"

    action_box(f"""
### {emoji} Recommended {trade_type}: Strike **${strike}** — Expiry **{selected_exp}**

You're betting that **{ticker}** will {direction} **${breakeven}** before {selected_exp}.

| Detail | Value |
|---|---|
| Strike price | ${strike} ({moneyness}) |
| Premium (cost per share) | ${premium:.2f} |
| Total cost — 1 contract | **${cost:,.2f}** (= 100 shares × ${premium:.2f}) |
| Breakeven price | **${breakeven}** (stock must {direction} this) |
| Stock needs to move | {be_move}% from current ${current_price:.2f} |
| Expiry | {selected_exp} ({selected_days} days away) |
| Implied Volatility | {iv*100:.1f}% |
| Volume today | {volume:,} contracts |
""")

    st.markdown("---")
    st.markdown("## 💰 Step 4 — When to sell?")

    col1, col2, col3 = st.columns(3)
    col1.metric("✅ Take Profit — sell option at", f"${tp_premium:.2f}",
                help="Sell when option premium doubles — lock in ~100% gain")
    col2.metric("🛑 Stop Loss — sell option at",  f"${sl_premium:.2f}",
                help="Exit if option loses 55% — stop the bleeding")
    col3.metric("🎯 Equivalent stock price",       f"${breakeven + atr:.2f}" if is_call else f"${breakeven - atr:.2f}",
                help="If stock reaches this, your option is well in profit")

    st.info(f"""
**Simple 4-rule playbook:**
1. **Buy** the ${strike} {trade_type} for ~${premium:.2f}/share (${cost:,.2f} for 1 contract)
2. **Sell** if the option price hits **${tp_premium:.2f}** → doubled your money ✅
3. **Sell** if the option price drops to **${sl_premium:.2f}** → cut the loss 🛑
4. **Don't hold past 1 week before expiry** — time decay accelerates sharply in the last week

> 1 contract = 100 shares. You're never buying the actual stock.
""")

    # Full table
    st.markdown("---")
    with st.expander("📋 Full options chain for this expiry"):
        display = relevant[["strike","lastPrice","bid","ask","volume","openInterest","impliedVolatility","inTheMoney"]].copy()
        display.columns = ["Strike","Last","Bid","Ask","Volume","OI","IV","ITM"]
        display["IV"]  = display["IV"].apply(lambda x: f"{x*100:.1f}%")
        display["Pick"] = display["Strike"].apply(lambda s: "✅ Best" if s == strike else "")
        st.dataframe(display, use_container_width=True, hide_index=True)


# ── Single-stock view ─────────────────────────────────────────────────────────
def show_single_stock(ticker: str, period: str, resolved_from: str = ""):
    with st.spinner(f"Fetching {ticker}..."):
        try:
            hist, info = get_stock_data(ticker, period)
        except Exception as e:
            st.error(f"Failed to fetch data: {e}")
            return

    if hist.empty:
        st.error(f"No data for **{ticker}**. Check the name and try again.")
        return

    if resolved_from and resolved_from.upper() != ticker:
        st.info(f'"{resolved_from}" → **{ticker}** — {info.get("longName", ticker)}')

    hist = calculate_indicators(hist)
    signals, overall, color, score = generate_signal(hist, info=info, ticker=ticker)
    latest, prev = hist.iloc[-1], hist.iloc[-2]
    change     = latest["Close"] - prev["Close"]
    change_pct = (change / prev["Close"]) * 100
    current_price = float(latest["Close"])

    # ── Metrics row ──────────────────────────────────────────────────────────
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Price",     f"${current_price:.2f}", f"{change:+.2f} ({change_pct:+.2f}%)")
    c2.metric("Volume",    f"{int(latest['Volume']):,}")
    mc = info.get("marketCap")
    c3.metric("Market Cap", f"${mc/1e9:.2f}B" if mc else "N/A")
    pe = info.get("trailingPE")
    c4.metric("P/E Ratio",  f"{pe:.1f}" if isinstance(pe, float) else "N/A")
    c5.metric("52W Low",   f"${info.get('fiftyTwoWeekLow',0):.2f}"  if info.get('fiftyTwoWeekLow')  else "N/A")
    c6.metric("52W High",  f"${info.get('fiftyTwoWeekHigh',0):.2f}" if info.get('fiftyTwoWeekHigh') else "N/A")

    st.markdown("---")

    # ── Your Position callout (if held in portfolio) ──────────────────────────
    portfolio      = load_portfolio()
    held           = next((h for h in portfolio.get("holdings", []) if h["ticker"] == ticker), None)
    if held:
        import math as _math
        h_shares   = held["shares"]
        h_avg      = held["avg_cost"]
        h_invested = h_shares * h_avg
        h_value    = h_shares * current_price
        h_gain     = h_value - h_invested
        h_gain_pct = (h_gain / h_invested * 100) if h_invested else 0
        g_color    = "#4CAF50" if h_gain >= 0 else "#f44336"
        g_arrow    = "▲" if h_gain >= 0 else "▼"

        st.markdown(
            f"<div style='border:1px solid {g_color};border-radius:10px;padding:14px 18px;"
            f"background:rgba(0,0,0,0.25);margin-bottom:12px;'>"
            f"<span style='font-size:1.1em;font-weight:bold;'>📂 You own this stock</span> &nbsp; "
            f"<span style='color:{g_color};font-weight:bold;'>{g_arrow} {h_gain_pct:+.2f}%</span>"
            f"</div>",
            unsafe_allow_html=True,
        )
        p1, p2, p3, p4, p5 = st.columns(5)
        p1.metric("Shares Held",    f"{h_shares:.3f}")
        p2.metric("Avg Cost",       f"${h_avg:.2f}")
        p3.metric("Current Value",  f"${h_value:,.2f}", f"{h_gain_pct:+.2f}%")
        p4.metric("Unrealized G/L", f"${h_gain:+,.2f}")
        pct_to_be = ((h_avg - current_price) / current_price * 100) if h_gain < 0 and current_price else 0
        p5.metric("Break-even" if h_gain < 0 else "Profit",
                  f"${h_avg:.2f}" if h_gain < 0 else f"${h_gain:,.2f}",
                  f"need +{pct_to_be:.1f}% to recover" if h_gain < 0 else "unrealized")

        # Contextual advice combining signal + position
        sig_after = overall   # determined just above
        sc_after  = score
        if h_gain >= 0:
            # Profitable position
            if sig_after in ("STRONG SELL", "SELL"):
                advice = (f"You're up **{h_gain_pct:.1f}%** and the signal is **{sig_after}**. "
                          "This could be a good moment to **take profits** — at least partially. "
                          "Consider selling enough to lock in gains while letting the rest ride.")
                adv_fn = st.warning
            elif sig_after in ("STRONG BUY", "BUY"):
                advice = (f"You're up **{h_gain_pct:.1f}%** and momentum is still **{sig_after}**. "
                          "The trend is in your favour — you can **hold or add** to the position.")
                adv_fn = st.success
            else:
                advice = (f"You're up **{h_gain_pct:.1f}%** with a **{sig_after}** signal. "
                          "No urgency — hold and re-evaluate if the signal strengthens either way.")
                adv_fn = st.info
        else:
            # Losing position
            pct_needed = abs(pct_to_be)
            if sig_after in ("STRONG BUY", "BUY") and h_gain_pct > -30:
                advice = (f"You're down **{abs(h_gain_pct):.1f}%** but the signal is **{sig_after}**. "
                          f"Technicals suggest the stock may be turning — this could be an opportunity to "
                          f"**average down** and lower your break-even (currently ${h_avg:.2f}, needs +{pct_needed:.1f}% to recover). "
                          "See the Loss Recovery section in My Portfolio for a calculator.")
                adv_fn = st.success
            elif sig_after in ("STRONG SELL", "SELL") or h_gain_pct < -35:
                advice = (f"You're down **{abs(h_gain_pct):.1f}%** and the signal is **{sig_after}**. "
                          f"Continuing to hold a deteriorating position risks deeper losses. "
                          f"Consider **cutting the loss** — the ${abs(h_gain):,.2f} realised loss can be used to "
                          "offset capital gains for tax purposes.")
                adv_fn = st.error
            else:
                advice = (f"You're down **{abs(h_gain_pct):.1f}%** with a **{sig_after}** signal. "
                          f"No strong technical case to add yet — hold and wait for a clearer BUY signal "
                          f"before averaging down. Break-even is ${h_avg:.2f} (+{pct_needed:.1f}%).")
                adv_fn = st.warning
        adv_fn(f"**What to do with your position:** {advice}")
        st.markdown("---")

    # ── Overall signal banner ─────────────────────────────────────────────────
    icons = {"STRONG BUY":"🚀","BUY":"✅","WEAK BUY":"📈","HOLD":"⏸️",
             "WEAK SELL":"📉","SELL":"⚠️","STRONG SELL":"🛑"}
    score_bar = ("▓" * max(0, score) + "░" * max(0, 10 - score)) if score > 0 else \
                ("▓" * max(0, -score) + "░" * max(0, 10 + score))
    msg = f"{icons.get(overall,'')} **Overall Signal: {overall}** &nbsp;&nbsp; Score: **{score}/10**"
    if color == "green":  st.success(msg, icon=None)
    elif color == "red":  st.error(msg, icon=None)
    else:                 st.warning(msg, icon=None)

    # ── Trade Setup box ───────────────────────────────────────────────────────
    setup = get_trade_setup(hist, overall, current_price)
    if setup:
        arrow = "🟢 LONG" if setup["is_long"] else "🔴 SHORT"
        verb  = "Buy" if setup["is_long"] else "Short/Put"
        st.markdown(f"### 🎯 Trade Setup — {arrow}")
        col_a, col_b, col_c, col_d, col_e = st.columns(5)
        col_a.metric(f"{verb} Zone",  f"${setup['entry_low']} – ${setup['entry_high']}", help="Enter anywhere in this range")
        col_b.metric("Target 1",      f"${setup['target1']}",  help=f"+{abs(setup['target1']-current_price):.2f} from entry (~2× ATR)")
        col_c.metric("Target 2",      f"${setup['target2']}",  help=f"+{abs(setup['target2']-current_price):.2f} from entry (~3.5× ATR)")
        col_d.metric("Stop Loss",     f"${setup['stop_loss']}", help=f"Exit if price reaches this (1.5× ATR away)")
        col_e.metric("Risk / Reward", f"1 : {setup['rr']}",    help="For every $1 you risk, you could gain this")
        st.caption(f"ATR = ${setup['atr']} — based on last 14 days average true range. Entry zone = current ±¼ ATR.")
        st.markdown("---")
    else:
        if overall not in ("STRONG BUY","BUY","STRONG SELL","SELL"):
            st.info(f"⚠️ No clear trade setup — signal is **{overall}** (score {score}/10). Wait for a stronger signal before entering.")
            st.markdown("---")

    # ── Charts ───────────────────────────────────────────────────────────────
    fig = make_subplots(rows=3, cols=1, shared_xaxes=True,
                        subplot_titles=("Price & Indicators","MACD","RSI"),
                        row_heights=[0.6, 0.2, 0.2], vertical_spacing=0.05)
    fig.add_trace(go.Candlestick(x=hist.index, open=hist["Open"], high=hist["High"],
                                 low=hist["Low"], close=hist["Close"], name="Price"), row=1, col=1)
    fig.add_trace(go.Scatter(x=hist.index, y=hist["SMA_20"],   name="SMA 20",   line=dict(color="orange", width=1)), row=1, col=1)
    fig.add_trace(go.Scatter(x=hist.index, y=hist["SMA_50"],   name="SMA 50",   line=dict(color="blue",   width=1)), row=1, col=1)
    fig.add_trace(go.Scatter(x=hist.index, y=hist["BB_upper"], name="BB Upper", line=dict(color="gray", dash="dash", width=1), showlegend=False), row=1, col=1)
    fig.add_trace(go.Scatter(x=hist.index, y=hist["BB_lower"], name="BB Lower", line=dict(color="gray", dash="dash", width=1),
                             fill="tonexty", fillcolor="rgba(180,180,180,0.1)"), row=1, col=1)

    # Draw trade setup levels on chart
    if setup:
        line_color  = "rgba(76,175,80,0.7)"  if setup["is_long"] else "rgba(244,67,54,0.7)"
        sl_color    = "rgba(244,67,54,0.7)"
        fig.add_hline(y=setup["target1"],   line_dash="dot",  line_color=line_color,  annotation_text="T1",  row=1, col=1)
        fig.add_hline(y=setup["target2"],   line_dash="dot",  line_color=line_color,  annotation_text="T2",  row=1, col=1)
        fig.add_hline(y=setup["stop_loss"], line_dash="dash", line_color=sl_color,    annotation_text="SL",  row=1, col=1)

    fig.add_trace(go.Scatter(x=hist.index, y=hist["MACD"],        name="MACD",   line=dict(color="blue")),   row=2, col=1)
    fig.add_trace(go.Scatter(x=hist.index, y=hist["Signal_Line"], name="Signal", line=dict(color="orange")), row=2, col=1)
    fig.add_trace(go.Bar(x=hist.index, y=hist["MACD_Hist"], name="Hist",
                         marker_color=["green" if v >= 0 else "red" for v in hist["MACD_Hist"]], showlegend=False), row=2, col=1)
    fig.add_trace(go.Scatter(x=hist.index, y=hist["RSI"], name="RSI", line=dict(color="purple")), row=3, col=1)
    fig.add_hline(y=70, line_dash="dash", line_color="red",   annotation_text="70", row=3, col=1)
    fig.add_hline(y=30, line_dash="dash", line_color="green", annotation_text="30", row=3, col=1)
    fig.update_layout(height=750, xaxis_rangeslider_visible=False, template="plotly_dark",
                      legend=dict(orientation="h"))
    st.plotly_chart(fig, use_container_width=True)

    # ── Signal breakdown table ────────────────────────────────────────────────
    st.subheader("📊 Signal Breakdown (7 criteria)")
    st.dataframe(pd.DataFrame(signals, columns=["Indicator","Signal","Reason"]),
                 use_container_width=True, hide_index=True)

    # ── Fundamentals ─────────────────────────────────────────────────────────
    with st.expander("📋 Company Info & Fundamentals"):
        col1, col2, col3 = st.columns(3)
        col1.markdown(f"**Name:** {info.get('longName', ticker)}")
        col1.markdown(f"**Sector:** {info.get('sector','N/A')}")
        col1.markdown(f"**Industry:** {info.get('industry','N/A')}")
        col1.markdown(f"**Country:** {info.get('country','N/A')}")
        col2.markdown(f"**EPS (TTM):** {info.get('trailingEps','N/A')}")
        col2.markdown(f"**Forward P/E:** {info.get('forwardPE','N/A')}")
        col2.markdown(f"**PEG Ratio:** {info.get('pegRatio','N/A')}")
        col2.markdown(f"**Beta:** {info.get('beta','N/A')}")
        dy = info.get("dividendYield")
        col2.markdown(f"**Dividend Yield:** {dy*100:.2f}%" if dy else "**Dividend Yield:** N/A")
        target = info.get("targetMeanPrice")
        upside = ((target - current_price) / current_price * 100) if target else None
        col3.markdown(f"**Analyst Target:** {'${:.2f}'.format(target) if target else 'N/A'}")
        col3.markdown(f"**Upside Potential:** {upside:+.1f}%" if upside else "**Upside Potential:** N/A")
        col3.markdown(f"**Recommendation:** {info.get('recommendationKey','N/A').upper()}")
        col3.markdown(f"**# Analysts:** {info.get('numberOfAnalystOpinions','N/A')}")
        summary = info.get("longBusinessSummary","")
        if summary:
            st.markdown("**About:**")
            st.write(summary[:600] + ("..." if len(summary) > 600 else ""))

    # ── Dividend Analysis ─────────────────────────────────────────────────────
    if info.get("dividendYield"):
        st.markdown("---")
        with st.expander("💰 Dividend Analysis — Yield, Safety Score & Income Calculator", expanded=True):
            show_dividend_analysis(ticker, info, current_price)

    # ── Options Advisor ───────────────────────────────────────────────────────
    st.markdown("---")
    st.markdown("## 📊 Options Advisor")
    show_options(ticker, current_price, hist, overall)

    # ── News ──────────────────────────────────────────────────────────────────
    st.markdown("---")
    st.subheader("📰 Recent News")
    try:
        news = yf.Ticker(ticker).news
        if news:
            for a in news[:6]:
                c       = a.get("content", {})
                title   = c.get("title", "No title")
                prov    = c.get("provider", {}).get("displayName", "Unknown")
                url     = c.get("canonicalUrl", {}).get("url", "#")
                pub     = c.get("pubDate", "")[:10]
                st.markdown(f"- **[{title}]({url})** — *{prov}* {'· '+pub if pub else ''}")
        else:
            st.write("No recent news found.")
    except Exception:
        st.write("News unavailable.")

    # ── AI Chat ───────────────────────────────────────────────────────────────
    st.markdown("---")
    st.subheader("🤖 Ask Claude About This Stock")
    st.caption("Claude has full context of the signals, price, fundamentals and your position")

    # Build context string for Claude
    held_ctx = ""
    portfolio  = load_portfolio()
    held       = next((h for h in portfolio.get("holdings", []) if h["ticker"] == ticker), None)
    if held:
        h_val   = held["shares"] * current_price
        h_gain  = h_val - held["shares"] * held["avg_cost"]
        held_ctx = (
            f"\nUSER'S POSITION: {held['shares']} shares, avg cost ${held['avg_cost']:.2f}, "
            f"current value ${h_val:,.2f}, unrealized P&L ${h_gain:+,.2f} "
            f"({(h_gain / (held['shares']*held['avg_cost'])*100):+.1f}%)"
        )

    ctx = (
        f"STOCK: {ticker} — {info.get('longName', ticker)}\n"
        f"Sector: {info.get('sector','N/A')} | Industry: {info.get('industry','N/A')}\n"
        f"Current Price: ${current_price:.2f} | Day Change: {change:+.2f} ({change_pct:+.2f}%)\n"
        f"Signal: {overall} (score {score}/10)\n"
        f"RSI: {latest['RSI']:.1f} | MACD hist: {latest['MACD_Hist']:.4f}\n"
        f"SMA20: ${latest['SMA_20']:.2f} | SMA50: ${latest['SMA_50']:.2f}\n"
        f"52W Low: ${info.get('fiftyTwoWeekLow',0):.2f} | 52W High: ${info.get('fiftyTwoWeekHigh',0):.2f}\n"
        f"P/E: {info.get('trailingPE','N/A')} | Forward P/E: {info.get('forwardPE','N/A')}\n"
        f"Market Cap: {'${:.2f}B'.format(info['marketCap']/1e9) if info.get('marketCap') else 'N/A'}\n"
        f"Analyst target: ${info.get('targetMeanPrice','N/A')} | Recommendation: {info.get('recommendationKey','N/A').upper()}\n"
        f"Dividend Yield: {'{:.2f}%'.format(info['dividendYield']*100) if info.get('dividendYield') else 'N/A'}"
        + held_ctx
    )
    if setup:
        ctx += (
            f"\nTrade Setup: Entry ${setup['entry_low']}–${setup['entry_high']}, "
            f"Target1 ${setup['target1']}, Target2 ${setup['target2']}, "
            f"Stop ${setup['stop_loss']}, R/R 1:{setup['rr']}"
        )

    show_ai_chat(system_context=ctx, chat_key=ticker)


# ── Sector view ───────────────────────────────────────────────────────────────
def show_sector(sector_data: dict, period: str):
    name    = sector_data["name"]
    etf     = sector_data["etf"]
    tickers = sector_data["tickers"]

    st.subheader(f"🏭 Sector: {name}  |  ETF Benchmark: {etf}")

    rows = []
    progress = st.progress(0, text="Loading sector stocks…")
    for i, t in enumerate(tickers):
        try:
            hist, info = get_stock_data(t, period)
            if hist.empty:
                continue
            hist = calculate_indicators(hist)
            _, overall, color, score = generate_signal(hist)
            latest, prev = hist.iloc[-1], hist.iloc[-2]
            change_pct = (latest["Close"] - prev["Close"]) / prev["Close"] * 100
            mc = info.get("marketCap", 0)
            rows.append({
                "Ticker":     t,
                "Company":    info.get("shortName", t),
                "Price":      f"${latest['Close']:.2f}",
                "Day %":      f"{change_pct:+.2f}%",
                "Signal":     overall,
                "Score":      score,
                "Mkt Cap":    f"${mc/1e9:.1f}B" if mc else "N/A",
                "P/E":        f"{info.get('trailingPE',0):.1f}" if isinstance(info.get("trailingPE"), float) else "N/A",
                "_color":     color,
                "_hist":      hist,
            })
        except Exception:
            pass
        progress.progress((i + 1) / len(tickers), text=f"Loaded {t}")
    progress.empty()

    if not rows:
        st.error("Could not load sector data.")
        return

    df_rows = pd.DataFrame(rows)
    counts  = df_rows["Signal"].value_counts()
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("🟢 Buy signals",   counts.get("STRONG BUY",0) + counts.get("BUY",0) + counts.get("WEAK BUY",0))
    col2.metric("⏸️ Hold",          counts.get("HOLD",0))
    col3.metric("🔴 Sell signals",  counts.get("STRONG SELL",0) + counts.get("SELL",0) + counts.get("WEAK SELL",0))
    col4.metric("Stocks Analyzed",  len(df_rows))

    st.markdown("---")
    st.subheader("📊 Sector Leaderboard (sorted by score)")
    display_df = df_rows[["Ticker","Company","Price","Day %","Signal","Score","Mkt Cap","P/E"]].sort_values("Score", ascending=False)
    st.dataframe(display_df, use_container_width=True, hide_index=True)

    st.subheader("📈 Normalized Performance (base = 100)")
    fig = go.Figure()
    for row in rows:
        h    = row["_hist"]
        norm = (h["Close"] / h["Close"].iloc[0]) * 100
        fig.add_trace(go.Scatter(x=h.index, y=norm, name=row["Ticker"], mode="lines"))
    fig.update_layout(height=400, template="plotly_dark", yaxis_title="% Return (base 100)",
                      legend=dict(orientation="h"))
    st.plotly_chart(fig, use_container_width=True)

    st.markdown("---")
    st.subheader("🔍 Drill into a stock")
    pick = st.selectbox("Select a stock:", [r["Ticker"] for r in rows])
    if pick:
        show_single_stock(pick, period)


# ── Sidebar ───────────────────────────────────────────────────────────────────
st.sidebar.header("Settings")

# User info + logout
uname = st.session_state.get("user_name", "User")
urole = st.session_state.get("user_role", "viewer")
st.sidebar.markdown(f"👤 **{uname}** &nbsp; `{urole}`")
if st.sidebar.button("🚪 Logout", use_container_width=True):
    token = st.session_state.get("session_token", "")
    if token:
        _delete_session(token)
    st.query_params.clear()
    for k in ["logged_in", "username", "user_name", "user_role", "session_token"]:
        st.session_state.pop(k, None)
    st.rerun()
st.sidebar.markdown("---")

# Navigation mode
nav_options = ["📈 Analyze", "📂 My Portfolio", "🤖 AI Chat"]
if urole == "admin":
    nav_options += ["👥 Users", "🔑 Change Password"]
else:
    nav_options += ["🔑 Change Password"]

nav_mode = st.sidebar.radio(
    "View",
    nav_options,
    horizontal=True,
)

url_ticker = st.query_params.get("ticker", "")
default_q  = url_ticker if url_ticker else ""

query  = st.sidebar.text_input("Stock, company, or sector", value=default_q,
                                placeholder="e.g. Apple, TSLA, Technology, AI…",
                                disabled=(nav_mode in ("📂 My Portfolio", "🤖 AI Chat")))
period = st.sidebar.selectbox("Time Period", ["1mo","3mo","6mo","1y","2y","5y"], index=3)

st.sidebar.markdown("---")
st.sidebar.markdown("**Examples**")
st.sidebar.markdown("- `AAPL` or `Apple`")
st.sidebar.markdown("- `NVDA` or `Nvidia`")
st.sidebar.markdown("- `Technology` or `AI`")
st.sidebar.markdown("- `Healthcare` or `Pharma`")
st.sidebar.markdown("- `Semiconductors` or `Banking`")
st.sidebar.markdown("- `Dividend` or `High Yield`")
st.sidebar.markdown("- `Income` or `REIT`")

st.sidebar.markdown("---")
compare_input = st.sidebar.text_input("Compare stocks (comma-separated)", placeholder="e.g. MSFT, GOOGL")

# ── Refresh controls ──────────────────────────────────────────────────────────
st.sidebar.markdown("---")
st.sidebar.markdown("**🔄 Data Refresh**")
if st.sidebar.button("Refresh Now", use_container_width=True, type="primary"):
    st.cache_data.clear()
    st.rerun()

auto_refresh = st.sidebar.toggle("Auto Refresh", value=False)
if auto_refresh:
    interval_mins = st.sidebar.select_slider(
        "Refresh every",
        options=[1, 2, 5, 10, 15, 30],
        value=5,
        format_func=lambda x: f"{x} min",
    )
    count = st_autorefresh(interval=interval_mins * 60 * 1000, key="autorefresh")
    st.sidebar.caption(f"Auto-refreshing every {interval_mins} min · refresh #{count}")

# ── Route: non-analyze views ─────────────────────────────────────────────────
if nav_mode == "📂 My Portfolio":
    show_portfolio()
    st.stop()

if nav_mode == "🤖 AI Chat":
    show_ai_chat_page()
    st.stop()

if nav_mode == "👥 Users":
    if urole == "admin":
        _show_user_management()
    else:
        st.error("Admin access required.")
    st.stop()

if nav_mode == "🔑 Change Password":
    _show_change_password()
    st.stop()

# ── Live ticker + Top 5 picks (Analyze mode only) ────────────────────────────
render_ticker_bar()
show_top_picks()

# ── Route input ───────────────────────────────────────────────────────────────
if not query.strip():
    st.info("Enter a stock, company name, or sector in the sidebar.")
    st.stop()

sector_data   = resolve_sector(query)
is_dividend_q = resolve_dividend(query)
is_portfolio_q = resolve_portfolio(query)

if is_portfolio_q:
    show_portfolio()
elif is_dividend_q:
    show_dividend_stocks()
elif sector_data:
    show_sector(sector_data, period)
else:
    with st.spinner(f'Looking up "{query}"…'):
        ticker = search_ticker(query)
    show_single_stock(ticker, period, resolved_from=query)

# ── Comparison chart ──────────────────────────────────────────────────────────
if not sector_data and not is_dividend_q and not is_portfolio_q and compare_input:
    st.markdown("---")
    st.subheader("📊 Comparison Chart")
    resolved_main   = search_ticker(query)
    compare_tickers = [resolved_main] + [t.strip().upper() for t in compare_input.split(",") if t.strip()]
    fig_c = go.Figure()
    for t in compare_tickers:
        try:
            h, _ = get_stock_data(t, period)
            if not h.empty:
                norm = (h["Close"] / h["Close"].iloc[0]) * 100
                fig_c.add_trace(go.Scatter(x=h.index, y=norm, name=t, mode="lines"))
        except Exception:
            st.warning(f"Could not load {t}")
    fig_c.update_layout(title="Normalized Price Performance (base = 100)", template="plotly_dark",
                        yaxis_title="% Return", height=400)
    st.plotly_chart(fig_c, use_container_width=True)

st.markdown("---")
st.caption("Data from Yahoo Finance · refreshed every 5 min · not financial advice.")
