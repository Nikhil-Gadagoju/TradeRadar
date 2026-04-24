"""
TradeRadar Telegram Alert Bot
Runs as a separate process on the Pi (pm2 start bot.py --name tradbot).
Scans a watchlist every 60 s during market hours and sends BUY/SELL alerts
with full trade setup (entry zone, sell targets, stop-loss, R/R).
"""

import json
import os
import time
import logging
import requests
import yfinance as yf
import pandas as pd
import numpy as np
from datetime import datetime
import pytz

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("tradbot")

# ── Config ────────────────────────────────────────────────────────────────────
_DIR         = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE  = os.path.join(_DIR, "config.json")
STATE_FILE   = os.path.join(_DIR, "bot_state.json")   # tracks last signal per ticker

DEFAULT_WATCHLIST = [
    "NVDA", "AAPL", "MSFT", "GOOGL", "META",
    "AMD",  "TSLA", "AMZN", "JPM",   "V",
]

SCAN_INTERVAL_SEC  = 60       # how often to scan (seconds)
ET_ZONE            = pytz.timezone("America/New_York")
MARKET_OPEN        = (9, 30)
MARKET_CLOSE       = (16, 0)
PRE_MARKET_OPEN    = (4, 0)   # scan pre-market too (optional, set below)
SCAN_PRE_MARKET    = False    # set True to also alert 4 AM–9:30 AM ET


def load_config() -> dict:
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def load_state() -> dict:
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_state(state: dict):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


# ── Telegram helpers ──────────────────────────────────────────────────────────

def _tg_url(token: str, method: str) -> str:
    return f"https://api.telegram.org/bot{token}/{method}"


def send_message(token: str, chat_id: str, text: str) -> bool:
    try:
        resp = requests.post(
            _tg_url(token, "sendMessage"),
            json={"chat_id": chat_id, "text": text, "parse_mode": "HTML"},
            timeout=10,
        )
        return resp.status_code == 200
    except Exception as e:
        log.error(f"Telegram send failed: {e}")
        return False


def get_updates(token: str, offset: int = 0) -> list:
    try:
        resp = requests.get(
            _tg_url(token, "getUpdates"),
            params={"offset": offset, "timeout": 5},
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json().get("result", [])
    except Exception:
        pass
    return []


# ── Market hours ──────────────────────────────────────────────────────────────

def is_scan_time() -> bool:
    now = datetime.now(ET_ZONE)
    if now.weekday() >= 5:          # Saturday / Sunday
        return False
    t = (now.hour, now.minute)
    if MARKET_OPEN <= t < MARKET_CLOSE:
        return True
    if SCAN_PRE_MARKET and PRE_MARKET_OPEN <= t < MARKET_OPEN:
        return True
    return False


def market_status() -> str:
    now = datetime.now(ET_ZONE)
    t   = (now.hour, now.minute)
    if now.weekday() >= 5:
        return "closed (weekend)"
    if MARKET_OPEN <= t < MARKET_CLOSE:
        return "open"
    if PRE_MARKET_OPEN <= t < MARKET_OPEN:
        return "pre-market"
    return "closed (after hours)"


# ── Indicators & Signal ───────────────────────────────────────────────────────

def calculate_indicators(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    close  = df["Close"].squeeze()
    high   = df["High"].squeeze()
    low    = df["Low"].squeeze()
    volume = df["Volume"].squeeze()

    df["EMA_9"]  = close.ewm(span=9,  adjust=False).mean()
    df["EMA_21"] = close.ewm(span=21, adjust=False).mean()
    df["SMA_20"] = close.rolling(20).mean()
    df["SMA_50"] = close.rolling(50).mean()

    ema12 = close.ewm(span=12, adjust=False).mean()
    ema26 = close.ewm(span=26, adjust=False).mean()
    df["MACD"]      = ema12 - ema26
    df["Sig_Line"]  = df["MACD"].ewm(span=9, adjust=False).mean()
    df["MACD_Hist"] = df["MACD"] - df["Sig_Line"]

    delta = close.diff()
    gain  = delta.clip(lower=0).rolling(14).mean()
    loss  = (-delta.clip(upper=0)).rolling(14).mean()
    df["RSI"] = 100 - 100 / (1 + gain / loss.replace(0, np.nan))

    hl = high - low
    hc = (high - close.shift()).abs()
    lc = (low  - close.shift()).abs()
    df["ATR"] = pd.concat([hl, hc, lc], axis=1).max(axis=1).rolling(14).mean()

    vol_ma = volume.rolling(20).mean()
    df["Vol_Ratio"] = volume / vol_ma.replace(0, np.nan)
    return df


def generate_signal(df: pd.DataFrame) -> tuple[str, int, dict]:
    """
    Returns (signal_str, score, details_dict).
    Fast technical-only scanner — no external API calls.
    """
    if len(df) < 26:
        return "HOLD", 0, {}

    latest = df.iloc[-1]
    prev   = df.iloc[-2]
    score  = 0
    info   = {}

    price    = float(latest["Close"])
    rsi      = float(latest["RSI"]) if not np.isnan(latest["RSI"]) else 50
    macd_h   = float(latest["MACD_Hist"])
    macd_h_p = float(prev["MACD_Hist"])
    ema9     = float(latest["EMA_9"])
    ema21    = float(latest["EMA_21"])
    sma20    = float(latest["SMA_20"])
    vol_r    = float(latest["Vol_Ratio"]) if not np.isnan(latest["Vol_Ratio"]) else 1.0

    # RSI
    info["rsi"] = rsi
    if rsi < 30:
        score += 3; info["rsi_note"] = "oversold"
    elif rsi < 40:
        score += 1; info["rsi_note"] = "approaching oversold"
    elif rsi > 70:
        score -= 3; info["rsi_note"] = "overbought"
    elif rsi > 60:
        score -= 1; info["rsi_note"] = "approaching overbought"
    else:
        info["rsi_note"] = "neutral"

    # MACD histogram direction
    info["macd_rising"] = macd_h > macd_h_p
    if macd_h > 0 and macd_h > macd_h_p:
        score += 2
    elif macd_h < 0 and macd_h < macd_h_p:
        score -= 2
    elif macd_h > macd_h_p:
        score += 1
    else:
        score -= 1

    # EMA 9/21 cross (day-trading trend)
    info["ema_bull"] = ema9 > ema21
    if ema9 > ema21:
        score += 1
    else:
        score -= 1

    # Price vs SMA20
    if price > sma20:
        score += 1
    else:
        score -= 1

    # Volume confirmation
    info["vol_ratio"] = vol_r
    if vol_r > 1.5:
        score += 1 if score > 0 else -1  # amplifies direction

    if score >= 5:
        return "STRONG BUY", score, info
    elif score >= 2:
        return "BUY", score, info
    elif score <= -5:
        return "STRONG SELL", score, info
    elif score <= -2:
        return "SELL", score, info
    else:
        return "HOLD", score, info


def get_trade_setup(df: pd.DataFrame, signal: str, price: float) -> dict | None:
    if signal not in ("STRONG BUY", "BUY", "STRONG SELL", "SELL"):
        return None

    atr     = float(df["ATR"].iloc[-1])
    is_long = "BUY" in signal

    if is_long:
        entry_low  = round(price - 0.25 * atr, 2)
        entry_high = round(price + 0.25 * atr, 2)
        stop_loss  = round(price - 1.5  * atr, 2)
        target1    = round(price + 2.0  * atr, 2)
        target2    = round(price + 3.5  * atr, 2)
    else:
        entry_low  = round(price - 0.25 * atr, 2)
        entry_high = round(price + 0.25 * atr, 2)
        stop_loss  = round(price + 1.5  * atr, 2)
        target1    = round(price - 2.0  * atr, 2)
        target2    = round(price - 3.5  * atr, 2)

    entry_mid        = (entry_low + entry_high) / 2
    risk_per_share   = abs(entry_mid - stop_loss)
    reward_per_share = abs(target1   - entry_mid)
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


# ── Alert formatting ──────────────────────────────────────────────────────────

def format_alert(ticker: str, price: float, signal: str, score: int,
                 info: dict, setup: dict | None, change_pct: float) -> str:
    now_et = datetime.now(ET_ZONE).strftime("%I:%M %p ET")
    is_buy  = "BUY" in signal
    emoji   = "🟢" if is_buy else "🔴"
    arrow   = "▲" if info.get("macd_rising") else "▼"
    vol_txt = f"{info.get('vol_ratio', 1):.1f}x vol"
    rsi_txt = f"RSI {info.get('rsi', 0):.0f} ({info.get('rsi_note', '')})"
    ema_txt = "EMA bull" if info.get("ema_bull") else "EMA bear"

    lines = [
        "📡 <b>TradeRadar Alert</b>",
        "━━━━━━━━━━━━━━━━━━",
        f"{emoji} <b>{signal} — {ticker}</b>",
        f"💲 Price: <b>${price:.2f}</b>  ({change_pct:+.2f}%)",
        f"📊 {rsi_txt}  •  MACD {arrow}  •  {vol_txt}  •  {ema_txt}",
    ]

    if setup:
        lines.append("")
        lines.append("🎯 <b>Trade Setup</b>")
        lines.append(f"  Entry zone:  ${setup['entry_low']} – ${setup['entry_high']}")

        t1_pct = (setup["target1"] - price) / price * 100
        t2_pct = (setup["target2"] - price) / price * 100
        sl_pct = (setup["stop_loss"] - price) / price * 100

        if is_buy:
            lines.append(f"  🎯 Sell T1:   ${setup['target1']}  ({t1_pct:+.1f}%)")
            lines.append(f"  🎯 Sell T2:   ${setup['target2']}  ({t2_pct:+.1f}%)")
        else:
            lines.append(f"  🎯 Buy back T1: ${setup['target1']}  ({t1_pct:+.1f}%)")
            lines.append(f"  🎯 Buy back T2: ${setup['target2']}  ({t2_pct:+.1f}%)")

        lines.append(f"  🛑 Stop loss: ${setup['stop_loss']}  ({sl_pct:+.1f}%)")
        lines.append(f"  ⚖️  R/R:       1 : {setup['rr']}")

    lines.append("")
    lines.append(f"⏰ {now_et}")
    return "\n".join(lines)


# ── Scanner ───────────────────────────────────────────────────────────────────

def scan_ticker(ticker: str) -> tuple[str, float, float, dict, dict | None] | None:
    """
    Fetch 5-min intraday data, compute signal + setup.
    Returns (signal, price, change_pct, info_dict, setup) or None on error.
    """
    try:
        df = yf.download(ticker, period="5d", interval="5m",
                         progress=False, auto_adjust=True)
        if df.empty or len(df) < 30:
            return None

        df       = calculate_indicators(df)
        close    = df["Close"].squeeze()
        price    = float(close.iloc[-1])
        prev_cls = float(close.iloc[-2])
        chg_pct  = (price - prev_cls) / prev_cls * 100

        signal, score, sig_info = generate_signal(df)
        setup = get_trade_setup(df, signal, price) if signal != "HOLD" else None
        return signal, price, chg_pct, sig_info, setup
    except Exception as e:
        log.warning(f"scan_ticker {ticker} error: {e}")
        return None


def run_scan(token: str, chat_id: str, watchlist: list[str], state: dict,
             min_score_threshold: int = 2) -> dict:
    """
    Scan all tickers. Send alert only when signal changes to BUY/SELL
    (avoids spamming the same alert every minute).
    Returns updated state dict.
    """
    for ticker in watchlist:
        result = scan_ticker(ticker)
        if result is None:
            continue

        signal, price, chg_pct, sig_info, setup = result
        prev_signal = state.get(ticker, {}).get("signal", "HOLD")

        # Alert only on signal transitions into actionable territory
        if signal in ("BUY", "STRONG BUY", "SELL", "STRONG SELL") and signal != prev_signal:
            log.info(f"ALERT  {ticker}  {prev_signal} → {signal}  ${price:.2f}")
            msg = format_alert(ticker, price, signal, 0, sig_info, setup, chg_pct)
            ok  = send_message(token, chat_id, msg)
            if ok:
                log.info(f"       Telegram sent ✓")
            else:
                log.warning(f"       Telegram send failed")
        else:
            log.debug(f"       {ticker}  {signal}  ${price:.2f}  (no change)")

        state[ticker] = {"signal": signal, "price": price, "ts": datetime.now(ET_ZONE).isoformat()}

    return state


# ── Command handler ───────────────────────────────────────────────────────────

def handle_commands(token: str, chat_id: str, watchlist: list[str], offset: int) -> int:
    updates = get_updates(token, offset)
    for upd in updates:
        offset = upd["update_id"] + 1
        msg    = upd.get("message", {})
        text   = msg.get("text", "").strip()
        from_id = str(msg.get("chat", {}).get("id", ""))

        if from_id != str(chat_id):
            continue   # ignore messages from other chats

        if text.startswith("/price "):
            sym = text.split()[-1].upper()
            res = scan_ticker(sym)
            if res:
                sig, price, chg, sinfo, setup = res
                reply = format_alert(sym, price, sig, 0, sinfo, setup, chg)
            else:
                reply = f"❌ Could not fetch data for {sym}"
            send_message(token, chat_id, reply)

        elif text == "/watchlist":
            send_message(token, chat_id,
                         "📋 <b>Watchlist</b>\n" + "  ".join(watchlist))

        elif text == "/status":
            send_message(token, chat_id,
                         f"📡 TradeRadar Bot\n"
                         f"Market: {market_status()}\n"
                         f"Watching: {len(watchlist)} tickers\n"
                         f"Scan interval: {SCAN_INTERVAL_SEC}s")

        elif text == "/help":
            send_message(token, chat_id,
                         "📖 <b>Commands</b>\n"
                         "/price TICKER  — instant signal for any ticker\n"
                         "/watchlist     — show current watchlist\n"
                         "/status        — bot + market status\n"
                         "/help          — this message")

    return offset


# ── Main loop ─────────────────────────────────────────────────────────────────

def main():
    log.info("TradeRadar Bot starting…")

    cfg        = load_config()
    token      = cfg.get("telegram_token", "")
    chat_id    = cfg.get("telegram_chat_id", "")
    watchlist  = cfg.get("alert_watchlist", DEFAULT_WATCHLIST)

    if not token or not chat_id:
        log.error("telegram_token or telegram_chat_id not set in config.json. "
                  "Add them via the Admin panel → Telegram Settings, then restart the bot.")
        return

    state     = load_state()
    tg_offset = 0
    last_scan = 0

    send_message(token, chat_id,
                 f"📡 <b>TradeRadar Bot started</b>\n"
                 f"Watching {len(watchlist)} tickers.\n"
                 f"Market is currently <b>{market_status()}</b>.\n"
                 f"Type /help for commands.")

    log.info(f"Watching: {watchlist}")

    while True:
        try:
            # Always handle commands (responsive even outside market hours)
            tg_offset = handle_commands(token, chat_id, watchlist, tg_offset)

            now = time.time()
            if is_scan_time() and (now - last_scan) >= SCAN_INTERVAL_SEC:
                log.info("Scanning…")
                state = run_scan(token, chat_id, watchlist, state)
                save_state(state)
                last_scan = now

            time.sleep(5)   # poll commands every 5 s

        except KeyboardInterrupt:
            log.info("Bot stopped by user.")
            send_message(token, chat_id, "⛔ TradeRadar Bot stopped.")
            break
        except Exception as e:
            log.error(f"Main loop error: {e}")
            time.sleep(30)


if __name__ == "__main__":
    main()
