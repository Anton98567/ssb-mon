#!/usr/bin/env python3
"""ssb-mon: мониторинг пользователей Secret-Sing-Box (clash-api + box.log).

Демон опрашивает clash-api (127.0.0.1) каждые INTERVAL секунд, пишет
снапшоты памяти/трафика/соединений в SQLite и читает box.log (INFO),
извлекая события "[user] inbound connection to ..." для истории сессий.

Конфигурация через переменные окружения (парсится из CLI в приоритете):
  SSB_MON_API       API base, по умолчанию http://127.0.0.1:9090
  SSB_MON_SECRET    Bearer-секрет clash-api, по умолчанию пустой
  SSB_MON_DB        путь к SQLite, по умолчанию /var/lib/ssb-mon/state.db
  SSB_MON_LOG       путь к логу sing-box, по умолчанию /var/lib/sing-box/box.log
  SSB_MON_INTERVAL  период опроса, cек, по умолчанию 10

CLI: ssb-mon <online|traffic|mem|sessions|users|history>
Демон: ssb-mon daemon
"""

import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import urllib.request
from datetime import datetime

_VERSION = "2.0.1"

ENV_FILE = "/etc/ssb-mon/env"


def _load_env():
    """Секрет/адрес задаётся в /etc/ssb-mon/env (пишет install.sh) или в окружении."""
    for path in (ENV_FILE,):
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
        except OSError:
            pass


_load_env()

API = os.environ.get("SSB_MON_API", "http://127.0.0.1:9090")
SECRET = os.environ.get("SSB_MON_SECRET", "")
DB_PATH = os.environ.get("SSB_MON_DB", "/var/lib/ssb-mon/state.db")
LOG_PATH = os.environ.get("SSB_MON_LOG", "/var/lib/sing-box/box.log")
INTERVAL = float(os.environ.get("SSB_MON_INTERVAL", "10"))

LOG_ENTRY = re.compile(r"\[([^\]]+)\] inbound (?:packet )?connection to (\S+):(\d+)")

# /memory и /traffic — стрим-эндпоинты: ответ не закрывается, каждый кадр —
# отдельный JSON-объект подряд. Читаем один объект и рвём соединение.
STREAM_ENDPOINTS = {"/memory", "/traffic"}


def api(ep):
    req = urllib.request.Request(
        f"{API}{ep}",
        headers={"Authorization": f"Bearer {SECRET}"} if SECRET else {},
    )
    with urllib.request.urlopen(req, timeout=8) as r:
        obj = json.loads(read_first_json_chunk(r))
        if ep == "/memory" and obj.get("inuse", 0) == 0:
            # первый кадр стрима может быть нулевым — дочитываем живой
            obj = json.loads(read_first_json_chunk(r))
        return obj


def read_first_json_chunk(r):
    """Читаем байт за байтом, пока JSON-объект не закрылся (depth==0)."""
    buf = b""
    depth = 0
    in_str = False
    esc = False
    while True:
        chunk = r.read(1)
        if not chunk:
            break
        b = chunk[0]
        if in_str:
            buf += chunk
            if esc:
                esc = False
            elif b == 0x5C:  # backslash
                esc = True
            elif b == 0x22:  # "
                in_str = False
            continue
        if b == 0x22:
            in_str = True
            buf += chunk
            continue
        buf += chunk
        if b == 0x7B:  # {
            depth += 1
        elif b == 0x7D:  # }
            depth -= 1
            if depth == 0:
                return buf


def db_connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.execute("PRAGMA journal_mode=WAL")
    return con


def init_db(con):
    con.executescript("""
    CREATE TABLE IF NOT EXISTS snapshots (
        ts INTEGER PRIMARY KEY,
        mem_inuse INTEGER,
        conns INTEGER,
        up INTEGER,
        down INTEGER
    );
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT,
        src_ip TEXT,
        host TEXT,
        started_at INTEGER,
        ended_at INTEGER,
        up INTEGER,
        down INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user);
    CREATE TABLE IF NOT EXISTS users_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT,
        event TEXT,
        ts INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_users_log_user ON users_log(user);
    """)
    con.commit()


class LogWatcher:
    """Читает box.log с конца, отдаёт новые строки за итерацию."""

    def __init__(self, path):
        self.path = path
        self.offset = self._start_offset()

    def _start_offset(self):
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return 0
        return max(0, size - 200 * 1024)

    def poll(self):
        try:
            with open(self.path, "rb") as f:
                f.seek(self.offset)
                data = f.read()
                self.offset = f.tell()
        except OSError:
            return []
        try:
            return data.decode("utf-8", errors="replace").splitlines()
        except Exception:
            return []


def log_events(new_lines):
    out = []
    for ln in new_lines:
        m = LOG_ENTRY.search(ln)
        if m:
            user, host, port = m.groups()
            out.append({"user": user, "host": host, "port": port, "ts": int(time.time())})
    return out


def now_ts():
    return int(time.time())


def main_daemon():
    con = db_connect()
    init_db(con)
    watcher = LogWatcher(LOG_PATH)
    print(
        f"ssb-mon daemon v{_VERSION} start: api={API} db={DB_PATH} log={LOG_PATH} interval={INTERVAL:.0f}s",
        flush=True,
    )

    while True:
        t0 = time.time()
        mem_inuse = None
        clist = []
        try:
            conns = api("/connections") or {"connections": []}
            clist = conns.get("connections", [])
            mem = api("/memory") or {"inuse": 0}
            mem_inuse = mem.get("inuse", 0)
        except Exception as e:
            print(f"[{now_ts()}] api error: {e}", flush=True)

        if mem_inuse is not None:
            total_up = sum(c.get("upload", 0) for c in clist)
            total_down = sum(c.get("download", 0) for c in clist)
            con.execute(
                "INSERT OR REPLACE INTO snapshots(ts,mem_inuse,conns,up,down) VALUES(?,?,?,?,?)",
                (now_ts(), mem_inuse, len(clist), total_up, total_down),
            )

        for ev in log_events(watcher.poll()):
            con.execute(
                "INSERT INTO users_log(user,event,ts) VALUES(?,?,?)",
                (ev["user"], f"inbound {ev['host']}:{ev['port']}", ev["ts"]),
            )
        con.commit()

        time.sleep(max(0, INTERVAL - (time.time() - t0)))


def fmt_size(b):
    if b is None:
        return "-"
    b = int(b)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024 or unit == "TB":
            return f"{b:.1f} {unit}" if unit != "B" else f"{b} B"
        b /= 1024
    return f"{b:.1f} TB"


def fmt_dt(ts):
    if not ts:
        return "-"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def cmd_online():
    try:
        conns = api("/connections") or {"connections": []}
    except Exception as e:
        print(f"ERROR: {e}")
        return 1
    clist = conns.get("connections", [])
    if not clist:
        print("Нет активных подключений.")
        return 0
    by_ip = {}
    for c in clist:
        m = c.get("metadata", {})
        ip = m.get("sourceIP", "?")
        d = by_ip.setdefault(ip, {"conns": [], "up": 0, "down": 0, "start": None})
        d["conns"].append(c)
        d["up"] += c.get("upload", 0)
        d["down"] += c.get("download", 0)
        st = c.get("start")
        if st and (d["start"] is None or st < d["start"]):
            d["start"] = st

    print(f"{'IP клиента':<18} {'Соед.':>5} {'Uplink':>10} {'Downlink':>10} {'Начало (UTC)'}")
    for ip, d in sorted(by_ip.items()):
        st = d["start"]
        try:
            start_s = datetime.strptime(st, "%Y-%m-%dT%H:%M:%S.%f%z" if "." in st else "%Y-%m-%dT%H:%M:%S%z")
            start_f = start_s.strftime("%H:%M:%S")
        except Exception:
            start_f = st or "-"
        print(f"{ip:<18} {len(d['conns']):>5} {fmt_size(d['up']):>10} {fmt_size(d['down']):>10} {start_f}")
    return 0


def cmd_traffic():
    try:
        conns = api("/connections") or {"connections": []}
    except Exception as e:
        print(f"ERROR: {e}")
        return 1
    clist = conns.get("connections", [])
    up = sum(c.get("upload", 0) for c in clist)
    down = sum(c.get("download", 0) for c in clist)
    print(f"Текущий трафик (активные соединения): up {fmt_size(up)}, down {fmt_size(down)}, соединений {len(clist)}")
    return 0


def cmd_mem():
    con = db_connect()
    try:
        row = con.execute(
            "SELECT ts, mem_inuse FROM snapshots ORDER BY ts DESC LIMIT 1"
        ).fetchone()
    except sqlite3.OperationalError:
        row = None
    try:
        cur = api("/memory").get("inuse")
    except Exception:
        cur = None
    print(f"sing-box память (clash-api): {fmt_size(cur)}")
    try:
        r = subprocess.run(["ps", "-o", "rss=", "-C", "sing-box"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and r.stdout.split():
            print(f"sing-box RSS (процесс):      {fmt_size(int(r.stdout.split()[0]) * 1024)}")
    except Exception:
        pass
    if row:
        print(f"Последний снапшот:            {fmt_dt(row[0])} — {fmt_size(row[1])}")
    try:
        rows = con.execute(
            "SELECT ts, mem_inuse FROM snapshots WHERE ts>=? ORDER BY ts DESC LIMIT 500",
            (now_ts() - 86400,),
        ).fetchall()
        if len(rows) > 30:
            vals = [r[1] for r in rows]
            print(
                f"За 24ч (по снапшотам):       мин {fmt_size(min(vals))} / макс {fmt_size(max(vals))} / сейчас {fmt_size(vals[0])}"
            )
    except Exception:
        pass
    return 0


def cmd_sessions():
    con = db_connect()
    try:
        rows = con.execute(
            "SELECT user, ts, event FROM users_log ORDER BY ts DESC LIMIT 25"
        ).fetchall()
    except sqlite3.OperationalError:
        rows = []
    if not rows:
        print("Сессий (из лога) ещё нет.")
        return 0
    print(f"{'Время':<21} {'Пользователь':<18} {'Событие'}")
    for user, ts, event in rows:
        print(f"{fmt_dt(ts):<21} {user:<18} {event}")
    return 0


def cmd_users():
    con = db_connect()
    try:
        rows = con.execute("""
            SELECT user, COUNT(*), MIN(ts), MAX(ts) FROM users_log
            GROUP BY user ORDER BY MAX(ts) DESC LIMIT 30
        """).fetchall()
    except sqlite3.OperationalError:
        rows = []
    if not rows:
        print("Нет данных о подключениях пользователей.")
        return 0
    print(f"{'Пользователь':<18} {'Событий':>7} {'Первый':<20} {'Последний':<20}")
    for user, cnt, mn, mx in rows:
        print(f"{user:<18} {cnt:>7} {fmt_dt(mn):<20} {fmt_dt(mx):<20}")
    return 0


def cmd_history():
    con = db_connect()
    try:
        hours = con.execute(
            "SELECT (ts/3600)*3600, AVG(mem_inuse), COUNT(*) FROM snapshots "
            "GROUP BY (ts/3600)*3600 ORDER BY 1 DESC LIMIT 12"
        ).fetchall()
    except sqlite3.OperationalError:
        hours = []
    if not hours:
        print("Истории нет (демон не шлёт снапшоты).")
        return 0
    print(f"{'Час':<16} {'Память (средн.)':<16} {'Снапшотов'}")
    for h, mem, cnt in hours:
        print(f"{fmt_dt(h):<16} {fmt_size(mem):<16} {cnt}")
    return 0


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("daemon", "online", "traffic", "mem", "sessions", "users", "history"):
        print(f"ssb-mon v{_VERSION}")
        print("usage: ssb-mon <daemon|online|traffic|mem|sessions|users|history>")
        return 1
    cmd = sys.argv[1]
    if cmd == "daemon":
        main_daemon()
    elif cmd == "online":
        return cmd_online()
    elif cmd == "traffic":
        return cmd_traffic()
    elif cmd == "mem":
        return cmd_mem()
    elif cmd == "sessions":
        return cmd_sessions()
    elif cmd == "users":
        return cmd_users()
    elif cmd == "history":
        return cmd_history()


if __name__ == "__main__":
    sys.exit(main())
