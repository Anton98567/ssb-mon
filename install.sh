#!/usr/bin/env bash
# Установщик ssb-mon — мониторинг пользователей Secret-Sing-Box.
# Запуск одной командой (после установки SSB):
#   sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Anton98567/ssb-mon/main/install.sh)"
# Локально:  sudo bash install.sh
# Включает clash-api в /etc/sing-box/config.json (127.0.0.1:9090 + секрет),
# поднимает уровень лога sing-box до info и ставит systemd-сервис ssb-mon.

set -euo pipefail

# --- Настройки (при необходимости переопределить извне: SECRET=xxx bash install.sh)
SSB_MON_PORT="${SSB_MON_PORT:-9090}"
# если clash_api уже сконфигурирован — оставляем его секрет, иначе генерируем
if SECRET="${SECRET:-}"; then :; fi
if [[ -z "${SECRET:-}" ]] && command -v jq >/dev/null; then
    SECRET="$(jq -r '.experimental.clash_api.secret // empty' /etc/sing-box/config.json 2>/dev/null || true)"
fi
if [[ -z "${SECRET:-}" ]]; then
    SECRET="$(head -c 24 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 32)"
fi
INTERVAL="${SSB_MON_INTERVAL:-10}"
INSTALL_DIR="/usr/local/bin"
DATA_DIR="/var/lib/ssb-mon"
SERVICE_NAME="ssb-mon"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-.}")" && pwd)"

# Репозиторий для скачивания ssb-mon.py при установке одной командой
REPO_RAW="https://raw.githubusercontent.com/Anton98567/ssb-mon/main"

# поддержка mbox (Схема B: sing-box-форк с mieru, enfein/mbox): /opt/mbox/bin/mbox + /etc/mbox/config.json
BIN="sing-box"; SERVICE="sing-box"; CONFIG_PATH="/etc/sing-box/config.json"
if ! command -v sing-box >/dev/null 2>&1 && [[ -x /opt/mbox/bin/mbox && -f /etc/mbox/config.json ]]; then
    BIN="/opt/mbox/bin/mbox"; SERVICE="mbox"; CONFIG_PATH="/etc/mbox/config.json"
fi

log() { echo -e "\033[1;36m[ssb-mon]\033[0m $*"; }
err() { echo -e "\033[1;31m[ssb-mon][ERROR]\033[0m $*" >&2; }

[[ $EUID -eq 0 ]] || { err "Запусти от root (sudo bash install.sh)"; exit 1; }

command -v "$BIN" >/dev/null 2>&1 || [[ -x $BIN ]] || { err "$BIN не установлен — сначала поставь Secret-Sing-Box (или mbox для Схемы B)"; exit 1; }
[[ -f "$CONFIG_PATH" ]] || { err "Нет $CONFIG_PATH — конфиг SSB не найден"; exit 1; }
command -v python3 >/dev/null || { err "python3 не установлен"; exit 1; }

SRC_PY="$SRC_DIR/ssb-mon.py"
if [[ ! -f "$SRC_PY" ]]; then
    log "локального ssb-mon.py нет — качаю из $REPO_RAW/ssb-mon.py"
    command -v curl >/dev/null || { err "curl не установлен"; exit 1; }
    TMP_PY="$(mktemp)"
    trap 'rm -f "$TMP_PY"' EXIT
    curl -fsSL "$REPO_RAW/ssb-mon.py" -o "$TMP_PY"
    SRC_PY="$TMP_PY"
fi

log "Резервная копия конфига: $CONFIG_PATH.bak.ssb-mon"
cp -n "$CONFIG_PATH" "$CONFIG_PATH.bak.ssb-mon"

log "Обновляю $CONFIG_PATH: clash-api + log level info"
python3 - "$CONFIG_PATH" "$SSB_MON_PORT" "$SECRET" <<'PYEOF'
import json, sys

path, port, secret = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path) as f:
    cfg = json.load(f)

# log: level -> info (если уже выше - не трогаем)
levels = {"fatal": 0, "error": 1, "warn": 2, "info": 3, "debug": 4, "trace": 5}
level = (cfg.get("log") or {}).get("level", "info")
if levels.get(level, 0) < levels["info"]:
    cfg.setdefault("log", {})["level"] = "info"

# experimental.clash_api
exp = cfg.setdefault("experimental", {})
api = exp.setdefault("clash_api", {})
changed = (
    api.get("external_controller") != f"127.0.0.1:{port}"
    or api.get("secret") != secret
)
api["external_controller"] = f"127.0.0.1:{port}"
api["secret"] = secret

with open(path, "w") as f:
    json.dump(cfg, f, indent=2, ensure_ascii=False)
print("config updated" if changed else "config already ok")
PYEOF

"$BIN" check -c "$CONFIG_PATH" || { err "sing-box check провалился — конфиг повреждён, откат"; cp "$CONFIG_PATH.bak.ssb-mon" "$CONFIG_PATH"; exit 1; }
log "sing-box check: OK"

systemctl restart "$SERVICE"
log "$SERVICE перезапущен"

log "Устанавливаю $INSTALL_DIR/ssb-mon"
install -m 0755 "$SRC_PY" "$INSTALL_DIR/ssb-mon"

mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR"

log "Пишу конфигурацию /etc/ssb-mon/env"
mkdir -p /etc/ssb-mon
cat > /etc/ssb-mon/env <<EOF
SSB_MON_API=http://127.0.0.1:$SSB_MON_PORT
SSB_MON_SECRET=$SECRET
SSB_MON_INTERVAL=$INTERVAL
SSB_MON_DB=$DATA_DIR/state.db
SSB_MON_LOG=/var/lib/sing-box/box.log
EOF
chmod 600 /etc/ssb-mon/env

log "Пишу systemd-юнит $SERVICE_NAME.service"
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=SSB Monitor (clash-api + box.log watcher)
After=network.target ${SERVICE}.service
Requires=${SERVICE}.service

[Service]
Type=simple
ExecStart=$INSTALL_DIR/ssb-mon daemon
EnvironmentFile=/etc/ssb-mon/env
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}.service"

sleep 6
if systemctl is-active --quiet "$SERVICE_NAME"; then
    log "Сервис работает."
else
    err "Сервис не поднялся — смотри: journalctl -u $SERVICE_NAME -n 50"
    exit 1
fi

echo
log "Установка завершена!"
echo "  Порт clash-api:     127.0.0.1:$SSB_MON_PORT"
echo "  Секрет clash-api:   $SECRET"
echo "  База данных:        $DATA_DIR/state.db"
echo "  Конфигурация:       /etc/ssb-mon/env"
echo "  Сервис:             $SERVICE_NAME (autostart)"
echo
echo "  Команды:"
echo "    ssb-mon online     - кто сейчас онлайн"
echo "    ssb-mon traffic    - текущий трафик"
echo "    ssb-mon mem        - память sing-box"
echo "    ssb-mon sessions   - последние входы пользователей"
echo "    ssb-mon users      - сводка по пользователям"
echo "    ssb-mon history    - почасовая история"
echo
echo "  Секрет хранится в:  /etc/ssb-mon/env"
