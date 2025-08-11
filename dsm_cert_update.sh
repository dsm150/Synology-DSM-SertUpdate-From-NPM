#!/bin/bash

################################################################################
# Обновление сертификата из Nginx Proxy Manager (NPM) в Synology DSM
# - «Умная» проверка: если текущий DSM-сертификат совпадает с новым (SHA-256 fp),
#   импорт и рестарты НЕ выполняются (Telegram: Up-to-date).
# - При отличиях: перезаписывает запись по desc (сохраняет привязки), затем
#   рестартует nginx и пакеты, привязанные к сертификату (isPkg=true), КРОМЕ ActiveBackup.
# - Telegram: "DSM-CertUpdate: <DSM name> | <cert desc> | Restarted=N"
#   + Serial, Expires (формат HH.MM.SS DD.MM.YYYY по Москве), Expires in: Nd
################################################################################

set -o errexit
set -o nounset
set -o pipefail

export PATH="/usr/sbin:/usr/bin:/bin:/usr/local/bin:$PATH"

# ----------------------------- НАСТРОЙКИ --------------------------------------

VERBOSE=1 # Уровень логирования 1=подробный лог 0=минимальный лог

# NPM (Nginx Proxy Manager)
NPM_IP="192.168.1.1"
NPM_USER="root"
NPM_SSH_KEY="/var/services/homes/certbot/.ssh/npm_key" # Подключаемся по ключу
NPM_CERT_PATH="/root/letsencrypt/archive/npm-2"        # Путь к сертификату на сервере NPM (имя директории с ключем, можно посмотреть в web панели NPM в разделе SSL Certificates троеточие справа

# Synology DSM
SYNO_USERNAME="LOGIN"
SYNO_PASSWORD="PASSWORD"
SYNO_CERTIFICATE="CERT_NAME_in_WEB_PANEL"   # НЕ менять после первого прогона по имени скрипт понимает, есть ли этот сертификат в DSM
SYNO_CREATE=1                    # 1=Создать, если не существует; 0=Только перезапись существующего
SYNO_SCHEME="http"
SYNO_HOSTNAME="localhost"
SYNO_PORT="5000"

AS_DEFAULT=true                  # при первом создании сделать дефолтным?

# Telegram
TELEGRAM_BOT_TOKEN="BOT_TOKEN"
TELEGRAM_CHAT_ID="CHAT_ID"

# Прочее
DOMAIN="mybest.domain"  # для сообщения в Telegram
EXCLUDE_PKG_IDS=("ActiveBackup")   # исключить из рестартов (использую родной самоподписной серт на многолет)
INFO_PATH="/usr/syno/etc/certificate/_archive/INFO" # тут скрипт берет инфу о сервисах к которым привязан серт, что бы их рестартнуть

# --------------------------- ВРЕМЕННЫЕ ФАЙЛЫ ----------------------------------

TEMP_DIR="/tmp/syno_cert_install"
KEY_FILE="$TEMP_DIR/privkey.pem"
CERT_FILE="$TEMP_DIR/cert.pem"
CA_FILE="$TEMP_DIR/chain.pem"
RESTARTED_IDS_FILE="$TEMP_DIR/restarted_ids.txt"

mkdir -p "$TEMP_DIR"
trap 'rm -rf "$TEMP_DIR" 2>/dev/null || true' EXIT

# ------------------------------- УТИЛИТЫ --------------------------------------

_log()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >&2; }
_vlog() { [ "${VERBOSE:-1}" -eq 1 ] && echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >&2 || true; }

require_bin() {
  local b
  for b in "$@"; do
    command -v "$b" >/dev/null 2>&1 || { _log "Ошибка: требуется '$b'"; exit 1; }
  done
}

BASE_URL() { printf "%s://%s:%s" "$SYNO_SCHEME" "$SYNO_HOSTNAME" "$SYNO_PORT"; }

send_telegram_report() {
  local dsm_name="$1"
  local cert_name="$2"
  local restarted_count="$3"
  local extra="${4:-}"
  local text="DSM-CertUpdate: *${dsm_name}* | Cert: *${cert_name}* | Restarted pkgs: *${restarted_count}* (excl. ActiveBackup)"
  [ -n "$extra" ] && text="${text}\n${extra}"
  curl -s -X POST \
    -H "Content-Type: application/json" \
    -d "{\"chat_id\":\"$TELEGRAM_CHAT_ID\",\"text\":\"${text}\",\"parse_mode\":\"markdown\"}" \
    "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" >/dev/null || true
}

send_telegram_nochange() {
  local dsm_name="$1"
  local cert_name="$2"
  local extra="${3:-}"
  local text="DSM-CertUpdate: *${dsm_name}* | Cert: *${cert_name}* — *Up-to-date*, no changes"
  [ -n "$extra" ] && text="${text}\n${extra}"
  curl -s -X POST \
    -H "Content-Type: application/json" \
    -d "{\"chat_id\":\"$TELEGRAM_CHAT_ID\",\"text\":\"${text}\",\"parse_mode\":\"markdown\"}" \
    "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" >/dev/null || true
}

# -------- OpenSSL helpers: fingerprint / serial / notAfter / формат MSK / дни --

cert_fp_sha256() {  # fingerprint (lowercase, без ':')
  local f="$1"
  openssl x509 -noout -fingerprint -sha256 -in "$f" 2>/dev/null \
    | awk -F= '{print tolower($2)}' | tr -d ':'
}
cert_serial_hex() {  # серийник (lowercase, без ведущих нулей)
  local f="$1"
  openssl x509 -noout -serial -in "$f" 2>/dev/null \
    | awk -F= '{print tolower($2)}' | sed 's/^0\+//'
}
cert_not_after() {   # raw: "Oct 28 00:03:19 2025 GMT"
  local f="$1"
  openssl x509 -noout -enddate -in "$f" 2>/dev/null | cut -d= -f2
}
# "Oct 28 00:03:19 2025 GMT" → "HH.MM.SS DD.MM.YYYY" (MSK)
to_msk() {
  local src="$1"
  if command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1; then
    local pybin="python3"; command -v python3 >/dev/null 2>&1 || pybin="python"
    "$pybin" - "$src" <<'PY' 2>/dev/null || { echo "$src"; return; }
import sys
from datetime import datetime, timedelta, timezone
s=sys.argv[1]
try:
    dt=datetime.strptime(s, "%b %d %H:%M:%S %Y %Z")
except ValueError:
    dt=datetime.strptime(s.replace(" GMT",""), "%b %d %H:%M:%S %Y")
dt=dt.replace(tzinfo=timezone.utc) + timedelta(hours=3)  # UTC -> MSK
print(dt.strftime("%H.%M.%S %d.%m.%Y"))
PY
    return
  fi
  if date -d '1970-01-01' >/dev/null 2>&1; then
    local out
    out=$(TZ=UTC date -d "$src +3 hour" +'%H.%M.%S %d.%m.%Y' 2>/dev/null || true)
    [ -n "$out" ] && { echo "$out"; return; }
  fi
  echo "$src"
}
# Сколько дней до истечения (ceil по суткам, минимум 0)
days_until_not_after() {
  local src="$1"
  if command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1; then
    local pybin="python3"; command -v python3 >/dev/null 2>&1 || pybin="python"
    "$pybin" - "$src" <<'PY' 2>/dev/null || { echo ""; return; }
import sys, math
from datetime import datetime, timezone
s=sys.argv[1]
try:
    dt=datetime.strptime(s, "%b %d %H:%M:%S %Y %Z")
except ValueError:
    dt=datetime.strptime(s.replace(" GMT",""), "%b %d %H:%M:%S %Y")
dt=dt.replace(tzinfo=timezone.utc)
now=datetime.now(timezone.utc)
sec=(dt-now).total_seconds()
days=max(0, math.ceil(sec/86400.0))
print(days)
PY
    return
  fi
  if date -u +%s >/dev/null 2>&1; then
    local exp now diff days
    exp=$(TZ=UTC date -d "$src" +%s 2>/dev/null || echo "")
    now=$(date -u +%s)
    if [ -n "$exp" ]; then
      diff=$((exp - now))
      [ $diff -lt 0 ] && diff=0
      days=$(( (diff + 86399) / 86400 ))   # ceil
      echo "$days"; return
    fi
  fi
  echo ""
}

# -------------------------- ОПРЕДЕЛЕНИЕ ИМЕНИ DSM -----------------------------

get_dsm_name() {
  local sid="$1"
  local r name
  r=$(curl -sk "$(BASE_URL)/webapi/entry.cgi?api=SYNO.Core.System&method=info&version=1&_sid=${sid}" || true)
  name=$(echo "$r" | grep -o '"hostname":"[^"]*' | cut -d'"' -f4 || true)
  if [ -z "${name:-}" ]; then
    r=$(curl -sk "$(BASE_URL)/webapi/entry.cgi?api=SYNO.Core.System&method=get&version=1&_sid=${sid}" || true)
    name=$(echo "$r" | grep -o '"hostname":"[^"]*' | cut -d'"' -f4 || true)
  fi
  [ -n "${name:-}" ] && echo "$name" || hostname
}

# --------------------------- ПОЛУЧЕНИЕ С NPM ----------------------------------

get_latest_cert_from_npm() {
  _log "Получаем последний сертификат с NPM (${NPM_IP})..."

  local SSH_OPTS=(-i "$NPM_SSH_KEY" -o BatchMode=yes -o ConnectTimeout=15)
  local SCP_OPTS=(-i "$NPM_SSH_KEY" -o BatchMode=yes -o ConnectTimeout=15)

  local latest_num
  latest_num=$(ssh "${SSH_OPTS[@]}" "$NPM_USER@$NPM_IP" \
    "ls -1 ${NPM_CERT_PATH}/cert*.pem 2>/dev/null | grep -oE 'cert([0-9]+)\\.pem' | sed -E 's/^cert([0-9]+)\\.pem/\\1/' | sort -n | tail -1" || true)

  if [ -z "${latest_num:-}" ]; then
    _log "Ошибка: не удалось найти сертификаты в ${NPM_CERT_PATH}"
    send_telegram_report "$(hostname)" "$SYNO_CERTIFICATE" "0" "Не найдены файлы cert*.pem на NPM"
    exit 1
  fi

  _log "Найден выпуск сертификата № ${latest_num}"

  scp "${SCP_OPTS[@]}" "$NPM_USER@$NPM_IP:${NPM_CERT_PATH}/cert${latest_num}.pem" "$CERT_FILE"
  scp "${SCP_OPTS[@]}" "$NPM_USER@$NPM_IP:${NPM_CERT_PATH}/privkey${latest_num}.pem" "$KEY_FILE"
  scp "${SCP_OPTS[@]}" "$NPM_USER@$NPM_IP:${NPM_CERT_PATH}/chain${latest_num}.pem" "$CA_FILE"

  if [ ! -s "$CERT_FILE" ] || [ ! -s "$KEY_FILE" ] || [ ! -s "$CA_FILE" ]; then
    _log "Ошибка: не удалось скопировать все файлы сертификата"
    send_telegram_report "$(hostname)" "$SYNO_CERTIFICATE" "0" "Не удалось скопировать cert/privkey/chain с NPM"
    exit 1
  fi

  _log "Сертификат успешно скопирован с NPM"
}

# ---------------------- ВСПОМОГАТЕЛЬНО: ЛОГИН/ЛОГАУТ -------------------------

syno_login() {
  local url; url="$(BASE_URL)/webapi/auth.cgi?api=SYNO.API.Auth&version=3&method=login&account=${SYNO_USERNAME}&passwd=${SYNO_PASSWORD}&session=Certificate&format=cookie"
  local r; r=$(curl -sk "$url")
  if ! echo "$r" | grep -q '"success":true'; then
    _log "Ошибка входа: $r"
    send_telegram_report "$(hostname)" "$SYNO_CERTIFICATE" "0" "Ошибка входа в DSM"
    exit 1
  fi
  echo "$r" | grep -o '"sid":"[^"]*' | cut -d'"' -f4
}

syno_logout() {
  local sid="$1"
  curl -sk "$(BASE_URL)/webapi/auth.cgi?api=SYNO.API.Auth&version=3&method=logout&session=Certificate&_sid=${sid}" >/dev/null || true
}

# ------------------------ РЕСТАРТ СЕРВИСОВ/ПАКЕТОВ ----------------------------

_find_synopkg() {
  if command -v synopkg >/dev/null 2>&1; then
    command -v synopkg
  elif [ -x /usr/sbin/synopkg ]; then
    echo /usr/sbin/synopkg
  elif [ -x /usr/bin/synopkg ]; then
    echo /usr/bin/synopkg
  else
    echo ""
  fi
}
SYNOPKG_BIN="$(_find_synopkg)"

restart_nginx() {
  _log "Перезапускаем nginx..."
  if command -v /usr/syno/bin/synosystemctl >/dev/null 2>&1; then
    if /usr/syno/bin/synosystemctl restart nginx 2>/dev/null; then _log "nginx: synosystemctl ok"; return 0; fi
  fi
  if command -v /usr/syno/bin/synoservicecfg >/dev/null 2>&1; then
    if /usr/syno/bin/synoservicecfg --restart nginx 2>/dev/null; then _log "nginx: synoservicecfg ok"; return 0; fi
  fi
  if [ -x /usr/syno/etc/rc.sysv/nginx.sh ]; then
    if /usr/syno/etc/rc.sysv/nginx.sh restart 2>/dev/null; then _log "nginx: rc.sysv ok"; return 0; fi
  fi
  if command -v /usr/syno/sbin/nginx >/dev/null 2>&1; then
    if /usr/syno/sbin/nginx -s reload 2>/dev/null; then _log "nginx: binary reload ok"; return 0; fi
  fi
  if [ -f /run/nginx.pid ]; then
    if kill -HUP "$(cat /run/nginx.pid)" 2>/dev/null; then _log "nginx: HUP ok"; return 0; fi
  fi
  _log "Не удалось перезапустить nginx никаким способом — продолжаем."
  return 1
}

# --------------------- ПАРСИНГ INFO: jq → python → awk ------------------------

get_bound_pkg_ids_from_info() {
  local cert_id="$1"
  local info="$INFO_PATH"
  [ -r "$info" ] || { _log "INFO не найден ($info)"; return 0; }

  if command -v jq >/dev/null 2>&1; then
    jq -r --arg id "$cert_id" '
      .[$id].services[]? | select(.isPkg==true) |
      (.subscriber // .service // .owner) | select(.!=null and .!="")
    ' "$info" 2>/dev/null | sed '/^$/d' | sort -u
    return 0
  fi

  if command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1; then
    local pybin="python3"; command -v python3 >/dev/null 2>&1 || pybin="python"
    "$pybin" - "$cert_id" "$info" <<'PY' 2>/dev/null | sed '/^$/d' | sort -u
import sys, json
cert_id = sys.argv[1]
info_path = sys.argv[2]
with open(info_path, 'r') as f:
    data = json.load(f)
svc_list = []
for svc in data.get(cert_id, {}).get('services', []):
    if svc.get('isPkg') is True:
        v = svc.get('subscriber') or svc.get('service') or svc.get('owner')
        if isinstance(v, str) and v.strip():
            svc_list.append(v.strip())
for s in sorted(set(svc_list)):
    print(s)
PY
    return 0
  fi

  # AWK-фолбэк
  awk -v target="$cert_id" '
    BEGIN { in_cert=0; in_services=0; in_elem=0; ispkg=0; sub=""; svc=""; own="";
            id_line="^[[:space:]]*\\\""target"\\\"[[:space:]]*:[[:space:]]*\\{";
            other_id="^[[:space:]]*\\\"[[:alnum:]]+\\\"[[:space:]]*:[[:space:]]*\\{" }
    { if ($0 ~ id_line) { in_cert=1; in_services=0; in_elem=0; ispkg=0; sub=""; svc=""; own=""; next }
      if (in_cert && $0 ~ other_id && $0 !~ id_line) { in_cert=0; in_services=0; in_elem=0; next }
      if (!in_cert) next
      if (!in_services && $0 ~ /"services"[[:space:]]*:/) { in_services=1; next }
      if (in_services) {
        if ($0 ~ /\]/) { in_services=0; in_elem=0; next }
        if (!in_elem && $0 ~ /\{/) { in_elem=1; ispkg=0; sub=""; svc=""; own=""; }
        if (in_elem) {
          if ($0 ~ /"isPkg"[[:space:]]*:[[:space:]]*true/) ispkg=1
          if (match($0, /"subscriber"[[:space:]]*:[[:space:]]*"([^"]*)"/, m)) sub=m[1]
          if (match($0, /"service"[[:space:]]*:[[:space:]]*"([^"]*)"/,    m)) svc=m[1]
          if (match($0, /"owner"[[:space:]]*:[[:space:]]*"([^"]*)"/,      m)) own=m[1]
          if ($0 ~ /\}/) {
            if (ispkg==1) { out=(sub!=""?sub:(svc!=""?svc:own)); if (out!="") print out }
            in_elem=0; ispkg=0; sub=""; svc=""; own="";
          }
        }
      }
    }
  ' "$info" | sed '/^$/d' | sort -u
}

# Проверка существования юнита/пакета
_pkg_exists() {
  local id="$1"
  if command -v /usr/syno/bin/synosystemctl >/dev/null 2>&1; then
    /usr/syno/bin/synosystemctl status "pkgctl-${id}" >/dev/null 2>&1 && return 0
    ls "/usr/lib/systemd/system/pkgctl-${id}.service" >/dev/null 2>&1 && return 0 || true
  fi
  [ -d "/var/packages/${id}" ] && return 0 || return 1
}

# Рестарт пакета по ID
_restart_pkg_by_id() {
  local id="$1"
  if command -v /usr/syno/bin/synosystemctl >/dev/null 2>&1; then
    /usr/syno/bin/synosystemctl restart "pkgctl-${id}" >/dev/null 2>&1 && return 0
  fi
  if command -v synopkg >/dev/null 2>&1; then
    synopkg restart "$id" >/dev/null 2>&1 && return 0
  elif [ -x /usr/sbin/synopkg ]; then
    /usr/sbin/synopkg restart "$id" >/dev/null 2>&1 && return 0
  elif [ -x /usr/bin/synopkg ]; then
    /usr/bin/synopkg restart "$id" >/dev/null 2>&1 && return 0
  fi
  return 1
}

# Рестарт только привязанных к сертификату пакетов
restart_bound_packages() {
  local cert_id="$1"
  : > "$RESTARTED_IDS_FILE"

  local -a raw_ids
  mapfile -t raw_ids < <(get_bound_pkg_ids_from_info "$cert_id" | sed '/^$/d' | sort -u)

  if [ "${#raw_ids[@]}" -eq 0 ]; then
    _log "В INFO нет привязанных пакетов (isPkg=true) для cert id=$cert_id"
    echo 0
    return 0
  fi

  _vlog "Найдены кандидаты пакетов из INFO: ${raw_ids[*]}"

  local -a ids=()
  local id; for id in "${raw_ids[@]}"; do
    local skip=false
    for ex in "${EXCLUDE_PKG_IDS[@]}"; do
      [ "$id" = "$ex" ] && { skip=true; break; }
    done
    $skip && { _vlog "Пропускаем (исключение): $id"; continue; }

    if _pkg_exists "$id"; then
      ids+=("$id")
    else
      _vlog "Похоже, пакет/юнит не найден: $id (пропуск)"
    fi
  done

  if [ "${#ids[@]}" -eq 0 ]; then
    _log "После фильтрации подходящих ID не осталось."
    echo 0
    return 0
  fi

  local restarted=0
  local -a restarted_ids=()
  for id in "${ids[@]}"; do
    _log "Перезапуск пакета: $id"
    if _restart_pkg_by_id "$id"; then
      restarted=$((restarted+1))
      restarted_ids+=("$id")
    else
      _log "Не удалось перезапустить пакет: $id"
    fi
    sleep 0.2
  done

  [ "${#restarted_ids[@]}" -gt 0 ] && _vlog "Перезапущены: ${restarted_ids[*]}"
  echo "${restarted_ids[*]}" > "$RESTARTED_IDS_FILE"
  printf "%s\n" "$restarted"
}

# ------------------------ УСТАНОВКА В SYNLOGY DSM -----------------------------

install_cert_to_synology() {
  _log "Начинаем установку сертификата в Synology DSM..."

  local sid; sid=$(syno_login)
  _log "Получен SID: $sid"

  local dsm_name; dsm_name=$(get_dsm_name "$sid")
  _log "Определено имя DSM: $dsm_name"

  # Новый сертификат (из NPM): fp/serial/expiry(+MSK/+days)
  local new_fp new_serial new_exp new_exp_msk new_days
  new_fp=$(cert_fp_sha256 "$CERT_FILE" || true)
  new_serial=$(cert_serial_hex "$CERT_FILE" || true)
  new_exp=$(cert_not_after "$CERT_FILE" || true)
  new_exp_msk=$(to_msk "$new_exp")
  new_days=$(days_until_not_after "$new_exp")
  _vlog "Новый cert fp: $new_fp | serial: $new_serial | notAfter(raw): $new_exp | MSK: $new_exp_msk | days: $new_days"

  # Ищем запись по desc
  _log "Ищем существующий сертификат по описанию: \"$SYNO_CERTIFICATE\"..."
  local list_response cert_id
  list_response=$(curl -sk "$(BASE_URL)/webapi/entry.cgi?api=SYNO.Core.Certificate.CRT&method=list&version=1&_sid=${sid}")
  cert_id=$(echo "$list_response" | sed -n "s/.*\"desc\":\"$(printf "%s" "$SYNO_CERTIFICATE" | sed 's/[.[\*^$\/]/\\&/g')\",\"id\":\"\([^\"]*\).*/\1/p" | head -n1)

  # Если запись есть — сравним fp
  if [ -n "${cert_id:-}" ]; then
    local current_cert="/usr/syno/etc/certificate/_archive/${cert_id}/cert.pem"
    if [ -s "$current_cert" ] && [ -n "${new_fp:-}" ]; then
      local cur_fp cur_serial cur_exp cur_exp_msk cur_days
      cur_fp=$(cert_fp_sha256 "$current_cert" || true)
      cur_serial=$(cert_serial_hex "$current_cert" || true)
      cur_exp=$(cert_not_after "$current_cert" || true)
      cur_exp_msk=$(to_msk "$cur_exp")
      cur_days=$(days_until_not_after "$cur_exp")
      _vlog "Текущий DSM cert fp: $cur_fp | serial: $cur_serial | MSK: $cur_exp_msk | days: $cur_days"

      if [ -n "$cur_fp" ] && [ "$cur_fp" = "$new_fp" ]; then
        _log "Сертификат совпадает — импорт и рестарты не требуются."
        local label="Expires"; echo "$new_exp_msk" | grep -Eq '^[0-9]{2}\.[0-9]{2}\.[0-9]{2} [0-9]{2}\.[0-9]{2}\.[0-9]{4}$' && label="Expires (MSK)"
        local days_note=""
        [ -n "$new_days" ] && days_note="\nExpires in: \`${new_days}d\`"
        local extra="Serial: \`${new_serial:-n/a}\`, ${label}: \`${new_exp_msk:-n/a}\`${days_note}"
        send_telegram_nochange "$dsm_name" "$SYNO_CERTIFICATE" "$extra"
        syno_logout "$sid"
        return 0
      fi
    fi
  fi

  # Если записи нет и SYNO_CREATE=0 — выходим
  if [ -z "${cert_id:-}" ] && [ "$SYNO_CREATE" != "1" ]; then
    _log "Не найден сертификат \"$SYNO_CERTIFICATE\" и создание отключено (SYNO_CREATE=0)."
    send_telegram_report "$dsm_name" "$SYNO_CERTIFICATE" "0" "Запись сертификата не найдена"
    syno_logout "$sid"
    exit 1
  fi

  [ -n "${cert_id:-}" ] && _log "Найден существующий сертификат id=${cert_id} — перезаписываем (привязки сохранятся)." \
                         || _log "Сертификат не найден — будет создан новый (привязки назначь один раз в DSM UI)."

  # Импорт (перезапись/создание) без трогания привязок
  local boundary="---------------------------$(date +%Y%m%d%H%M%S)"
  local temp_file="$TEMP_DIR/upload_data"

  {
    echo "--$boundary"
    echo 'Content-Disposition: form-data; name="key"; filename="privkey.pem"'
    echo 'Content-Type: application/octet-stream'; echo
    cat "$KEY_FILE"

    echo "--$boundary"
    echo 'Content-Disposition: form-data; name="cert"; filename="cert.pem"'
    echo 'Content-Type: application/octet-stream'; echo
    cat "$CERT_FILE"

    echo "--$boundary"
    echo 'Content-Disposition: form-data; name="inter_cert"; filename="chain.pem"'
    echo 'Content-Type: application/octet-stream'; echo
    cat "$CA_FILE"

    if [ -n "${cert_id:-}" ]; then
      echo "--$boundary"
      echo 'Content-Disposition: form-data; name="id"'; echo
      echo "$cert_id"
    fi

    echo "--$boundary"
    echo 'Content-Disposition: form-data; name="desc"'; echo
    echo "$SYNO_CERTIFICATE"

    echo "--$boundary"
    echo 'Content-Disposition: form-data; name="as_default"'; echo
    $AS_DEFAULT && echo "true" || echo "false"

    echo "--$boundary--"
  } > "$temp_file"

  _log "Загружаем сертификат в DSM..."
  local upload_response
  upload_response=$(curl -sk -X POST -H "Content-Type: multipart/form-data; boundary=$boundary" \
    --data-binary "@$temp_file" \
    "$(BASE_URL)/webapi/entry.cgi?api=SYNO.Core.Certificate&method=import&version=1&_sid=${sid}")
  _log "Ответ на загрузку: $upload_response"

  if echo "$upload_response" | grep -q '"error":'; then
    _log "Ошибка при установке сертификата: $upload_response"
    send_telegram_report "$dsm_name" "$SYNO_CERTIFICATE" "0" "Ошибка при установке сертификата"
    syno_logout "$sid"
    exit 1
  fi

  # Рестарт nginx + привязанных пакетов
  restart_nginx

  _log "Перезапускаем пакеты, привязанные к сертификату (isPkg=true) из INFO..."
  local final_cert_id="${cert_id:-$(echo "$upload_response" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -n1)}"

  local restarted_count
  restarted_count=$(restart_bound_packages "$final_cert_id")

  # Отчёт
  local label="Expires"; echo "$new_exp_msk" | grep -Eq '^[0-9]{2}\.[0-9]{2}\.[0-9]{2} [0-9]{2}\.[0-9]{2}\.[0-9]{4}$' && label="Expires (MSK)"
  local days_note=""; [ -n "$new_days" ] && days_note="\nExpires in: \`${new_days}d\`"
  local extra_msg="Serial: \`${new_serial:-n/a}\`, ${label}: \`${new_exp_msk:-n/a}\`${days_note}"
  local restarted_list=""
  [ -f "$RESTARTED_IDS_FILE" ] && restarted_list=$(cat "$RESTARTED_IDS_FILE")
  if [ -n "$restarted_list" ]; then
    extra_msg="${extra_msg}\nPkgs: $(echo "$restarted_list" | awk '{for(i=1;i<=NF && i<=6;i++) printf ((i>1?", ":"") $i)}')"
  fi

  send_telegram_report "$dsm_name" "$SYNO_CERTIFICATE" "$restarted_count" "$extra_msg"
  syno_logout "$sid"
  _log "Готово. Перезапущено пакетов: $restarted_count"
}

# ------------------------------- MAIN -----------------------------------------

main() {
  require_bin curl ssh scp grep sed sort tail awk openssl

  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    _log "Нужны права root. Запусти скрипт с sudo."
    exit 1
  fi

  _log "Начало работы скрипта для домена: ${DOMAIN}"
  get_latest_cert_from_npm
  install_cert_to_synology
  _log "Скрипт завершил работу"
}

main "$@"
