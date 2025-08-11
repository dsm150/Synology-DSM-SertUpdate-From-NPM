# DSM Cert Sync

Скрипт для автоматического обновления сертификата на **Synology DSM** из **Nginx Proxy Manager (NPM)**.

* Забирает последний выпуск сертификата (`certN.pem`, `privkeyN.pem`, `chainN.pem`) по SSH с NPM.
* Импортирует в DSM через WebAPI, **перезаписывая существующую запись по `desc`** → все привязки к сервисам сохраняются.
* Выполняет «умную проверку»: если **SHA-256 отпечаток** не изменился — импорт и рестарты не выполняются.
* После импорта перезапускает **nginx** и **те пакеты, что привязаны к сертификату** (по `/usr/syno/etc/certificate/_archive/INFO`), исключая `ActiveBackup`.
* Шлёт отчёт в Telegram: `DSM-CertUpdate: <hostname> | <cert desc> | Restarted=N` + Serial, Expires в московском времени `HH.MM.SS DD.MM.YYYY`, и `Expires in: Nd`.

> Первый раз после создания записи нужно один раз назначить сертификат нужным сервисам в DSM GUI:
> Панель управления → Безопасность → Сертификат → «Назначить сертификат» (Configure).

---

## Возможности

* Обновление без простоя: перезапись **существующей записи** → привязки остаются.
* Автоматический рестарт только тех пакетов, где реально используется сертификат.
* Отчёт в Telegram с полезными атрибутами (серийник, дата истечения, дни до истечения).
* Защита от лишних действий: пропуск, если сертификат не изменился.

---

## Требования

* Synology DSM 6/7, запуск от **root**.
* Доступ по SSH с DSM → NPM (обычно `root@<NPM>` с ключом).
* Инструменты: `curl`, `ssh`, `scp`, `openssl`, `awk`, `sed`, `grep`, `sort`, `tail`.
* Опционально: `jq`/`python3` (улучшает парсинг/формат дат; есть fallbacks).

---

## Установка

1. Скопируйте скрипт на DSM (например, в `/usr/local/sbin/`):

```bash
sudo mv install_cert_synology.sh /usr/local/sbin/install_cert_synology.sh
sudo chown root:root /usr/local/sbin/install_cert_synology.sh
sudo chmod 700 /usr/local/sbin/install_cert_synology.sh
```

2. Настройте SSH-доступ DSM → NPM:

```bash
# от пользователя, под которым будет выполняться скрипт (например, certbot)
mkdir -p ~/.ssh && chmod 700 ~/.ssh
ssh-keygen -t ed25519 -f ~/.ssh/npm_key -N '' -C 'DSM->NPM'
chmod 600 ~/.ssh/npm_key
chmod 644 ~/.ssh/npm_key.pub

# добавьте публичный ключ на NPM
scp ~/.ssh/npm_key.pub root@<NPM_IP>:/root/
# на NPM:
sudo mkdir -p /root/.ssh && sudo chmod 700 /root/.ssh
sudo sh -c 'cat /root/npm_key.pub >> /root/.ssh/authorized_keys'
sudo chmod 600 /root/.ssh/authorized_keys
sudo rm -f /root/npm_key.pub

# примите ключ хоста (первое подключение)
ssh -i ~/.ssh/npm_key root@<NPM_IP> 'echo OK'
```

3. Отредактируйте настройки в начале скрипта:

```bash
# NPM
NPM_IP="NPM_IP"
NPM_USER="root"
NPM_SSH_KEY="/var/services/homes/certbot/.ssh/npm_key"  # расположение ssh ключа
NPM_CERT_PATH="/root/letsencrypt/archive/npm-2"   # например npm-1 / npm-2

# DSM
SYNO_USERNAME="certbot"           # создаем пользователя на DSM, например certbot c правами администратора и запретом ко-всем сервисам
SYNO_PASSWORD="***"
SYNO_CERTIFICATE="jet-net.net"    # это desc записи в DSM (НЕ менять потом)
SYNO_CREATE=1                     # 1 = создать, если не существует
SYNO_SCHEME="http"                # или https
SYNO_HOSTNAME="localhost"         # IP/домен DSM
SYNO_PORT="5000"                  # 5000/5001

# Телеграм
TELEGRAM_BOT_TOKEN="***"
TELEGRAM_CHAT_ID="***"

# Для логов/отчёта
DOMAIN="jet-net.net"

# Исключения по рестартам пакетов
EXCLUDE_PKG_IDS=("ActiveBackup")
```

> Для другого DSM/домена достаточно поменять:
> `SYNO_HOSTNAME`, при необходимости `SYNO_SCHEME/PORT`, `SYNO_CERTIFICATE`, `DOMAIN`, и `NPM_CERT_PATH` (например, `/root/letsencrypt/archive/npm-1`).
> Пользователь и пароль DSM могут оставаться теми же, если вы их так используете.

---

## Запуск

```bash
sudo /usr/local/sbin/install_cert_synology.sh
```

Пример логов:

```
[2025-08-11 17:51:05] Определено имя DSM: SYNO-DSM
[2025-08-11 17:51:05] Найден существующий сертификат id=FdRTh — будет перезаписан (привязки сохранятся).
[2025-08-11 17:51:27] Перезапускаем nginx...
[2025-08-11 17:53:28] Перезапущены: LogCenter ReplicationService ScsiTarget SynologyDrive
```

---

## Планировщик задач (ежедневно утром)

DSM → Панель управления → Планировщик заданий → Создать → Задание по сценарию:

* Пользователь: `root`
* Команда:

  ```bash
  /usr/local/sbin/install_cert_synology.sh >> /var/log/dsm-cert-sync.log 2>&1
  ```
* Расписание: ежедневно, например 09:00.

---

## Как это работает

1. По SSH на NPM ищется **последний выпуск**: `certN.pem`, `privkeyN.pem`, `chainN.pem`.
2. В DSM через WebAPI выполняется `SYNO.Core.Certificate.import` с параметром `id` существующей записи (если есть) и `desc` → **перезапись** без изменения привязок.
3. Перезапуск **nginx**.
4. По `/usr/syno/etc/certificate/_archive/INFO` парсятся сервисы, где `isPkg=true`, и рестартуются соответствующие пакеты (кроме `EXCLUDE_PKG_IDS`).
5. В Telegram улетает отчёт с метаданными сертификата и списком перезапущенных пакетов.

---

## Telegram-уведомление

Пример:

```
DSM-CertUpdate: SYNO-DSM | Cert: mybest.domain | Restarted pkgs: 4 (excl. ActiveBackup)
Serial: `04a1...2f`, Expires (MSK): `00.03.19 28.10.2025`
Expires in: `78d`
Pkgs: LogCenter, ReplicationService, ScsiTarget, SynologyDrive
```

---

## FAQ

**Нужно ли каждый раз назначать сертификат сервисам?**
Нет. Скрипт перезаписывает существующую запись по `desc`, поэтому начальные привязки **сохраняются**. Это и позволяет обновлять сертификат без ручных действий.

**Что будет, если на NPM нет нового выпуска?**
Скрипт сравнит отпечаток SHA-256 нового и текущего DSM-сертификата и **пропустит** импорт/рестарты, отправив «Up-to-date» в Telegram.

**Где искать проблемы с SSH?**

* `Load key ".../npm_key": Permission denied` → проверьте владельца/права:
  `.ssh (700)`, `npm_key (600)`, `npm_key.pub (644)`, владелец — тот же пользователь, который запускает скрипт.
* `Host key verification failed` → примите ключ хоста (первое подключение `ssh root@NPM`, ответить `yes`) или вручную заполните `~/.ssh/known_hosts`.

**Можно запускать на нескольких DSM?**
Да, просто разместите скрипт на каждом DSM и подправьте 5–6 переменных в «Настройках».

---

## Безопасность (по желанию)

Сценарий рассчитан на «безопасный периметр». Если захотите усилить:

* вынесите секреты в `.env` (chmod 600, владельцем root);
* используйте cookie-jar вместо `_sid` в URL;
* ведите отдельный SSH-ключ на каждый DSM.

---


Скрипт создан, чтобы «поставил и забыл» — а если что-то идёт не так, логи и Telegram подскажут 🙂
