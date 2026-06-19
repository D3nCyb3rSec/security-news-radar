# Security News Radar

Lokaler Security-News-Aggregator fuer aktuelle CVEs, bekannte Exploits und wichtige Cybersecurity-Meldungen. Der Lauf erzeugt eine statische Webseite und kann neue Treffer per Telegram oder E-Mail versenden.

Das Projekt kommt ohne externe Python-Pakete aus. Auf einem Linux-Server reicht Python 3.

## Linux-Schnellstart

Beispielinstallation unter `/opt/security-news`:

```bash
sudo mkdir -p /opt/security-news /var/lib/security-news /var/www/security-news
sudo cp -r . /opt/security-news/
sudo useradd --system --home /opt/security-news --shell /usr/sbin/nologin security-news || true
sudo chown -R security-news:security-news /opt/security-news /var/lib/security-news /var/www/security-news
sudo chmod +x /opt/security-news/run.sh
sudo -u security-news cp /opt/security-news/config.example.json /opt/security-news/config.json
```

Filter und Quellen danach in `/opt/security-news/config.json` anpassen.

Testlauf ohne Benachrichtigung:

```bash
sudo -u security-news /opt/security-news/run.sh --no-notify
```

Die Webseite liegt standardmaessig unter `/opt/security-news/public/index.html`. Fuer Serverbetrieb empfiehlt sich:

```bash
sudo -u security-news SECURITY_NEWS_SITE_PATH=/var/www/security-news/index.html \
  SECURITY_NEWS_DB_PATH=/var/lib/security-news/security_news.sqlite \
  /opt/security-news/run.sh --no-notify
```

## systemd Timer

Die mitgelieferten Units nutzen diese Pfade:

- Code: `/opt/security-news`
- Datenbank: `/var/lib/security-news/security_news.sqlite`
- Webseite: `/var/www/security-news/index.html`
- Secrets/Umgebung: `/etc/security-news.env`

Installation:

```bash
sudo cp /opt/security-news/systemd/security-news.service /etc/systemd/system/
sudo cp /opt/security-news/systemd/security-news.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now security-news.timer
```

Manueller Lauf und Logs:

```bash
sudo systemctl start security-news.service
sudo journalctl -u security-news.service -n 100 --no-pager
systemctl list-timers security-news.timer
```

## Cron Alternative

Falls du kein systemd nutzen moechtest:

```bash
sudo crontab -e
```

Eintrag fuer 08:00 Uhr taeglich:

```cron
0 8 * * * cd /opt/security-news && /opt/security-news/run.sh >> /var/log/security-news.log 2>&1
```

## Nginx Beispiel

Minimaler vHost fuer die generierte statische Webseite:

```nginx
server {
    listen 80;
    server_name security-news.example.com;

    root /var/www/security-news;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

## Telegram

Lege die Zugangsdaten entweder in `/etc/security-news.env` oder in `/opt/security-news/.env` ab:

```bash
TELEGRAM_BOT_TOKEN=123456:ABC...
TELEGRAM_CHAT_ID=123456789
```

Danach:

```bash
sudo systemctl start security-news.service
```

## E-Mail

Setze in `config.json` unter `email.enabled` den Wert auf `true`. Zugangsdaten koennen in der Datei stehen oder besser als Umgebungsvariablen in `/etc/security-news.env`:

```bash
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=user@example.com
SMTP_PASSWORD=app-password
SMTP_FROM=security-news@example.com
SMTP_TO=admin@example.com
```

## Filter

`include_keywords` begrenzt Meldungen auf gewuenschte Themen. `exclude_keywords` blendet Begriffe aus. `min_cvss_severity` gilt fuer NVD-CVEs und akzeptiert `LOW`, `MEDIUM`, `HIGH` oder `CRITICAL`.

Beispiel:

```json
"include_keywords": ["ransomware", "zero-day", "fortinet", "citrix", "microsoft"],
"exclude_keywords": ["android"],
"min_cvss_severity": "HIGH"
```

## Quellen

Aktiv enthalten sind NVD CVE, CISA Known Exploited Vulnerabilities und mehrere RSS-Feeds. Weitere RSS-Quellen koennen in `config.json` als Quelle mit `"type": "rss"` ergaenzt werden.

Optional kannst du fuer NVD einen API-Key setzen, damit Rate-Limits seltener stoeren:

```bash
NVD_API_KEY=your-nvd-api-key
```
