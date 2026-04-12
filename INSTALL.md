# ArtiShield — Installationsanleitung

## Inhaltsverzeichnis

1. [Voraussetzungen](#voraussetzungen)
2. [Schnellstart](#schnellstart)
3. [Installation aus dem Quellcode](#installation-aus-dem-quellcode)
4. [Native 3D Globe App](#native-3d-globe-app)
5. [Docker](#docker)
6. [Docker Compose (empfohlen für Produktion)](#docker-compose)
7. [systemd-Service](#systemd-service)
8. [Konfiguration](#konfiguration)
9. [GeoIP-Datenbank (optional)](#geoip-datenbank-optional)
10. [arti-Integration](#arti-integration)
11. [Verifizierung](#verifizierung)
12. [Upgrade](#upgrade)
13. [Deinstallation](#deinstallation)

---

## Voraussetzungen

### Pflicht

| Komponente | Mindestversion | Hinweis |
|------------|---------------|---------|
| Rust / Cargo | 1.77 | `rustup update stable` |
| arti | laufend | SOCKS5-Port muss erreichbar sein |

### Optional

| Komponente | Zweck |
|------------|-------|
| MaxMind GeoLite2-ASN | ASN-basierte Sybil-Erkennung |
| Docker + Compose V2 | Container-Deployment |
| Prometheus | Metriken-Scraping |
| Grafana | Metriken-Visualisierung |

### arti starten (falls noch nicht aktiv)

```bash
# Paketmanager (Debian/Ubuntu)
sudo apt install arti
sudo systemctl enable --now arti

# Oder aus dem Quellcode
cargo install arti
arti proxy &
```

arti lauscht standardmäßig auf `127.0.0.1:9150` (SOCKS5).

---

## Schnellstart

```bash
git clone https://github.com/cdemkos/artishield.git
cd artishield
cargo run --release -- --config artishield.toml
```

Dashboard erreichbar unter: `http://localhost:7878`

---

## Installation aus dem Quellcode

### 1. Repository klonen

```bash
git clone https://github.com/cdemkos/artishield.git
cd artishield
```

### 2. Binary bauen

**Standard (SOCKS-basierte Detektoren + GeoIP):**

```bash
cargo build --release
```

**Mit nativer 3D Globe App** (Bevy-UI, benötigt X11/Wayland-Dev-Libs):

```bash
# Linux: X11 + Audio-Dev-Pakete installieren
sudo apt install -y libx11-dev libxi-dev libxcursor-dev libxrandr-dev \
                    libudev-dev libasound2-dev
cargo build --release --features bevy-ui
```

**Mit voller arti-Integration** (Sybil-, Guard- und HS-Detektor aktiv):

```bash
cargo build --release --features arti-hooks
```

**Ohne optionale Features** (minimaler Build, z.B. für CI):

```bash
cargo build --release --no-default-features
```

Das fertige Binary liegt unter `target/release/artishield`.

### 3. Binary installieren

```bash
sudo install -m 755 target/release/artishield /usr/local/bin/artishield
```

### 4. Konfiguration anlegen

```bash
sudo mkdir -p /etc/artishield
sudo cp artishield.toml.example /etc/artishield/artishield.toml
sudo chmod 640 /etc/artishield/artishield.toml
# Pfade und Einstellungen anpassen:
sudo nano /etc/artishield/artishield.toml
```

### 5. Datenverzeichnis anlegen

```bash
sudo mkdir -p /var/lib/artishield
```

### 6. Starten

```bash
artishield --config /etc/artishield/artishield.toml
```

---

## Native 3D Globe App

Die native Globe-App visualisiert Angriffe in Echtzeit als animierte Bézier-Bögen auf einem rotierenden 3D-Globus. Sie benötigt das Feature `bevy-ui` und einen lokalen Display-Server (X11 oder Wayland).

### Voraussetzungen

```bash
# Debian/Ubuntu
sudo apt install -y \
  libx11-dev libxi-dev libxcursor-dev libxrandr-dev \
  libudev-dev libasound2-dev libgl1

# Fedora/RHEL
sudo dnf install -y \
  libX11-devel libXi-devel libXcursor-devel libXrandr-devel \
  systemd-devel alsa-lib-devel mesa-libGL
```

### Build

```bash
cargo build --release --features bevy-ui
```

### Starten

**Demo-Modus** (kein laufendes arti benötigt — synthetische Events):

```bash
cargo run --release --features bevy-ui -- native --no-monitor
# oder nach Installation:
artishield native --no-monitor
```

**Live-Modus** (verbindet sich mit laufendem arti via SOCKS5):

```bash
artishield --config artishield.toml native
```

### Steuerung

| Eingabe | Aktion |
|---------|--------|
| Linke Maustaste + Ziehen | Globus rotieren |
| Mausrad | Zoom ein/aus |
| Fenster schließen / Ctrl-C | Beenden |

### Farbcodierung der Angriffspfeile

| Farbe | Severity |
|-------|----------|
| Rot | Critical |
| Orange | High |
| Gelb | Medium |
| Hellblau | Low |
| Grün | Info |

### Docker-Container (X11)

```bash
docker build -f Dockerfile.native -t artishield-native .

# X11-Zugriff erlauben
xhost +local:docker

docker run --rm -it \
  -e DISPLAY=$DISPLAY \
  -v /tmp/.X11-unix:/tmp/.X11-unix \
  artishield-native
```

---

## Docker

### Image bauen

```bash
docker build -t artishield:latest .
```

### Container starten

```bash
docker run -d \
  --name artishield \
  --restart unless-stopped \
  -p 127.0.0.1:7878:7878 \
  -v artishield-data:/var/lib/artishield \
  -v ./artishield.toml:/opt/artishield/artishield.toml:ro \
  -e RUST_LOG="artishield=info,warn" \
  artishield:latest
```

### Health-Status prüfen

```bash
docker inspect --format='{{.State.Health.Status}}' artishield
```

---

## Docker Compose

Die empfohlene Methode für Produktiv-Deployments. Startet ArtiShield zusammen mit Prometheus und Grafana.

### 1. Umgebungsvariablen setzen

```bash
cp .env.example .env
# .env öffnen und GRAFANA_ADMIN_PASSWORD setzen:
nano .env
```

```env
GRAFANA_ADMIN_PASSWORD=sicheres-passwort-hier
```

### 2. (Optional) Eigene Konfiguration verwenden

Das Docker-Image enthält bereits eine funktionsfähige Standardkonfiguration.
Für individuelle Anpassungen:

```bash
cp artishield.toml.example artishield.toml
nano artishield.toml
# Danach in docker-compose.yml das Volume-Mount für artishield.toml einkommentieren.
```

### 3. Stack starten

```bash
docker compose up -d
```

### 4. Status prüfen

```bash
docker compose ps
```

### Erreichbare Dienste

| Dienst | URL | Hinweis |
|--------|-----|---------|
| ArtiShield Dashboard | http://localhost:7878 | |
| Prometheus | http://localhost:9090 | |
| Grafana | http://localhost:3000 | Login: `admin` / gesetztes Passwort |

### Stack stoppen

```bash
docker compose down
```

### Logs anzeigen

```bash
docker compose logs -f artishield
```

---

## systemd-Service

### 1. Systembenutzer anlegen

```bash
sudo useradd -r -s /bin/false -d /opt/artishield artishield
```

### 2. Verzeichnisse vorbereiten

```bash
sudo mkdir -p /opt/artishield /etc/artishield /var/lib/artishield
sudo chown artishield:artishield /opt/artishield /var/lib/artishield
sudo chmod 750 /var/lib/artishield
```

### 3. Binary und Konfiguration installieren

```bash
sudo install -m 755 target/release/artishield /usr/local/bin/artishield
sudo install -m 640 -o root -g artishield \
    artishield.toml.example /etc/artishield/artishield.toml
# Konfiguration anpassen:
sudo nano /etc/artishield/artishield.toml
```

### 4. Service-Datei installieren

```bash
sudo cp deploy/artishield.service /etc/systemd/system/
sudo systemctl daemon-reload
```

### 5. Service aktivieren und starten

```bash
sudo systemctl enable --now artishield
```

### Nützliche systemctl-Befehle

```bash
sudo systemctl status artishield       # Status anzeigen
sudo systemctl restart artishield      # Neustarten
sudo journalctl -u artishield -f       # Logs live verfolgen
sudo journalctl -u artishield --since today
```

> **Hinweis:** Der Service setzt `Requires=arti.service` voraus.
> arti muss als systemd-Service laufen und erreichbar sein.

---

## Konfiguration

Die vollständige Konfigurationsdatei mit allen Standardwerten:

```toml
# arti SOCKS5-Adresse
socks_addr = "127.0.0.1:9150"

# Dashboard- und API-Adresse
# Für lokalen Betrieb auf 127.0.0.1 beschränken:
api_addr = "127.0.0.1:7878"

# SQLite-Datenbank
db_path = "/var/lib/artishield/artishield.db"

# Log-Level (RUST_LOG-Syntax, überschreibbar via Umgebungsvariable RUST_LOG)
log_level = "artishield=info,warn"

# Optionale MaxMind-Datenbank für ASN-Lookups
# geoip_db = "/etc/artishield/GeoLite2-ASN.mmdb"

[detectors]
# Sybil: Alert wenn zwei Circuit-Hops in derselben /24-Subnet
sybil_subnet_check = true

# Sybil: Maximale Hops aus demselben ASN pro Circuit
sybil_asn_max_hops = 1

# Timing: Pearson |r|-Schwellwert (0.0–1.0, niedriger = sensitiver)
timing_correlation_threshold = 0.6

# Timing: Minimales Probe-Fenster in Sekunden
timing_window_secs = 30

# Guard: Maximale Guard-Rotationen pro Consensus vor Alert
guard_rotation_max = 5

# Globaler Anomalie-Score ab dem Mitigationen ausgelöst werden
alert_threshold = 0.70

[mitigations]
# Guard-Pin-Alert bei unerwarteter Rotation aktivieren
guard_pin = true

# Automatische Circuit-Rotation bei Überschreiten des alert_threshold
auto_circuit_rotate = false

# Sybil-/Scanner-IPs in persistente Blocklist aufnehmen
entry_ip_filter = false
```

### Konfiguration testen

```bash
artishield --config /etc/artishield/artishield.toml check-config
```

### Konfiguration via Umgebungsvariable überschreiben

```bash
RUST_LOG=artishield=debug artishield --config artishield.toml
```

---

## GeoIP-Datenbank (optional)

Die MaxMind GeoLite2-ASN-Datenbank verbessert die Sybil-Erkennung durch ASN-basierte Relay-Gruppierung.

### 1. Kostenloser Account bei MaxMind

Registrierung unter: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

### 2. Datenbank herunterladen

```bash
# Beispiel mit mmdbinspect oder direktem Download nach Login:
curl -o GeoLite2-ASN.tar.gz \
  "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=DEIN_KEY&suffix=tar.gz"

tar -xzf GeoLite2-ASN.tar.gz
sudo install -m 644 GeoLite2-ASN_*/GeoLite2-ASN.mmdb \
    /etc/artishield/GeoLite2-ASN.mmdb
```

### 3. Pfad in Konfiguration eintragen

```toml
geoip_db = "/etc/artishield/GeoLite2-ASN.mmdb"
```

### 4. Monatliche Aktualisierung (Cronjob)

```bash
# /etc/cron.monthly/update-geoip
#!/bin/bash
curl -s -o /tmp/GeoLite2-ASN.tar.gz \
  "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=${MAXMIND_KEY}&suffix=tar.gz"
tar -xzf /tmp/GeoLite2-ASN.tar.gz -C /tmp/
install -m 644 /tmp/GeoLite2-ASN_*/GeoLite2-ASN.mmdb /etc/artishield/GeoLite2-ASN.mmdb
systemctl restart artishield
```

---

## arti-Integration

Für die vollständige Integration (Sybil-, Guard-Discovery- und HS-Enumerations-Detektor) muss ArtiShield mit dem Feature `arti-hooks` gebaut werden.

### Voraussetzungen

- arti Version 0.37.x
- `experimental-api`-Feature von arti muss aktiviert sein
- arti und ArtiShield müssen exakt dieselbe Minor-Version der `tor-*`-Crates verwenden

### Build

```bash
cargo build --release --features arti-hooks
```

### Funktionsumfang mit `arti-hooks`

| Feature | Ohne arti-hooks | Mit arti-hooks |
|---------|----------------|----------------|
| TimingDetector | ✓ | ✓ |
| DosDetector | ✓ | ✓ |
| SybilDetector (Circuit) | ✓ | ✓ |
| SybilDetector (Netzwerk) | — | ✓ |
| GuardDiscoveryDetector | — | ✓ |
| HsEnumDetector | — | ✓ |
| Circuit-Rotation | — | ✓ |

---

## Verifizierung

### 1. Health-Endpoint

```bash
curl -s http://localhost:7878/health
# Erwartete Ausgabe: ok
```

### 2. API-Metriken

```bash
curl -s http://localhost:7878/api/metrics | python3 -m json.tool
```

### 3. Prometheus-Endpunkt

```bash
curl -s http://localhost:7878/metrics | grep artishield
```

### 4. arti-Status im Dashboard

`http://localhost:7878` öffnen — der Status-Indikator oben rechts zeigt:

| Anzeige | Bedeutung |
|---------|-----------|
| `● arti online` | Vollbetrieb mit arti-hooks |
| `○ Kein arti (SOCKS-Modus)` | Nur SOCKS-basierte Detektoren aktiv |
| `◌ Verbinde mit Tor…` | arti bootstrapped noch |
| `✕ error: …` | arti nicht erreichbar |

### 5. Test-Events erzeugen

```bash
# Suspicious Relay manuell eintragen (Test)
curl -s -X POST http://localhost:7878/api/relay/AABBCCDD/flag \
  -H "Content-Type: application/json" \
  -d '{"flag":"test"}'
# Erwartete Ausgabe bei unbekanntem Relay: 404

# Erst Relay anlegen via interne Reputation, dann flaggen
curl -s http://localhost:7878/api/relays/suspicious
```

### 6. Unit-Tests ausführen

```bash
cargo test
# Erwartete Ausgabe: 80 passed; 0 failed
```

---

## Upgrade

### Binary-Update

```bash
git pull
cargo build --release
sudo install -m 755 target/release/artishield /usr/local/bin/artishield
sudo systemctl restart artishield
```

### Docker-Update

```bash
docker compose pull
docker compose up -d --build artishield
```

> Die SQLite-Datenbank ist abwärtskompatibel — kein Datenverlust beim Upgrade.

---

## Deinstallation

### Binary und Konfiguration

```bash
sudo systemctl disable --now artishield
sudo rm /usr/local/bin/artishield
sudo rm /etc/systemd/system/artishield.service
sudo systemctl daemon-reload
sudo rm -rf /etc/artishield
sudo rm -rf /var/lib/artishield   # Achtung: löscht DB und alle gespeicherten Events
sudo userdel artishield
```

### Docker

```bash
docker compose down -v   # -v löscht auch Volumes
docker rmi artishield:latest
```
