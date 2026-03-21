# 🛡️ Threat Intelligence Platform (TIP)

A production-grade cybersecurity platform for finance and banking environments.
Automatically collects threat intelligence from multiple OSINT sources, scores indicators
using a CVSS-aligned risk engine, enforces dynamic firewall rules, and visualizes
everything in a Kibana SIEM dashboard.

---

## 📁 Project Structure

```
threat-intelligence-platform/
├── config/
│   ├── config.yaml              # Central configuration — add your API keys here
│   └── mongo-init.js            # MongoDB collection and index initialization
├── week1_osint/
│   ├── feed_collector.py        # OSINT collectors: AlienVault OTX, AbuseIPDB, URLhaus
│   └── db_handler.py            # MongoDB interface with deduplication and audit logging
├── week2_siem/
│   ├── normalizer.py            # Risk scoring engine (0–10, CVSS v3 aligned)
│   └── elk_pusher.py            # MongoDB → Elasticsearch sync for Kibana
├── week3_enforcer/
│   ├── rule_engine.py           # iptables rule engine with whitelist and dry-run support
│   └── policy_daemon.py         # Continuous enforcement daemon with signal handling
├── week4_dashboard/
│   ├── rollback_manager.py      # CLI: list / unblock / reblock / flush / history
│   ├── alert_manager.py         # Email + Slack alerting with daily summaries
│   └── kibana_dashboard.json    # Import-ready Kibana 8.x dashboard
├── tests/
│   └── test_all.py              # 27 unit tests across all 4 weeks (all passing)
├── docs/
│   └── API_SETUP.md             # Free API registration guide
├── docker-compose.yml           # MongoDB + Elasticsearch + Kibana stack
├── requirements.txt             # Python dependencies
└── README.md
```

---

## ⚡ Quick Start

### Prerequisites
- Ubuntu / Kali Linux
- Docker + Docker Compose
- Python 3.10+
- 4GB RAM minimum (for Elasticsearch)

---

### Step 1 — Fix system memory for Elasticsearch

This is required before starting Docker. Run it once:

```bash
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

---

### Step 2 — Clone and configure

```bash
git clone https://github.com/pruthviraj-oo7/Advanced-Threat-Intelligence-Platform-TIP-Dynamic-Policy-Enforcer.git
cd Advanced-Threat-Intelligence-Platform-TIP-Dynamic-Policy-Enforcer
```

Add your free API keys to `config/config.yaml`:

```bash
nano config/config.yaml
```

Fill in the following API keys (see `docs/API_SETUP.md` for full registration instructions):

| API | Key field in config.yaml | Where to get it | Required |
|-----|--------------------------|-----------------|----------|
| AlienVault OTX | `apis.alienvault_otx.api_key` | https://otx.alienvault.com | ✅ Yes |
| AbuseIPDB | `apis.abuseipdb.api_key` | https://www.abuseipdb.com/api | ✅ Yes |
| VirusTotal | `apis.virustotal.api_key` | https://www.virustotal.com | ⚪ Optional |
| URLhaus | No key needed | https://urlhaus.abuse.ch | ⚪ Free/No key |

---

### Step 3 — Install Python dependencies

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install all required packages
pip install requests pymongo "elasticsearch==8.11.0" pyyaml aiohttp beautifulsoup4 python-dateutil validators schedule APScheduler colorlog pytest --break-system-packages
```

> **Note:** Every time you open a new terminal, activate the venv first with `source venv/bin/activate` before running any scripts.

---

### Step 4 — Start the infrastructure

```bash
docker-compose up -d
```

Wait about 60 seconds, then verify all containers are healthy:

```bash
docker ps
```

All three containers (`tip_mongodb`, `tip_elasticsearch`, `tip_kibana`) should show **healthy**.

---

### Step 5 — Run the pipeline

**Important: Always run all commands from the project root directory.**

```bash
# Week 1 — Collect threat indicators from OSINT feeds (~2-3 minutes)
python3 week1_osint/feed_collector.py

# Week 2 — Normalize and risk-score all indicators
python3 week2_siem/normalizer.py

# Week 2 — Push data to Elasticsearch for Kibana
python3 week2_siem/elk_pusher.py

# Week 3 — Start the policy enforcement daemon (Ctrl+C to stop)
sudo python3 week3_enforcer/policy_daemon.py

# Week 4 — List all blocked IPs
python3 week4_dashboard/rollback_manager.py list

# Week 4 — Unblock a specific IP (example)
python3 week4_dashboard/rollback_manager.py unblock 105.247.69.196 --actor "SOC_Analyst"

# Week 4 — View full audit history
python3 week4_dashboard/rollback_manager.py history
```

---

### Step 6 — Open Kibana

Navigate to: **http://localhost:5601**

1. Click ☰ → **Discover** → **Create data view**
2. Name: `TIP Threats` | Index pattern: `tip-threats` | Timestamp: `@timestamp`
3. Click **Save data view to Kibana**
4. Search `severity: HIGH` to see high-risk indicators
5. If no results appear, change the time range to **Last 7 days**

---

## 🧪 Run Tests

```bash
pytest tests/test_all.py -v
```

Expected output: **27 passed, 19 subtests passed**

---

## 🔧 Quick Reference

| Command | Description |
|---------|-------------|
| `docker-compose up -d` | Start MongoDB + Elasticsearch + Kibana |
| `docker-compose down` | Stop containers (data is preserved) |
| `docker-compose down -v` | Stop containers and delete all data |
| `python3 week1_osint/feed_collector.py` | Collect threat indicators |
| `python3 week2_siem/normalizer.py` | Normalize and risk-score indicators |
| `python3 week2_siem/elk_pusher.py` | Sync data to Elasticsearch/Kibana |
| `sudo python3 week3_enforcer/policy_daemon.py` | Start firewall enforcement daemon |
| `python3 week4_dashboard/rollback_manager.py list` | List all blocked IPs |
| `python3 week4_dashboard/rollback_manager.py unblock 105.247.69.196 --actor "SOC_Analyst"` | Unblock a specific IP |
| `python3 week4_dashboard/rollback_manager.py history` | View full audit history |
| `python3 week4_dashboard/rollback_manager.py reblock <IP> --actor "Name"` | Re-block an IP |
| `python3 week4_dashboard/rollback_manager.py flush --actor "Name" --confirm` | Emergency unblock all IPs |
| `pytest tests/test_all.py -v` | Run all unit tests |

---

## 🏗️ Architecture

```
[AlienVault OTX]  ──┐
[AbuseIPDB]       ──┼──► [feed_collector.py] ──► [MongoDB]
[URLhaus]         ──┤                                │
[VirusTotal]      ──┘                         [normalizer.py]
                                                      │
                                          [elk_pusher.py] ──► [Elasticsearch] ──► [Kibana :5601]
                                                      │
                                      [policy_daemon.py] ──► [iptables firewall rules]
                                                      │
                          [rollback_manager.py] + [alert_manager.py]
```

---

## 📊 Expected Results

| Metric | Value |
|--------|-------|
| Indicators collected | ~7,500–8,500 |
| HIGH severity IPs | ~500 |
| Unit tests passing | 27/27 |
| Kibana dashboard | http://localhost:5601 |

---

## 🔒 Security Notes

- The policy daemon runs in `dry_run: true` mode by default — logs what would be blocked without applying real iptables rules
- To enable live blocking, set `dry_run: false` in `config/config.yaml` and run with `sudo`
- All block and unblock actions are recorded in a PCI-DSS compliant audit log
- Private IP ranges (`10.x.x.x`, `192.168.x.x`, `172.16.x.x`, `127.x.x.x`) are always whitelisted

---

## 📄 License

MIT License — free for educational and commercial use.
