# Lattice Keeper

**Sovereign Mission Control for Smallholder Farmers**

Lattice Keeper is a CLI-based agricultural AI assistant built for regenerative farming. It combines local LLM intelligence (via [Ollama](https://ollama.ai)) with live weather data, a multi-tier safety filter (Guardian Vector), and a cryptographically signed forensic audit chain.

## Features

- **Local AI Advisor** — Farm-specific answers using Ollama models, with domain-aware routing (soil, water, crops, general)
- **Guardian Vector v3** — 3-tier safety filter that blocks harmful recommendations, adapts to weather conditions, and reinforces regenerative practices
- **Live Weather Integration** — Real-time conditions from Open-Meteo (wind, rain, temperature, frost risk)
- **Forensic Audit Chain** — SHA-256 hash-linked audit log with ECDSA digital signatures
- **Bitcoin Anchoring** — Optional OP_RETURN anchoring of Merkle roots to Bitcoin testnet
- **Farm Profile** — Persistent profile with soil health tracking
- **Multi-Channel Alerts** — Email, SMS (via email gateway), and push notifications (via ntfy.sh)

## Requirements

- Python 3.9+
- [Ollama](https://ollama.ai) running locally

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Pull the models
ollama pull llama3.2
ollama pull mistral

# Make sure Ollama is running
ollama serve

# Run Lattice Keeper
python lattice_keeper.py
```

## Commands

| Command | Description |
|---------|-------------|
| `/profile` | View farm profile |
| `/edit` | Update farm profile |
| `/weather` | Show live weather + frost risk |
| `/soil` | Soil health quick-tips |
| `/audit` | Show recent Guardian decisions |
| `/stats` | Guardian statistics |
| `/export` | Export audit log to JSON |
| `/verify` | Verify forensic audit integrity |
| `/anchor` | Bitcoin OP_RETURN anchor |
| `/clearlockout` | Reset Operator Hold lockout |
| `/quit` | Exit |

## Guardian Vector Tiers

1. **Tier 1 — Hard Veto**: Blocks synthetic herbicides, dangerous tillage on degraded soil, operations during frost risk
2. **Tier 2 — Environmental Adaptation**: Modifies recommendations based on wind speed, rain forecast, soil moisture, and soil temperature
3. **Tier 3 — Positive Reinforcement**: Recognizes and encourages regenerative practices (cover crops, compost, no-till, etc.)

## Configuration

Config files are stored in `~/.lattice_keeper/`:

- `farm_profile.json` — Farm profile data
- `alert_config.json` — Alert channel configuration (email, SMS, push)
- `operator_private_key.pem` — ECDSA signing key (auto-generated, owner-only permissions)
- `forensic_audit.json` — Persistent audit log with hash chain

### Alert Configuration

Create `~/.lattice_keeper/alert_config.json`:

```json
{
    "email": {
        "sender": "you@gmail.com",
        "receiver": "you@gmail.com",
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 465,
        "app_password": "your-app-password"
    },
    "sms": {
        "enabled": false,
        "phone_number": "15551234567",
        "carrier_gateway": "@txt.bell.ca"
    },
    "push": {
        "enabled": true,
        "topic": "lattice-your-farm",
        "base_url": "https://ntfy.sh"
    }
}
```

## License

MIT
