#!/usr/bin/env python3
"""
Lattice Keeper v0.5.0 — Sovereign Mission Control
====================================================
Full Operator Lattice with Guardian Vector v3, Forensic Auditor,
ECDSA Digital Signatures, Hash Chaining, Bitcoin OP_RETURN Anchoring,
Domain-Aware Model Routing, Weather Caching, and Seasonal Awareness.

Merged from v0.4.4 (extra sensor context, detailed genesis anchor)
and v0.4.5-fixed (all bug fixes, model routing, frost detection).

Dependencies:
    pip install requests ecdsa ollama --break-system-packages
    pip install bitcoinlib  # optional, for Bitcoin OP_RETURN anchoring

Ollama must be running:
    ollama serve
    ollama pull llama3.2
    ollama pull mistral   # optional, for domain-specific routing
"""

import json
import os
import re
import smtplib
import hashlib
import tempfile
import requests
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
from collections import Counter

from ecdsa import SigningKey, VerifyingKey, SECP256k1
import ollama

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────

WEATHER_URL  = "https://api.open-meteo.com/v1/forecast"
CONFIG_DIR   = Path.home() / ".lattice_keeper"
PROFILE_FILE = CONFIG_DIR / "farm_profile.json"

# Thresholds (Guardian Vector)
WIND_SPRAY_THRESHOLD_KMH = 30
RAIN_HEAVY_THRESHOLD_MM  = 15
RAIN_IRRIGATION_THRESHOLD_MM = 10
SOM_TILLAGE_THRESHOLD_PERCENT = 1.8
SOM_CRITICAL_PERCENT = 1.5
SOM_OPTIMAL_PERCENT  = 2.5
SOIL_TEMP_MIN_GERMINATION_C = 10
FROST_RISK_TEMP_C = 2
MOISTURE_SKIP_IRRIGATION_PERCENT = 65

# Limits
MAX_QUESTION_LENGTH = 250
MAX_AUDIT_ENTRIES   = 200
MAX_OP_RETURN_BYTES = 80

# Weather cache TTL (seconds)
WEATHER_CACHE_TTL = 300

# Model routing
MODELS = {
    "soil":    "mistral",
    "water":   "mistral",
    "crops":   "mistral",
    "general": "llama3.2",
}

DEFAULT_PROFILE = {
    "farm_name":                   "Jay's Valley Farm",
    "acres":                       2.0,
    "location":                    "Bathurst, NB",
    "latitude":                    47.6,
    "longitude":                   -65.6,
    "soil_organic_matter_percent": 2.5,
    "soil_moisture_percent":       45.0,
    "primary_crops":               ["vegetables", "cover crops"],
    "livestock":                   ["chickens", "duck", "quail"],
}

# Seasonal mapping
SEASON_MAP = {
    1: "winter", 2: "winter", 3: "early spring", 4: "spring",
    5: "late spring", 6: "early summer", 7: "summer", 8: "late summer",
    9: "early fall", 10: "fall", 11: "late fall", 12: "winter",
}


# ─────────────────────────────────────────────
# WEATHER (with cache)
# ─────────────────────────────────────────────

_weather_cache: Dict[str, Any] = {"data": None, "fetched_at": None}


def get_weather(profile: Dict[str, Any], ttl_seconds: int = WEATHER_CACHE_TTL) -> Dict[str, Any]:
    """Fetch current wind and today's rain forecast from Open-Meteo, with TTL cache."""
    if (_weather_cache["fetched_at"] is not None
            and (datetime.now() - _weather_cache["fetched_at"]).total_seconds() < ttl_seconds):
        return _weather_cache["data"]

    try:
        r = requests.get(WEATHER_URL, params={
            "latitude":      profile.get("latitude", 47.6),
            "longitude":     profile.get("longitude", -65.6),
            "current":       "wind_speed_10m,temperature_2m,relative_humidity_2m",
            "daily":         "precipitation_sum,temperature_2m_max,temperature_2m_min",
            "timezone":      "America/Halifax",
            "forecast_days": 2,
        }, timeout=8)
        r.raise_for_status()
        d     = r.json()
        cur   = d.get("current", {})
        daily = d.get("daily", {})
        precip   = daily.get("precipitation_sum", [0, 0])
        temp_max = daily.get("temperature_2m_max", [None, None])
        temp_min = daily.get("temperature_2m_min", [None, None])
        result = {
            "wind":        cur.get("wind_speed_10m", 0),
            "rain":        precip[0] if precip else 0,
            "rain_tmrw":   precip[1] if len(precip) > 1 else 0,
            "temperature": cur.get("temperature_2m"),
            "humidity":    cur.get("relative_humidity_2m"),
            "temp_max":    temp_max[0] if temp_max else None,
            "temp_min":    temp_min[0] if temp_min else None,
        }
        _weather_cache["data"] = result
        _weather_cache["fetched_at"] = datetime.now()
        return result
    except Exception as e:
        print(f"  ⚠️  Weather fetch failed: {e}")
        return {"wind": 0, "rain": 0, "rain_tmrw": 0}


# ─────────────────────────────────────────────
# GUARDIAN VECTOR v3 — Forensic Edition (fixed)
# ─────────────────────────────────────────────

class GuardianVector:
    """
    3-tier runtime safety filter + security layer + forensic audit chain.

    Forensic features:
    - SHA-256 hash chain linking every audit entry
    - ECDSA digital signature on every entry
    - Merkle root computation for batch integrity
    - Bitcoin OP_RETURN anchoring (testnet by default)

    Alert config: ~/.lattice_keeper/alert_config.json
    """

    def __init__(self) -> None:
        self.audit_log: List[Dict[str, Any]] = []
        self.config_dir = CONFIG_DIR
        self.config_dir.mkdir(exist_ok=True)

        self.lockout_file     = self.config_dir / "guardian_lockout.json"
        self.alert_file       = self.config_dir / "openwebui_alert.json"
        self.audit_file       = self.config_dir / "forensic_audit.json"
        self.hash_chain_file  = self.config_dir / "forensic_hash_chain.txt"
        self.anchor_file      = self.config_dir / "bitcoin_anchors.json"
        self.private_key_file = self.config_dir / "operator_private_key.pem"
        self.public_key_file  = self.config_dir / "operator_public_key.pem"

        self.is_testnet  = True
        self.alert_cfg   = self._load_alert_config()
        self.signing_key = self._load_or_generate_keys()
        self.current_hash = self._load_hash_chain()

    # ── Alert config ──────────────────────────

    def _load_alert_config(self) -> Dict[str, Any]:
        cfg_file = self.config_dir / "alert_config.json"
        if cfg_file.exists():
            try:
                return json.loads(cfg_file.read_text())
            except (json.JSONDecodeError, OSError) as e:
                print(f"  ⚠️  Could not load alert_config.json: {e}")
        return {}

    def _email_cfg(self) -> Dict[str, Any]:
        return self.alert_cfg.get("email", {})

    def _sms_cfg(self) -> Dict[str, Any]:
        return self.alert_cfg.get("sms", {})

    def _push_cfg(self) -> Dict[str, Any]:
        return self.alert_cfg.get("push", {})

    # ── Alert senders ─────────────────────────

    def _send_email(self, subject: str, body: str) -> None:
        cfg = self._email_cfg()
        if not cfg.get("app_password"):
            return
        try:
            msg = MIMEMultipart()
            msg["Subject"] = f"[LK] {subject}"
            msg["From"]    = cfg["sender"]
            msg["To"]      = cfg["receiver"]
            msg.attach(MIMEText(body + f"\nTime: {datetime.now()}", "plain"))
            with smtplib.SMTP_SSL(cfg["smtp_server"], cfg["smtp_port"]) as s:
                s.login(cfg["sender"], cfg["app_password"])
                s.sendmail(cfg["sender"], cfg["receiver"], msg.as_string())
        except (smtplib.SMTPException, OSError):
            pass

    def _send_sms(self, subject: str, body: str) -> None:
        cfg = self._sms_cfg()
        ecfg = self._email_cfg()
        if not cfg.get("enabled") or not ecfg.get("app_password"):
            return
        try:
            phone = re.sub(r"[^0-9]", "", cfg.get("phone_number", ""))
            if not phone:
                return
            msg = MIMEText(body[:140])
            msg["Subject"] = subject[:50]
            msg["From"]    = ecfg["sender"]
            msg["To"]      = f"{phone}{cfg['carrier_gateway']}"
            with smtplib.SMTP_SSL(ecfg["smtp_server"], ecfg["smtp_port"]) as s:
                s.login(ecfg["sender"], ecfg["app_password"])
                s.sendmail(ecfg["sender"],
                           f"{phone}{cfg['carrier_gateway']}",
                           msg.as_string())
        except (smtplib.SMTPException, OSError):
            pass

    def _send_push(self, title: str, message: str, priority: int = 3) -> None:
        cfg = self._push_cfg()
        if not cfg.get("enabled") or not cfg.get("topic"):
            return
        try:
            requests.post(
                f"{cfg.get('base_url', 'https://ntfy.sh')}/{cfg['topic']}",
                json={"title": title, "message": message,
                      "tags": ["warning", "lattice"], "priority": priority},
                timeout=5)
        except (requests.RequestException, OSError):
            pass

    def _create_alert(self, title: str, message: str) -> None:
        try:
            self.alert_file.write_text(json.dumps(
                {"timestamp": datetime.now().isoformat(),
                 "title": title, "message": message}, indent=2))
        except OSError:
            pass

    def _alert_all(self, title: str, message: str, priority: int = 3) -> None:
        self._create_alert(title, message)
        self._send_email(title, message)
        self._send_sms(title, message)
        self._send_push(title, message, priority)

    # ── Cryptographic layer ───────────────────

    def _load_or_generate_keys(self) -> SigningKey:
        if self.private_key_file.exists() and self.public_key_file.exists():
            try:
                return SigningKey.from_pem(self.private_key_file.read_bytes())
            except Exception:
                pass
        sk = SigningKey.generate(curve=SECP256k1)
        self.private_key_file.write_bytes(sk.to_pem())
        self.public_key_file.write_bytes(sk.get_verifying_key().to_pem())
        # Restrict permissions so only the owner can read the private key
        os.chmod(self.private_key_file, 0o600)
        os.chmod(self.public_key_file, 0o644)
        print("  🔑 New operator key pair generated (private key permissions: owner-only).")
        return sk

    def _sign_entry(self, entry: Dict[str, Any]) -> str:
        """Sign the entry dict. The caller controls which fields are present."""
        try:
            canonical = json.dumps(entry, sort_keys=True,
                                   separators=(',', ':')).encode("utf-8")
            return self.signing_key.sign_deterministic(
                canonical, hashfunc=hashlib.sha256).hex()
        except Exception:
            return "SIGNING_FAILED"

    def _load_hash_chain(self) -> str:
        if self.hash_chain_file.exists():
            try:
                return self.hash_chain_file.read_text().strip()
            except OSError:
                pass
        return hashlib.sha256(b"Genesis Anchor - Operator Lattice - Jay Valley - 2026").hexdigest()

    def _save_hash_chain(self, new_hash: str) -> None:
        try:
            self.hash_chain_file.write_text(new_hash)
        except OSError:
            pass

    def _compute_entry_hash(self, entry: Dict[str, Any], previous_hash: str) -> str:
        combined = previous_hash + json.dumps(
            entry, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()

    def _get_merkle_root(self) -> str:
        if not self.audit_log:
            return hashlib.sha256(b"empty_log").hexdigest()
        leaves = [
            hashlib.sha256(
                json.dumps(e, sort_keys=True, separators=(',', ':')).encode()
            ).digest()
            for e in self.audit_log
        ]
        while len(leaves) > 1:
            if len(leaves) % 2 == 1:
                leaves.append(leaves[-1])
            leaves = [hashlib.sha256(leaves[i] + leaves[i + 1]).digest()
                      for i in range(0, len(leaves), 2)]
        return leaves[0].hex()

    # ── Security layer ────────────────────────

    def _redact_for_alert(self, query: str) -> str:
        """Redact sensitive patterns from a query before including in alert messages."""
        for p in [
            r"bypass|disable|override|hack|exploit|remove guard|ignore rules",
            r"satellite telemetry|cfs|onair|dart|apophis|planetary defense",
            r"nuclear|weapon|military|offensive|damage|harm|sabotage",
        ]:
            query = re.sub(p, "[REDACTED]", query, flags=re.IGNORECASE)
        return query[:MAX_QUESTION_LENGTH] + "..." if len(query) > MAX_QUESTION_LENGTH else query

    def _check_bad_intent(self, question: str) -> Dict[str, Any]:
        state: Dict[str, Any] = {"triggers": [], "locked_until": None}
        if self.lockout_file.exists():
            try:
                state = json.loads(self.lockout_file.read_text())
            except (json.JSONDecodeError, OSError):
                pass

        now = datetime.now()

        if state.get("locked_until"):
            locked_until = datetime.fromisoformat(state["locked_until"])
            if now < locked_until:
                msg = f"Operator Hold Lockout active until {state['locked_until'][:16]}"
                self._alert_all("OPERATOR HOLD LOCKOUT ACTIVE", msg, priority=4)
                return {"pass": False, "reason": "Operator Hold Active"}
            else:
                state["locked_until"] = None
                state["triggers"] = []
                self.lockout_file.write_text(json.dumps(state))

        bad_words = ["bypass", "ignore rules", "hack", "military", "weapon", "sabotage"]
        if any(w in question.lower() for w in bad_words):
            sanitized = self._redact_for_alert(question)
            recent = [t for t in state.get("triggers", [])
                      if now - datetime.fromisoformat(t) < timedelta(hours=1)]
            recent.append(now.isoformat())
            state["triggers"] = recent

            if len(recent) >= 3:
                state["locked_until"] = (now + timedelta(hours=24)).isoformat()
                self.lockout_file.write_text(json.dumps(state))
                msg = "3 bad intent triggers in 60 min. Operator Hold lockout for 24 hours."
                self._alert_all("OPERATOR HOLD LOCKOUT ACTIVATED",
                                msg + f"\nSanitized: {sanitized}", priority=4)
                return {"pass": False, "reason": msg, "lockout": True}

            self.lockout_file.write_text(json.dumps(state))
            remaining = 3 - len(recent)
            msg = f"Bad intent query blocked. Triggers remaining: {remaining}"
            self._alert_all("BAD INTENT DETECTED", msg + f"\nSanitized: {sanitized}")
            return {"pass": False, "reason": "Tier 1: Bad intent detected"}

        return {"pass": True}

    def manual_clear_lockout(self) -> None:
        if self.lockout_file.exists():
            self.lockout_file.unlink()
        if self.alert_file.exists():
            self.alert_file.unlink()
        print("   ✓ Operator Hold lockout manually cleared.")
        self._alert_all("Lockout Cleared", "Manual override by operator.")

    def _is_lockout_active(self) -> bool:
        if not self.lockout_file.exists():
            return False
        try:
            state = json.loads(self.lockout_file.read_text())
            if state.get("locked_until"):
                return datetime.now() < datetime.fromisoformat(state["locked_until"])
        except (json.JSONDecodeError, OSError):
            pass
        return False

    # ── Guardian evaluate ─────────────────────

    def evaluate(self, raw_output: str, context: Dict[str, Any]) -> Dict[str, str]:
        """
        Evaluate AI output through Guardian safety tiers.

        Context keys:
            question                    : str
            soil_organic_matter_percent : float
            soil_moisture_percent       : float  (optional)
            soil_temperature_c          : float  (optional)
            canopy_temp_mean_c          : float  (optional, from sensor)
            current_wind_speed          : float  (km/h)
            forecast_rain_today         : float  (mm)
            frost_risk                  : str    "LOW" | "HIGH" (optional)
            ndvi_current                : float  (optional, from sensor)
        """
        user_q = context.get("question", "")
        security = self._check_bad_intent(user_q)
        if not security.get("pass", True):
            result = {
                "decision":    "BLOCKED",
                "output":      f"🛑 OPERATOR HOLD: {security['reason']}",
                "explanation": f"Security Layer: {security['reason']}",
                "tier":        "0",
            }
            self.log_audit(user_q, result, context)
            return result

        lower    = raw_output.lower()
        som      = context.get("soil_organic_matter_percent")
        moisture = context.get("soil_moisture_percent")
        soil_t   = context.get("soil_temperature_c")
        wind     = context.get("current_wind_speed", 0) or 0
        rain     = context.get("forecast_rain_today", 0) or 0
        frost    = context.get("frost_risk", "LOW")
        # Extra sensor fields (canopy_temp_mean_c, ndvi_current) are captured
        # in the audit context_snapshot for forensic logging. Add evaluation
        # rules here when sensor integration is available.

        # Tier 1 — Hard Veto
        if any(w in lower for w in ["glyphosate", "roundup", "2,4-d", "dicamba", "atrazine"]):
            result = {
                "decision":    "REJECT",
                "output":      "⚠️  Cannot recommend synthetic herbicides. Use mechanical or cultural control.",
                "explanation": "Tier 1 Veto: Prohibited herbicide.",
                "tier":        "1",
            }
            self.log_audit(user_q, result, context)
            return result

        if (som is not None and som < SOM_TILLAGE_THRESHOLD_PERCENT
                and any(w in lower for w in ["tillage", "plow", "deep till"])):
            result = {
                "decision":    "REJECT",
                "output":      f"⚠️  Blocked: SOM is {som}% — tillage risks serious soil collapse. Use no-till.",
                "explanation": f"Tier 1 Veto: Low SOM ({som}%) + tillage.",
                "tier":        "1",
            }
            self.log_audit(user_q, result, context)
            return result

        if frost == "HIGH" and any(w in lower for w in ["plant", "transplant", "seed", "spray", "till"]):
            result = {
                "decision":    "REJECT",
                "output":      "⚠️  High frost risk. Postpone operations and protect with mulch or row covers.",
                "explanation": "Tier 1 Veto: Frost risk protection.",
                "tier":        "1",
            }
            self.log_audit(user_q, result, context)
            return result

        # Tier 2 — Environmental Adaptation
        if (moisture is not None and moisture > MOISTURE_SKIP_IRRIGATION_PERCENT
                and any(w in lower for w in ["irrigate", "water heavily"])):
            result = {
                "decision":    "MODIFIED",
                "output":      f"Soil moisture is {moisture}% — irrigation not needed.",
                "explanation": f"Tier 2: Skip irrigation (moisture {moisture}%).",
                "tier":        "2",
            }
            self.log_audit(user_q, result, context)
            return result

        if wind > WIND_SPRAY_THRESHOLD_KMH and any(w in lower for w in ["spray", "apply", "foliar"]):
            result = {
                "decision":    "MODIFIED",
                "output":      f"⚠️  Wind Warning: {wind} km/h. Postpone spraying to prevent drift.",
                "explanation": f"Tier 2: Wind drift prevention ({wind} km/h).",
                "tier":        "2",
            }
            self.log_audit(user_q, result, context)
            return result

        if rain > RAIN_HEAVY_THRESHOLD_MM and any(w in lower for w in ["fertilize", "manure", "nitrogen", "apply"]):
            result = {
                "decision":    "MODIFIED",
                "output":      f"⚠️  Heavy rain ({rain}mm) forecast. Postpone applications to prevent runoff.",
                "explanation": f"Tier 2: Nutrient leaching prevention ({rain}mm).",
                "tier":        "2",
            }
            self.log_audit(user_q, result, context)
            return result

        if rain > RAIN_IRRIGATION_THRESHOLD_MM and any(w in lower for w in ["irrigate", "water heavily"]):
            result = {
                "decision":    "MODIFIED",
                "output":      f"Rain ({rain}mm) forecast today — irrigation not needed.",
                "explanation": f"Tier 2: Skip irrigation — rain forecast ({rain}mm).",
                "tier":        "2",
            }
            self.log_audit(user_q, result, context)
            return result

        if (soil_t is not None and soil_t < SOIL_TEMP_MIN_GERMINATION_C
                and any(w in lower for w in ["plant", "seed", "transplant"])):
            result = {
                "decision":    "MODIFIED",
                "output":      f"Soil temperature is {soil_t}°C — too cold for good germination. Wait for warmer conditions.",
                "explanation": f"Tier 2: Cold soil protection ({soil_t}°C).",
                "tier":        "2",
            }
            self.log_audit(user_q, result, context)
            return result

        # Tier 3 — Positive Reinforcement
        positives = [w for w in [
            "cover crop", "compost", "mulch", "no-till", "green manure",
            "crop rotation", "companion plant", "rainwater", "earthworm",
            "biochar", "mycorrhizal", "minimal tillage", "row cover",
        ] if w in lower]
        if positives:
            result = {
                "decision":    "REINFORCED",
                "output":      raw_output + f"\n\n  🌱 Guardian: Excellent regenerative practice ({', '.join(positives)}).",
                "explanation": f"Tier 3: {', '.join(positives)}.",
                "tier":        "3",
            }
            self.log_audit(user_q, result, context)
            return result

        result = {
            "decision":    "APPROVED",
            "output":      raw_output,
            "explanation": "Guardian Vector: Clean pass.",
            "tier":        "pass",
        }
        self.log_audit(user_q, result, context)
        return result

    # ── Forensic audit logging ────────────────

    def log_audit(self, question: str, result: Dict[str, str],
                  context: Optional[Dict[str, Any]] = None) -> None:
        """Log entry with hash chain + digital signature. Called once inside evaluate()."""
        SNAPSHOT_KEYS = [
            "soil_organic_matter_percent", "soil_moisture_percent",
            "soil_temperature_c", "canopy_temp_mean_c", "frost_risk",
            "ndvi_current", "current_wind_speed", "forecast_rain_today",
        ]
        entry = {
            "timestamp":        datetime.now().isoformat(),
            "question":         question[:MAX_QUESTION_LENGTH],
            "decision":         result.get("decision"),
            "tier":             result.get("tier"),
            "explanation":      result.get("explanation"),
            "context_snapshot": {k: (context or {}).get(k) for k in SNAPSHOT_KEYS},
        }

        # Compute hash over the base entry (before hash/prev_hash/signature are added)
        entry_hash = self._compute_entry_hash(entry, self.current_hash)

        # Add chain fields — signature is computed over entry WITH hash and previous_hash
        entry["hash"]          = entry_hash
        entry["previous_hash"] = self.current_hash

        # Sign the entry that includes hash + previous_hash but NOT signature itself
        entry["signature"] = self._sign_entry(entry)

        self.audit_log.append(entry)
        if len(self.audit_log) > MAX_AUDIT_ENTRIES:
            self.audit_log.pop(0)

        # Persist to disk using atomic write — only advance hash chain on success
        try:
            full_log: List[Dict[str, Any]] = []
            if self.audit_file.exists():
                full_log = json.loads(self.audit_file.read_text())
            full_log.append(entry)

            # Atomic write: write to temp file then rename
            dir_path = self.audit_file.parent
            with tempfile.NamedTemporaryFile(mode="w", dir=dir_path,
                                             suffix=".tmp", delete=False) as tmp:
                json.dump(full_log, tmp, indent=2)
                tmp_path = Path(tmp.name)
            tmp_path.replace(self.audit_file)

            # Only advance hash chain after successful disk write
            self.current_hash = entry_hash
            self._save_hash_chain(entry_hash)
        except (OSError, json.JSONDecodeError) as e:
            # Disk write failed — hash chain NOT advanced to stay in sync
            print(f"  ⚠️  Audit disk write failed: {e}")

    def verify_audit_integrity(self) -> bool:
        """Verify the full forensic audit chain: hash links + digital signatures."""
        if not self.audit_file.exists():
            print("  No audit log yet.\n")
            return True
        try:
            log = json.loads(self.audit_file.read_text())
            current = hashlib.sha256(b"Genesis Anchor - Operator Lattice - Jay Valley - 2026").hexdigest()
            vk = VerifyingKey.from_pem(self.public_key_file.read_bytes())

            for i, entry in enumerate(log):
                stored_hash = entry.get("hash")
                stored_prev = entry.get("previous_hash")
                stored_sig  = entry.get("signature")

                # Check hash chain link
                if stored_prev != current:
                    print(f"  ⚠️  Hash chain broken at entry {i}!\n")
                    return False

                # Recompute hash over base entry (without hash/previous_hash/signature)
                base_entry = {k: v for k, v in entry.items()
                              if k not in ("hash", "previous_hash", "signature")}
                computed = self._compute_entry_hash(base_entry, current)
                if computed != stored_hash:
                    print(f"  ⚠️  Hash mismatch at entry {i}!\n")
                    return False

                # Verify signature (signed over entry WITH hash + previous_hash, WITHOUT signature)
                if stored_sig and stored_sig != "SIGNING_FAILED":
                    sig_entry = {k: v for k, v in entry.items() if k != "signature"}
                    canonical = json.dumps(sig_entry, sort_keys=True,
                                           separators=(',', ':')).encode("utf-8")
                    try:
                        vk.verify(bytes.fromhex(stored_sig), canonical,
                                  hashfunc=hashlib.sha256)
                    except Exception:
                        print(f"  ⚠️  Signature verification failed at entry {i}!\n")
                        return False

                current = stored_hash

            print("  ✓ Forensic audit verified: hash chain intact + all signatures valid.\n")
            return True
        except Exception as e:
            print(f"  ⚠️  Verification error: {e}\n")
            return False

    def show_audit(self, n: int = 10) -> None:
        if not self.audit_log:
            print("  No audit records yet.\n")
            return
        print(f"\n  📋 Forensic Auditor — Last {min(n, len(self.audit_log))} decisions:\n")
        for e in self.audit_log[-n:]:
            print(f"  [{e['timestamp'][11:16]}] {e['decision']:<10} "
                  f"| Tier {e.get('tier', '?')} | {e['explanation'][:60]}")
        print()

    def export_audit(self) -> None:
        filepath = self.config_dir / f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            filepath.write_text(json.dumps(self.audit_log, indent=2))
            print(f"  ✓ Audit exported to {filepath}\n")
        except OSError as e:
            print(f"  ✗ Export failed: {e}\n")

    def get_stats(self) -> Dict[str, Any]:
        if not self.audit_log:
            return {
                "total": 0, "safety_interventions": 0,
                "protection_rate": 0.0, "breakdown": {},
                "security_stats": {
                    "bad_intent_triggers": 0,
                    "current_lockout_active": False,
                },
            }
        decisions  = [e["decision"] for e in self.audit_log]
        safety     = sum(1 for d in decisions if d in ["BLOCKED", "REJECT", "MODIFIED"])
        bad_intent = sum(1 for e in self.audit_log
                         if "bad intent" in e.get("explanation", "").lower())
        return {
            "total":                len(self.audit_log),
            "breakdown":            dict(Counter(decisions)),
            "safety_interventions": safety,
            "protection_rate":      round((safety / len(decisions)) * 100, 1),
            "security_stats": {
                "bad_intent_triggers":    bad_intent,
                "current_lockout_active": self._is_lockout_active(),
            },
        }

    def anchor_to_bitcoin(self) -> Optional[str]:
        """Anchor Merkle root of audit log to Bitcoin testnet via OP_RETURN."""
        merkle_root = self._get_merkle_root()
        anchor_data = {
            "timestamp":   datetime.now().isoformat(),
            "merkle_root": merkle_root,
            "log_size":    len(self.audit_log),
            "note":        "Lattice Keeper Forensic Auditor Anchor",
        }
        try:
            from bitcoinlib.wallets import Wallet

            network     = "testnet" if self.is_testnet else "bitcoin"
            wallet_name = f"lattice_keeper_{network}"
            try:
                wallet = Wallet(wallet_name, network=network)
            except Exception:
                wallet = Wallet.create(wallet_name, network=network)

            data_bytes = json.dumps(
                anchor_data, separators=(',', ':')).encode()[:MAX_OP_RETURN_BYTES]

            t = wallet.send_to(
                "OP_RETURN " + data_bytes.hex(),
                value=0,
                fee=1000,
            )
            txid = t.txid if hasattr(t, "txid") else str(t)
            anchor_data.update({"txid": txid, "network": network})

            anchors: List[Dict[str, Any]] = []
            if self.anchor_file.exists():
                anchors = json.loads(self.anchor_file.read_text())
            anchors.append(anchor_data)
            self.anchor_file.write_text(json.dumps(anchors, indent=2))

            print(f"  ✓ Bitcoin OP_RETURN anchor created on {network}!")
            print(f"  TXID        : {txid}")
            print(f"  Merkle Root : {merkle_root[:16]}...{merkle_root[-8:]}\n")
            return txid

        except ImportError:
            print("  ⚠️  bitcoinlib not installed. Run: pip install bitcoinlib\n")
        except Exception as e:
            print(f"  ⚠️  Bitcoin anchoring failed: {e}")
            print("  Tip: Fund your testnet wallet before anchoring.\n")
        return None


# ─────────────────────────────────────────────
# PROFILE
# ─────────────────────────────────────────────

def load_profile() -> Dict[str, Any]:
    """Load the farm profile from disk, or create the default."""
    CONFIG_DIR.mkdir(exist_ok=True)
    if PROFILE_FILE.exists():
        try:
            return json.loads(PROFILE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    PROFILE_FILE.write_text(json.dumps(DEFAULT_PROFILE, indent=2))
    return DEFAULT_PROFILE.copy()


def save_profile(profile: Dict[str, Any]) -> None:
    """Persist the farm profile to disk."""
    PROFILE_FILE.write_text(json.dumps(profile, indent=2))


def edit_profile(profile: Dict[str, Any]) -> Dict[str, Any]:
    """Interactive editor for the farm profile."""
    print("\n  FARM PROFILE EDITOR  (Enter to keep current value)")
    print("  " + "─" * 44)
    for key, label, cast in [
        ("farm_name",                   "Farm name",       str),
        ("acres",                       "Acres",           float),
        ("soil_organic_matter_percent", "Soil OM %",       float),
        ("soil_moisture_percent",       "Soil moisture %", float),
        ("latitude",                    "Latitude",        float),
        ("longitude",                   "Longitude",       float),
    ]:
        val = input(f"  {label} [{profile.get(key, '')}]: ").strip()
        if val:
            try:
                profile[key] = cast(val)
            except ValueError:
                print("  (invalid input, keeping current value)")
    save_profile(profile)
    print("\n  ✓ Profile saved.\n")
    return profile


def show_profile(profile: Dict[str, Any]) -> None:
    """Display the current farm profile."""
    som = profile.get("soil_organic_matter_percent")
    if som is not None and som < SOM_CRITICAL_PERCENT:
        som_line = f"  SOM       : {som}%  ⚠️  CRITICAL"
    elif som is not None and som < SOM_OPTIMAL_PERCENT:
        som_line = f"  SOM       : {som}%  📊 Room to improve"
    elif som is not None:
        som_line = f"  SOM       : {som}%  ✅ Excellent"
    else:
        som_line = "  SOM       : not measured"
    print(f"""
  🌾 FARM PROFILE
  {"─" * 44}
  Farm      : {profile.get("farm_name", "?")}
  Acres     : {profile.get("acres", "?")}
  Location  : {profile.get("location", "?")}
{som_line}
  Moisture  : {profile.get("soil_moisture_percent", "?")}%
  Crops     : {", ".join(profile.get("primary_crops", []))}
  Livestock : {", ".join(profile.get("livestock", []))}
""")


# ─────────────────────────────────────────────
# MODEL ROUTING
# ─────────────────────────────────────────────

def route_question(q: str) -> str:
    """Route a question to the best-suited model domain."""
    q = q.lower()
    if any(k in q for k in [
        "soil", "compost", "organic matter", "som", "fertility",
        "mulch", "amendment", "ph", "humus", "earthworm",
    ]):
        return "soil"
    if any(k in q for k in [
        "water", "irrigation", "drought", "aquifer", "rain",
        "moisture", "flood", "runoff", "well",
    ]):
        return "water"
    if any(k in q for k in [
        "crop", "plant", "seed", "harvest", "rotation", "grow", "yield",
        "pest", "weed", "companion", "tomato", "potato", "bean",
        "squash", "garlic", "kale", "carrot",
    ]):
        return "crops"
    return "general"


# ─────────────────────────────────────────────
# AI QUERY
# ─────────────────────────────────────────────

def get_ai_response(question: str, profile: Dict[str, Any], weather: Dict[str, Any]) -> str:
    """Query local Ollama with full farm + weather + seasonal context."""
    som = profile.get("soil_organic_matter_percent", "?")
    som_note = ""
    if isinstance(som, (int, float)):
        if som < SOM_CRITICAL_PERCENT:
            som_note = f" CRITICAL: SOM {som}% — below survival threshold."
        elif som < 2.0:
            som_note = f" NOTE: SOM {som}% — below optimal."

    season = SEASON_MAP.get(datetime.now().month, "unknown")

    system_msg = (
        f"You are Lattice Keeper, a protective agricultural AI for {profile.get('farm_name', 'the farm')}. "
        f"Farm: {profile.get('acres', 2)} acres in {profile.get('location', 'New Brunswick')}. "
        f"Soil OM: {som}%.{som_note} "
        f"Current season: {season}. "
        f"Weather: {weather.get('temperature')}°C, {weather.get('wind', 0)} km/h wind, "
        f"{weather.get('rain', 0)}mm rain today, {weather.get('rain_tmrw', 0)}mm tomorrow. "
        "Priority: Long-term soil and water health. No synthetic herbicides. "
        "Be practical and concise. Atlantic Canada conditions apply."
    )

    domain = route_question(question)
    model  = MODELS.get(domain, "llama3.2")

    try:
        response = ollama.chat(
            model=model,
            messages=[
                {"role": "system", "content": system_msg},
                {"role": "user",   "content": question},
            ],
        )
        return response["message"]["content"].strip()
    except Exception as e:
        return f"ERROR: {e}"


# ─────────────────────────────────────────────
# FROST RISK DETECTION
# ─────────────────────────────────────────────

def detect_frost_risk(weather: Dict[str, Any]) -> str:
    """Derive frost risk from forecast minimum temperature."""
    temp_min = weather.get("temp_min")
    if temp_min is not None and temp_min <= FROST_RISK_TEMP_C:
        return "HIGH"
    return "LOW"


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main() -> None:
    CONFIG_DIR.mkdir(exist_ok=True)
    profile  = load_profile()
    guardian = GuardianVector()

    print("\n" + "=" * 70)
    print("  LATTICE KEEPER v0.5.0 — Sovereign Mission Control")
    print(f"  Farm: {profile['farm_name']} | {profile['acres']} acres")
    print("  Guardian: ARMED | Forensic Audit: ACTIVE | Bitcoin: READY")
    print("  Type /help for commands")
    print("=" * 70)

    # Ollama connection check
    try:
        ollama.list()
    except Exception:
        print("\n  ❌ Ollama not running. Start with: ollama serve\n")
        return

    show_profile(profile)

    while True:
        try:
            user_input = input("\n🌱 You: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n  Peace holds. Mission is good.")
            break

        if not user_input:
            continue

        if user_input.startswith("/"):
            cmd = user_input.lower().split()[0]

            if cmd in ("/help", "/?"):
                print("""
  Commands:
  ─────────────────────────────────────────────
  /profile      View farm profile
  /edit         Update farm profile
  /weather      Show live weather
  /soil         Soil health quick-tips
  /audit        Show recent Guardian decisions
  /stats        Guardian statistics
  /export       Export audit log to JSON
  /verify       Verify forensic audit integrity
  /anchor       Bitcoin OP_RETURN anchor
  /clearlockout Reset Operator Hold lockout
  /quit         Exit
  ─────────────────────────────────────────────""")

            elif cmd == "/profile":
                show_profile(profile)

            elif cmd == "/edit":
                profile = edit_profile(profile)

            elif cmd == "/weather":
                print("\n  Fetching weather...", end="", flush=True)
                w = get_weather(profile, ttl_seconds=0)  # Force fresh fetch
                print(" DONE\n")
                frost = detect_frost_risk(w)
                print("  ☁️  CONDITIONS")
                print(f"  Temperature : {w.get('temperature')}°C")
                print(f"  Humidity    : {w.get('humidity')}%")
                print(f"  Wind        : {w.get('wind', 0)} km/h")
                print(f"  Rain today  : {w.get('rain', 0)} mm")
                print(f"  Rain tmrw   : {w.get('rain_tmrw', 0)} mm")
                print(f"  Frost risk  : {frost}\n")

            elif cmd == "/soil":
                print("""
  🌱 SOIL HEALTH QUICK-TIPS
  ─────────────────────────────────────────────
  • Target SOM above 2.5% for best results
  • Add compost in fall so it breaks down over winter
  • Cover crops (clover, winter rye) protect soil between seasons
  • Minimize tillage — preserves fungal networks and earthworms
  • Compost your chicken manure — free fertilizer for your beds
  • Test soil pH — most vegetables prefer 6.0–7.0
  ─────────────────────────────────────────────""")

            elif cmd == "/audit":
                guardian.show_audit()

            elif cmd == "/stats":
                s = guardian.get_stats()
                print(f"""
  📊 GUARDIAN STATISTICS
  ─────────────────────────────────────────────
  Total decisions      : {s['total']}
  Safety interventions : {s['safety_interventions']}
  Protection rate      : {s['protection_rate']}%
  Lockout active       : {s['security_stats']['current_lockout_active']}
  Bad intent triggers  : {s['security_stats']['bad_intent_triggers']}
  Breakdown            : {s['breakdown']}
  ─────────────────────────────────────────────""")

            elif cmd == "/export":
                guardian.export_audit()

            elif cmd == "/verify":
                guardian.verify_audit_integrity()

            elif cmd == "/anchor":
                guardian.anchor_to_bitcoin()

            elif cmd == "/clearlockout":
                confirm = input("  Clear lockout? Type CONFIRM: ").strip()
                if confirm == "CONFIRM":
                    guardian.manual_clear_lockout()
                else:
                    print("  Cancelled.\n")

            elif cmd in ("/quit", "/exit"):
                print("  Peace holds. Mission is good.")
                break

            else:
                print(f"  Unknown command: {cmd}. Type /help\n")

            continue

        # ── AI QUERY ──────────────────────────────
        print("  Gathering weather...", end="", flush=True)
        weather = get_weather(profile)
        print(f" DONE ({weather['wind']} km/h wind, {weather['rain']}mm rain)")

        domain = route_question(user_input)
        model  = MODELS.get(domain, "llama3.2")
        print(f"  Consulting {domain} model ({model})...", end="", flush=True)
        raw_ai = get_ai_response(user_input, profile, weather)
        print(" DONE")

        if raw_ai.startswith("ERROR"):
            print(f"\n  ❌ {raw_ai}\n")
            continue

        frost_risk = detect_frost_risk(weather)

        # evaluate() calls log_audit() internally — do NOT call it again
        ctx: Dict[str, Any] = {
            "question":                    user_input,
            "soil_organic_matter_percent": profile.get("soil_organic_matter_percent"),
            "soil_moisture_percent":       profile.get("soil_moisture_percent"),
            "soil_temperature_c":          None,      # add sensor data when available
            "canopy_temp_mean_c":          None,      # add sensor data when available
            "current_wind_speed":          weather.get("wind", 0),
            "forecast_rain_today":         weather.get("rain", 0),
            "frost_risk":                  frost_risk,
            "ndvi_current":                None,      # add sensor data when available
        }
        result = guardian.evaluate(raw_ai, ctx)

        print("\n" + "─" * 70)
        print(result["output"])
        print("─" * 70)

        decision = result["decision"]
        if decision in ("BLOCKED", "REJECT"):
            print(f"🔴 Guardian: {decision} | {result['explanation']}")
        elif decision == "MODIFIED":
            print(f"🟡 Guardian: {decision} | {result['explanation']}")
        elif decision == "REINFORCED":
            print(f"🟢 Guardian: {decision} | {result['explanation']}")
        else:
            print(f"✅ Guardian: {decision} | {result['explanation']}")
        print()


if __name__ == "__main__":
    main()
