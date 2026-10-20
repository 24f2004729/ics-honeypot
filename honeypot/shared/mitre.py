# =============================================================================
#  ics_honeypot / shared / mitre.py
#  ---------------------------------------------------------------------------
#  MITRE ATT&CK® for Industrial Control Systems (ICS) Framework Mapping
#  ---------------------------------------------------------------------------
#  Provides standard taxonomy tags, tactics, and technique IDs for all
#  detected attacker behaviors across Modbus, DNP3, and MQTT.
#
#  Reference: https://attack.mitre.org/matrices/ics/
# =============================================================================

from typing import Dict, Any, Optional

# Standard MITRE ATT&CK for ICS Techniques
MITRE_ICS_TECHNIQUES = {
    # Impair Process Control / Impact
    "T0855": {
        "name": "Unauthorized Command Message",
        "tactic": "Impair Process Control",
        "description": "Adversary injects command messages to change actuator state or process setpoints."
    },
    "T0836": {
        "name": "Modify Parameter",
        "tactic": "Impair Process Control",
        "description": "Adversary modifies operational parameters or setpoints."
    },
    # Collection & Discovery
    "T0801": {
        "name": "Monitor Process State",
        "tactic": "Collection",
        "description": "Adversary polls telemetry, digital inputs, or analog sensor values."
    },
    "T0888": {
        "name": "Point & Tag Identification",
        "tactic": "Discovery",
        "description": "Adversary probes or enumerates register ranges and data points to understand site layout."
    },
    "T0846": {
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "description": "Adversary interrogates device identification attributes (MEI, vendor strings, firmware)."
    },
    "T0802": {
        "name": "Automated Collection",
        "tactic": "Collection",
        "description": "High-volume automated scanning collecting telemetry across tags."
    },
    # Initial Access & Credentials
    "T0812": {
        "name": "Default Credentials",
        "tactic": "Initial Access",
        "description": "Adversary attempts authentication using factory default or common credentials."
    },
    # Inhibit Response Function / Evasion
    "T0814": {
        "name": "Denial of Service",
        "tactic": "Inhibit Response Function",
        "description": "Adversary floods or sends malformed frames to disable or crash the controller."
    }
}


def classify_mitre_attack(action: str, details: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """
    Classify an event action into its corresponding MITRE ATT&CK for ICS technique.
    Returns technique ID, technique name, and tactic name.
    """
    action_lower = action.lower()
    details = details or {}

    # 1. Unauthorized Command Message (Modbus Write, DNP3 Operate)
    if any(k in action_lower for k in ("operate", "write_multiple", "write_single_coil", "write_single_register")):
        tech = MITRE_ICS_TECHNIQUES["T0855"]
        return {
            "mitre_id": "T0855",
            "mitre_name": tech["name"],
            "mitre_tactic": tech["tactic"]
        }

    # 2. Default Credentials (MQTT Connect with username/password)
    if "connect" in action_lower and (details.get("username") or details.get("password")):
        tech = MITRE_ICS_TECHNIQUES["T0812"]
        return {
            "mitre_id": "T0812",
            "mitre_name": tech["name"],
            "mitre_tactic": tech["tactic"]
        }

    # 3. Device Identification / Discovery (MEI, Diagnostics)
    if any(k in action_lower for k in ("mei", "device_identification", "diagnostics")):
        tech = MITRE_ICS_TECHNIQUES["T0846"]
        return {
            "mitre_id": "T0846",
            "mitre_name": tech["name"],
            "mitre_tactic": tech["tactic"]
        }

    # 4. Point & Tag Identification (Register scanning)
    quantity = details.get("quantity", 1)
    if (isinstance(quantity, int) and quantity > 16) or "scan" in action_lower:
        tech = MITRE_ICS_TECHNIQUES["T0888"]
        return {
            "mitre_id": "T0888",
            "mitre_name": tech["name"],
            "mitre_tactic": tech["tactic"]
        }

    # 5. Monitor Process State (Standard Reads / Polls)
    if any(k in action_lower for k in ("read", "poll", "subscribe")):
        tech = MITRE_ICS_TECHNIQUES["T0801"]
        return {
            "mitre_id": "T0801",
            "mitre_name": tech["name"],
            "mitre_tactic": tech["tactic"]
        }

    # Fallback Discovery
    tech = MITRE_ICS_TECHNIQUES["T0846"]
    return {
        "mitre_id": "T0846",
        "mitre_name": tech["name"],
        "mitre_tactic": tech["tactic"]
    }
