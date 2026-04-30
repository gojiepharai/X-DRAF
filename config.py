from typing import Any, Dict


DEFAULT_CONFIG: Dict[str, Any] = {
    "final_score": {
        "weights": {
            "vulnerability": 0.4,
            "maintainer_health": 0.25,
            "supply_chain": 0.2,
            "operational": 0.15,
        },
        "scale_max": 10,
    },
    "vulnerability": {
        "weights": {
            "severity": 0.45,
            "exploitability": 0.25,
            "patch_latency": 0.2,
            "age_unpatched": 0.1,
        },
        "severity_map": {
            "NONE": 0,
            "LOW": 0.2,
            "MEDIUM": 0.5,
            "HIGH": 0.8,
            "CRITICAL": 1,
        },
        "use_max_over_avg": True,
        "patch_latency_half_life_days": 14,
        "age_unpatched_half_life_days": 90,
    },
    "maintainer_health": {
        "weights": {
            "release_cadence": 0.25,
            "recent_activity": 0.25,
            "responsiveness": 0.2,
            "maintainer_depth": 0.2,
            "security_policies": 0.1,
        },
        "cadence_target_days": 30,
        "recent_release_max_days": 90,
        "issue_response_good_days": 7,
        "maintainers_good": 3,
        "bus_factor_good": 2,
    },
    "supply_chain": {
        "weights": {
            "signed_commits": 0.2,
            "branch_protection": 0.2,
            "maintainers_2fa": 0.2,
            "artifact_signing": 0.2,
            "reproducible_builds": 0.1,
            "registry_context": 0.1,
        }
    },
    "operational": {
        "weights": {
            "lifecycle": 0.45,
            "currency": 0.35,
            "business_criticality": 0.2,
        },
        "version_age_half_life_days": 180,
        "update_lag_half_life_days": 120,
        "deprecated_penalty": 1,
        "eol_penalty": 1,
    },
}

 