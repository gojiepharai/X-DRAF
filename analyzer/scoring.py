
from datetime import datetime, timezone
import statistics
from typing import Any, Dict, List

from analyzer.utils import clamp, days_between, logistic, normalize_ratio


def score_vulnerability(dep: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]: 
    config = cfg["vulnerability"]
    weights = config["weights"]
    severity_map = config["severity_map"] 

    vulns: List[Dict[str, Any]] = dep.get("vulns", []) or [] 
 
    # Base severity signal from NVD labels/CVSS.
    severity_scores = []
    for vuln in vulns:
        severity = (vuln.get("severity") or "").upper() 

        if severity in severity_map:
            severity_scores.append(severity_map[severity])
        else: 
            cvss = vuln.get("cvss")
            if isinstance(cvss, (int, float)):
                severity_scores.append(clamp(cvss / 10.0))

    if severity_scores:
        if config["use_max_over_avg"]:
            severity_component = max(severity_scores)
        else:
            severity_component = statistics.mean(severity_scores) 
    else:
        severity_component = 0.0

    # Exposure signal from KEV/EPSS. 
    epss_values = [
        normalize_ratio(vuln.get("epss")) 
        for vuln in vulns
        if vuln.get("epss") is not None 
    ]

    epss_component = max(epss_values) if epss_values else 0.0
    kev_component = 1.0 if any(vuln.get("kev") for vuln in vulns) else 0.0

    exploitability_component = clamp(
        0.7 * kev_component + 0.3 * epss_component
    )

    # Older unresolved CVEs count more than fresh ones.
    today = datetime.now(timezone.utc).date().isoformat() 
    latencies = []

    for vuln in vulns:
        published = vuln.get("published")

        if not published:
            continue

        if vuln.get("patched"):
            latencies.append(7)
        else:
            days = days_between(published, today) 
            if days is not None:
                latencies.append(days)

    if latencies:
        latency_scores = [ 
            logistic(d, config["patch_latency_half_life_days"]) 
            for d in latencies
        ]
        patch_latency_component = clamp(statistics.mean(latency_scores))
    else:
        patch_latency_component = 0.0

    # Track how stale explicitly unpatched issues are.
    ages = []

    for vuln in vulns:
        if vuln.get("patched") is False:
            published = vuln.get("published")

            if not published:
                continue

            days = days_between(published, today)
            if days is not None: 
                ages.append(days)

    if ages:
        age_scores = [
            logistic(d, config["age_unpatched_half_life_days"])
            for d in ages
        ]
        age_unpatched_component = clamp(statistics.mean(age_scores))
    else:
        age_unpatched_component = 0.0

    pillar = clamp(
        weights["severity"] * severity_component +
        weights["exploitability"] * exploitability_component +
        weights["patch_latency"] * patch_latency_component +
        weights["age_unpatched"] * age_unpatched_component 
    )

    return {
        "severity": severity_component,
        "exploitability": exploitability_component,
        "patch_latency": patch_latency_component, 
        "age_unpatched": age_unpatched_component,
        "pillar": pillar,
    }


def score_maintainer_health(dep: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    config = cfg["maintainer_health"]
    weights = config["weights"]
    metrics = dep.get("maintainer", {}) or {}

    cadence = metrics.get("release_cadence_days")
    cadence_component = (
        logistic(float(cadence), config["cadence_target_days"])
        if cadence is not None
        else 0.5
    )

    days_since = metrics.get("days_since_last_release")
    recent_component = logistic(
        float(days_since or 999),
        config["recent_release_max_days"]
    )

    response_time = metrics.get("issue_response_days_p50")
    responsiveness_component = logistic(
        float(response_time or 999),
        config["issue_response_good_days"]
    )

    active_maintainers = metrics.get("active_maintainers") or 0
    maintainers_good = config["maintainers_good"]

    if active_maintainers:
        maintainer_depth_component = 1.0 - clamp(
            active_maintainers / max(1, maintainers_good)
        )
    else:
        maintainer_depth_component = 0.7

    bus_factor = metrics.get("bus_factor_estimate")
    if bus_factor is not None:
        bus_factor_penalty = 1.0 - clamp(
            bus_factor / max(1, config["bus_factor_good"])
        )
        maintainer_depth_component = clamp(
            0.5 * maintainer_depth_component + 0.5 * bus_factor_penalty
        )

    security_policy_component = 0.0 if metrics.get("security_policy") else 1.0

    pillar = clamp(
        weights["release_cadence"] * cadence_component +
        weights["recent_activity"] * recent_component +
        weights["responsiveness"] * responsiveness_component +
        weights["maintainer_depth"] * maintainer_depth_component +
        weights["security_policies"] * security_policy_component
    )

    return {
        "release_cadence": cadence_component,
        "recent_activity": recent_component,
        "responsiveness": responsiveness_component,
        "maintainer_depth": maintainer_depth_component,
        "security_policies": security_policy_component,
        "pillar": pillar,
    }


def score_supply_chain(dep: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    config = cfg["supply_chain"]
    weights = config["weights"]
    supply_data = dep.get("supply_chain", {}) or {}

    signed_commits_ratio = normalize_ratio(
        supply_data.get("signed_commits_ratio"))
    signed_commits_component = 1.0 - signed_commits_ratio

    branch_protection_component = 0.0 if supply_data.get(
        "repo_branch_protection") else 1.0
    maintainers_2fa_component = 0.0 if supply_data.get(
        "maintainers_2fa") else 1.0
    artifact_signing_component = 0.0 if supply_data.get(
        "artifact_signing") else 1.0
    reproducible_builds_component = 0.0 if supply_data.get(
        "reproducible_builds") else 1.0

    registry_component = normalize_ratio(supply_data.get("registry_risk"))

    pillar = clamp(
        weights["signed_commits"] * signed_commits_component +
        weights["branch_protection"] * branch_protection_component +
        weights["maintainers_2fa"] * maintainers_2fa_component +
        weights["artifact_signing"] * artifact_signing_component +
        weights["reproducible_builds"] * reproducible_builds_component +
        weights["registry_context"] * registry_component
    )

    return {
        "signed_commits": signed_commits_component,
        "branch_protection": branch_protection_component,
        "maintainers_2fa": maintainers_2fa_component,
        "artifact_signing": artifact_signing_component,
        "reproducible_builds": reproducible_builds_component,
        "registry_context": registry_component,
        "pillar": pillar,
    }


def score_operational(dep: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    config = cfg["operational"]
    weights = config["weights"]

    operational_data = dep.get("operational", {}) or {}
    business_data = dep.get("business", {}) or {}

    deprecated_penalty = config["deprecated_penalty"] if operational_data.get(
        "deprecated") else 0.0
    eol_penalty = config["eol_penalty"] if operational_data.get("eol") else 0.0

    version_age_days = float(operational_data.get("version_age_days") or 0)
    version_age_component = logistic(
        version_age_days,
        config["version_age_half_life_days"]
    )

    update_lag_days = float(operational_data.get("update_lag_days") or 0)
    update_lag_component = logistic(
        update_lag_days,
        config["update_lag_half_life_days"]
    )

    lifecycle_component = clamp(
        max(deprecated_penalty, eol_penalty, version_age_component)
    )

    criticality = normalize_ratio(business_data.get("criticality"))
    breaking_aversion = normalize_ratio(
        operational_data.get("breaking_change_aversion")
    )

    currency_component = clamp(
        0.7 * update_lag_component + 0.3 * breaking_aversion
    )

    pillar = clamp(
        weights["lifecycle"] * lifecycle_component +
        weights["currency"] * currency_component +
        weights["business_criticality"] * criticality
    )

    return {
        "lifecycle": lifecycle_component,
        "currency": currency_component,
        "business_criticality": criticality,
        "pillar": pillar,
    }


def calculate_score(dep: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    vuln_score = score_vulnerability(dep, config)
    maintainer_score = score_maintainer_health(dep, config)
    supply_chain_score = score_supply_chain(dep, config)
    operational_score = score_operational(dep, config)

    weights = config["final_score"]["weights"]

    # Blend pillar scores by weight, then scale to the final 0-10 score.
    raw_score = clamp(
        weights["vulnerability"] * vuln_score["pillar"] +
        weights["maintainer_health"] * maintainer_score["pillar"] +
        weights["supply_chain"] * supply_chain_score["pillar"] +
        weights["operational"] * operational_score["pillar"]
    )

    final_score = round(raw_score * config["final_score"]["scale_max"], 3)

    return {
        "vuln_score": vuln_score,
        "maintainer_score": maintainer_score,
        "supply_chain_score": supply_chain_score,
        "operational_score": operational_score,
        "final": final_score,
    }
