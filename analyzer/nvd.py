# Helpers for matching NVD CVEs to a GitHub repo.

import json
import re
from typing import Iterable, List, Optional, Tuple

# Parse vendor/product fields from CPE strings.
_cpe_pattern = re.compile(r"^cpe:2\.3:[aho]:([^:]*):([^:]*):")
_commit_url_pattern = re.compile(
    r"https?://github\.com/([^/]+)/([^/]+)/commit/([0-9a-fA-F]{7,40})")
_pr_url_pattern = re.compile(
    r"https?://github\.com/([^/]+)/([^/]+)/pull/(\d+)")


def pick_best_cvss(metrics: dict) -> Tuple[Optional[float], Optional[str]]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(key)

        if not metric_list:
            continue

        metric = metric_list[0]
        cvss_data = metric.get("cvssData") or {}

        score = cvss_data.get("baseScore") or metric.get("baseScore")
        severity = metric.get("baseSeverity")

        try:
            score = float(score) if score is not None else None
        except Exception:
            score = None

        return score, severity

    return None, None


def cpe_tokens(cve: dict) -> Iterable[Tuple[str, str]]:
    for config in cve.get("configurations", []) or []:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []) or []:
                criteria = cpe_match.get(
                    "criteria") or cpe_match.get("cpe23Uri")

                if not criteria:
                    continue

                match_obj = _cpe_pattern.match(criteria)

                if not match_obj:
                    continue

                vendor = (match_obj.group(1) or "").lower()
                product = (match_obj.group(2) or "").lower()

                yield vendor, product


def cve_matches_repo(
    cve: dict,
    owner: str,
    name: str,
    *,
    owner_url: str,
    repo_url: str,
    tokens: List[str],
    extra_tokens: List[str],
    use_cpe: bool,
    debug: bool
) -> bool:
    # Merge name-derived and user-provided tokens.
    all_tokens = {t for t in tokens + extra_tokens if t}

    # 1) Fast path: match the exact repo URL or anything under the owner URL.
    for ref in cve.get("references", []) or []:
        url = (ref.get("url") or "").lower()

        if repo_url in url or owner_url in url:
            return True

        # Also allow token hits in URLs (helps with renames/aliases).
        if any(token in url for token in all_tokens):
            return True

    # 2) Check English descriptions for token mentions.
    for description in cve.get("descriptions", []) or []:
        if (description.get("lang") or "").lower() != "en":
            continue

        text = (description.get("value") or "").lower()

        if all_tokens and any(token in text for token in all_tokens):
            return True

    # 3) Optionally match via CPE vendor/product tokens.
    if use_cpe:
        for vendor, product in cpe_tokens(cve):
            if vendor in all_tokens or product in all_tokens:
                return True

    # Optional debug breadcrumbs for misses.
    if debug:
        cve_id = cve.get("id")
        references = cve.get("references", []) or []
        # if references:
        #     print(
        #         f"[DEBUG] no match: {cve_id} ref0={references[0].get('url')}")
        # else:
        #     print(f"[DEBUG] no match: {cve_id} (no refs)")

    return False


# Pull CVEs that look relevant to this repo.
def find_repo_vulnerabilities(
    nvd_json_path: str,
    owner: str,
    name: str,
    *,
    keywords: List[str],
    use_cpe: bool,
    debug: bool
) -> List[dict]:

    repo_url = f"https://github.com/{owner}/{name}".lower()
    owner_url = f"https://github.com/{owner}/".lower()

    # Normalize repo name into search tokens.
    clean_name = re.sub(r"[_\-]+", " ", name).lower()
    parts = clean_name.split()

    tokens = []
    for part in parts:
        if part:
            tokens.append(part)

    # Normalize extra keyword filters.
    extra_tokens = []
    for t in keywords:
        if t and t.strip():
            cleaned = t.strip().lower()
            extra_tokens.append(cleaned)

    with open(nvd_json_path, "r", encoding="utf-8") as file:
        data = json.load(file)

    vulnerability_items = data.get("vulnerabilities", [])

    vulns: List[dict] = []
    match_count = 0

    for item in vulnerability_items:
        cve = item.get("cve", {})

        if not cve:
            continue

        matches = cve_matches_repo(
            cve,
            owner,
            name,
            owner_url=owner_url,
            repo_url=repo_url,
            tokens=tokens,
            extra_tokens=extra_tokens,
            use_cpe=use_cpe,
            debug=debug,
        )

        if not matches:
            continue

        match_count += 1

        score, severity = pick_best_cvss(cve.get("metrics", {}))
        published = cve.get("published")

        # Heuristic: treat Patch-tagged refs or repo PR links as patched.
        patched = False
        for ref in cve.get("references", []) or []:
            url = (ref.get("url") or "").lower()
            tags = ref.get("tags") or []

            if any((tag or "").lower() == "patch" for tag in tags):
                patched = True

            if (
                _pr_url_pattern.match(url)
                and owner.lower() in url
                and name.lower() in url
            ):
                patched = True

        vulns.append({
            "id": cve.get("id"),
            "cvss": score,
            "severity": (severity or "").upper() if severity else None,
            "published": published,
            "patched": patched,
            "epss": None,
            "kev": False,
        })

    if debug:
        print(f"[DEBUG] Matched {match_count} CVEs for {owner}/{name}")

    return vulns