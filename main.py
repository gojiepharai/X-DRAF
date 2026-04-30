"""
Simple CLI tool to check how risky a GitHub repo is
based on NVD vulnerabilities + some optional repo signals.
"""

import argparse
import json
import csv

from config import DEFAULT_CONFIG
from analyzer.git_analysis import get_repo_stats
from analyzer.nvd import find_repo_vulnerabilities
from analyzer.risk import get_risk_tier, format_tier
from analyzer.scoring import calculate_score


def parse_keywords(raw_keywords):
    if not raw_keywords:
        return []

    result = []
    for word in raw_keywords.split(","):
        word = word.strip()
        if word:
            result.append(word)

    return result


def build_supply_data(args):
    return {
        "signed_commits_ratio": args.signed_commits,
        "repo_branch_protection": bool(args.branch_protection),
        "maintainers_2fa": bool(args.maintainers_2fa),
        "artifact_signing": bool(args.artifact_signing),
        "reproducible_builds": bool(args.repro_builds),
        "registry_risk": args.registry_risk if args.registry_risk is not None else 0.3,
    }


def build_operational_data(repo_stats, args):
    return {
        "deprecated": False,
        "eol": False,
        "version_age_days": repo_stats.get("days_since_last_release"),
        "update_lag_days": None,
        "breaking_change_aversion": args.breaking_aversion if args.breaking_aversion is not None else 0.5,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Quickly estimate risk level of a GitHub repo"
    )

    parser.add_argument("--nvd-json", required=True,
                        help="Path to NVD JSON file")
    parser.add_argument("--repo", required=True,
                        help="Repo format: owner/name")
    parser.add_argument("--repo-path", help="Local clone path (optional)")

    parser.add_argument("--criticality", type=float, default=0.5)

    parser.add_argument("--out-json")
    parser.add_argument("--out-csv")

    parser.add_argument("--keywords", default="")
    parser.add_argument("--use-cpe", action="store_true")

    parser.add_argument("--signed-commits", type=float)
    parser.add_argument("--branch-protection", action="store_true")
    parser.add_argument("--maintainers-2fa", action="store_true")
    parser.add_argument("--artifact-signing", action="store_true")
    parser.add_argument("--repro-builds", action="store_true")
    parser.add_argument("--registry-risk", type=float)

    parser.add_argument("--breaking-aversion", type=float)

    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--debug", action="store_true")

    args = parser.parse_args()

    owner, repo_name = args.repo.split("/", 1)
    keywords = parse_keywords(args.keywords)

    # Pull matching CVEs from the local NVD dump.
    vulnerabilities = find_repo_vulnerabilities(
        args.nvd_json,
        owner,
        repo_name,
        keywords=keywords,
        use_cpe=args.use_cpe,
        debug=args.debug,
    )

    # Get repo health signals from the local git clone.
    repo_stats = get_repo_stats(args.repo_path) or {}

    # Package optional inputs for the scoring model.
    supply_data = build_supply_data(args)
    operational_data = build_operational_data(repo_stats, args)

    dependency_info = {
        "name": repo_name,
        "version": None,
        "ecosystem": "github",
        "vulns": vulnerabilities,
        "maintainer": repo_stats,
        "supply_chain": supply_data,
        "operational": operational_data,
        "business": {"criticality": args.criticality},
    }

    # Run the scoring pipeline.
    score_result = calculate_score(dependency_info, DEFAULT_CONFIG)
    final_score = score_result["final"]
    tier = get_risk_tier(final_score)

    # Extra score breakdown prints (handy while tuning weights).
    # print("\n--- scores ---")
    # print("Vulnerability:", score_result["vuln_score"]["pillar"])
    # print("Maintainer:", score_result["maintainer_score"]["pillar"])
    # print("Supply Chain:", score_result["supply_chain_score"]["pillar"])
    # print("Operational:", score_result["operational_score"]["pillar"])
    # print("--------------------\n")

    print(f"\nRepo: {args.repo}")
    print(f"Vulnerabilities found: {len(vulnerabilities)}")

    if vulnerabilities:
        print("Some examples:")
        for v in vulnerabilities[:5]:
            print(
                f"  - {v.get('id')} ({v.get('severity')}, CVSS: {v.get('cvss')})")

    print(f"\nRisk score (0–10): {final_score:.2f}")
    print("Risk tier:", format_tier(tier, disable_color=args.no_color))

    # Write full result payload to JSON if requested.
    if args.out_json:
        with open(args.out_json, "w", encoding="utf-8") as f:
            json.dump(score_result, f, indent=2)
        print(f"[saved] JSON → {args.out_json}")

    # Write a one-row summary CSV if requested.
    if args.out_csv:
        row = {
            "repo": args.repo,
            "score": final_score,
            "tier": tier,
            "vuln_score": round(score_result["vuln_score"]["pillar"], 3),
            "maintainer_score": round(score_result["maintainer_score"]["pillar"], 3),
            "supply_score": round(score_result["supply_chain_score"]["pillar"], 3),
            "operational_score": round(score_result["operational_score"]["pillar"], 3),
            "cve_count": len(vulnerabilities),
        }

        with open(args.out_csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=row.keys())
            writer.writeheader()
            writer.writerow(row)

        print(f"[saved] CSV → {args.out_csv}")


if __name__ == "__main__":
    main()
