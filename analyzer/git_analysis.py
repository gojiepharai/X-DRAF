# Collect maintainer-health signals from a local git clone.
from datetime import datetime, timezone
import os
import re
import subprocess
from typing import List, Optional


def run(cmd: List[str], cwd: Optional[str] = None) -> str:
    result = subprocess.run(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
    )
    return result.stdout.strip()


def get_repo_stats(repo_path: Optional[str]) -> dict:
    if not repo_path or not os.path.isdir(repo_path):
        return {
            "active_maintainers": None,
            "release_cadence_days": None,
            "days_since_last_release": None,
            "issue_response_days_p50": None,
            "open_issue_backlog": None,
            "security_policy": None,
            "bus_factor_estimate": None,
        }

    # Count contributors with commits in the last 90 days.
    try:
        output = run(
            ["git", "shortlog", "-s", "-n", "--since=90 days"],
            cwd=repo_path,
        )
        active_maintainers = len(
            [line for line in output.splitlines() if line.strip()]
        )
    except Exception:
        active_maintainers = None

    # Helper to read a git timestamp and convert it to UTC datetime.
    def get_ref_date(cmd: List[str]) -> Optional[datetime]:
        try:
            output = run(cmd, cwd=repo_path)
            if not output:
                return None
            return datetime.fromtimestamp(int(output), tz=timezone.utc)
        except Exception:
            return None

    # Pull latest tag date and latest commit date.
    last_tag_date = get_ref_date([
        "git", "log", "--tags",
        "--simplify-by-decoration",
        "--pretty=%ct", "-1"
    ])

    last_commit_date = get_ref_date([
        "git", "log", "-1", "--pretty=%ct"
    ])

    now = datetime.now(timezone.utc)

    days_since_last_release = None
    release_cadence_days = None

    if last_tag_date:
        days_since_last_release = (now - last_tag_date).days

        # Approximate release cadence from the most recent tags.
        try:
            output = run(
                [
                    "git", "for-each-ref",
                    "--sort=-creatordate",
                    "--format=%(creatordate:unix)",
                    "refs/tags",
                ],
                cwd=repo_path,
            )

            timestamps = [
                int(line)
                for line in output.splitlines()[:10]
                if line.strip()
            ]

            if len(timestamps) >= 2:
                gaps = [
                    (timestamps[i] - timestamps[i + 1]) / 86400.0
                    for i in range(len(timestamps) - 1)
                ]
                release_cadence_days = sum(gaps) / len(gaps)

        except Exception:
            release_cadence_days = None

    elif last_commit_date:
        # No tags? Fall back to the last commit date.
        days_since_last_release = (now - last_commit_date).days

    # Simple check for SECURITY.md.
    security_policy = os.path.isfile(
        os.path.join(repo_path, "SECURITY.md")
    )

    # Rough bus factor estimate from commit distribution.
    try:
        output = run(
            ["git", "shortlog", "-s", "-n", "--since=365 days"],
            cwd=repo_path,
        )

        commit_counts = []
        total_commits = 0

        for line in output.splitlines():
            match = re.match(r"\s*(\d+)\s+", line)
            if match:
                count = int(match.group(1))
                commit_counts.append(count)
                total_commits += count

        major_contributors = sum(
            1 for count in commit_counts
            if total_commits and (count / total_commits) >= 0.2
        )

        bus_factor_estimate = (
            max(1, major_contributors) if commit_counts else None
        )

    except Exception:
        bus_factor_estimate = None

    # Shape output to match the scoring contract.
    result = {
        "active_maintainers": active_maintainers,
        "release_cadence_days": release_cadence_days,
        "days_since_last_release": days_since_last_release,
        "issue_response_days_p50": None,
        "open_issue_backlog": None,
        "security_policy": security_policy,
        "bus_factor_estimate": bus_factor_estimate,
    }

    return result
