# Helpers for mapping score -> tier and colorizing output.
def get_risk_tier(score: float) -> str:
    """Map a score (0–10) to a risk level."""
    score = float(score)

    if 0.0 <= score <= 3.0:
        return "LOW"
    if score <= 6.0:
        return "MEDIUM"
    if score <= 8.0:
        return "HIGH"
    if score <= 10.0:
        return "CRITICAL"

    return "UNKNOWN"


ANSI_COLORS = {
    "LOW": "\033[92m",       # green
    "MEDIUM": "\033[93m",    # yellow
    "HIGH": "\033[91m",      # red
    "CRITICAL": "\033[95m",  # magenta
    "UNKNOWN": "\033[90m",   # dim
}

ANSI_RESET = "\033[0m"


def format_tier(tier: str, disable_color: bool = False) -> str:
    if disable_color:
        return tier

    color = ANSI_COLORS.get(tier, ANSI_COLORS["UNKNOWN"])
    return f"{color}{tier}{ANSI_RESET}"
