def diff_scans(previous: dict | None, current: dict) -> dict:
    """
    Compares the previous scan's structured results to the current one.
    Both are expected to have: subdomains (list), open_ports (dict host->list[int]),
    tls_findings (list of dicts with 'port'/'days_until_expiry'/'flags').

    Returns a dict describing what changed, suitable for both storage and
    building an alert message.
    """
    if previous is None:
        return {"first_scan": True, "new_subdomains": current.get("subdomains", []), "new_open_ports": current.get("open_ports", {})}

    diff = {"first_scan": False, "new_subdomains": [], "removed_subdomains": [],
            "new_open_ports": {}, "closed_ports": {}, "new_socket_flags": [], "new_tls_flags": []}

    prev_subs = set(previous.get("subdomains", []))
    curr_subs = set(current.get("subdomains", []))
    diff["new_subdomains"] = sorted(curr_subs - prev_subs)
    diff["removed_subdomains"] = sorted(prev_subs - curr_subs)

    prev_ports = previous.get("open_ports", {})
    curr_ports = current.get("open_ports", {})
    for host, ports in curr_ports.items():
        old = set(prev_ports.get(host, []))
        new = set(ports)
        opened = sorted(new - old)
        closed = sorted(old - new)
        if opened:
            diff["new_open_ports"][host] = opened
        if closed:
            diff["closed_ports"][host] = closed

    return diff


def build_alert_message(domain: str, diff: dict) -> str | None:
    """Returns a human-readable Slack message, or None if nothing to alert on."""
    if diff.get("first_scan"):
        return None  # don't alert on the baseline scan

    lines = []
    if diff["new_subdomains"]:
        lines.append(f"New subdomains discovered for {domain}: {', '.join(diff['new_subdomains'])}")
    for host, ports in diff.get("new_open_ports", {}).items():
        lines.append(f"New open ports on {host}: {ports}")

    if not lines:
        return None
    return f":rotating_light: AttackSurface Monitor — changes detected for *{domain}*\n" + "\n".join(lines)
