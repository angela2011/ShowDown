from worker.tasks.risk_engine import inventory, score_snapshot


def changes(before, after):
    return {
        'new': [after[k] for k in sorted(after.keys() - before.keys())],
        'changed': [{'before':before[k], 'after':after[k]} for k in sorted(before.keys() & after.keys()) if before[k] != after[k]],
        'no_longer_detected': [before[k] for k in sorted(before.keys() - after.keys())],
    }


def diff_scans(previous: dict | None, current: dict) -> dict:
    before, after = inventory(previous), inventory(current)
    first = previous is None
    groups = {kind:changes(before[kind],after[kind]) for kind in after}
    new_ports, closed_ports = {}, {}
    for label, output in [('new',new_ports),('no_longer_detected',closed_ports)]:
        for row in groups['ports'][label]:
            output.setdefault(row['host'],[]).append(row['port'])
        for ports in output.values():
            ports.sort()
    risk = score_snapshot(current, None if first else new_ports)
    previous_risk = ((previous or {}).get('diff') or {}).get('risk')
    if not isinstance(previous_risk,dict):
        previous_risk = score_snapshot(previous or {})
    groups['findings'] = changes({f['id']:f for f in previous_risk.get('findings',[])}, {f['id']:f for f in risk['findings']})
    def flags(snapshot, field):
        from worker.tasks.risk_engine import rows
        return {(host,row['port'],flag) for host,row in rows(snapshot or {},field) for flag in row.get('flags') or []}
    notes = ['No longer detected does not establish removal or remediation. Closed ports are legacy aliases for ports no longer observed.']
    if current.get('warnings') or ((previous or {}).get('diff') or {}).get('warnings'):
        notes.append('Discovery warnings exist; comparisons may reflect incomplete coverage.')
    if previous and not ((previous.get('diff') or {}).get('risk')):
        notes.append('Previous findings reconstructed from legacy observations; historical new-port context is unavailable.')
    return {'first_scan':first,'baseline_scan_id':(previous or {}).get('scan_id'),
            'new_subdomains':[a['host'] for a in groups['assets']['new']],
            'removed_subdomains':[a['host'] for a in groups['assets']['no_longer_detected']],
            'new_open_ports':new_ports,'closed_ports':closed_ports,
            'new_socket_flags':[dict(host=h,port=p,flag=f) for h,p,f in sorted(flags(current,'socket_findings')-flags(previous,'socket_findings'))],
            'new_tls_flags':[dict(host=h,port=p,flag=f) for h,p,f in sorted(flags(current,'tls_findings')-flags(previous,'tls_findings'))],
            'changes':groups,'risk':risk,'comparison_notes':notes}


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
