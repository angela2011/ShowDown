"""Explainable decoy confidence, independent of scan exposure scoring."""
import ipaddress


def confidence(details, recent_count):
    reasons = [{'rule': 'decoy_contact', 'points': 10,
                'explanation': 'Contact with an owned decoy; alone this is weak evidence.'}]
    weights = {'credential_probe': 30, 'path_traversal': 40, 'shell_pattern': 40}
    for signal in sorted(set(details.get('signals', []))):
        if signal in weights:
            reasons.append({'rule': signal, 'points': weights[signal],
                            'explanation': 'A bounded protocol sample matched this pattern; no payload was executed.'})
    if recent_count >= 10:
        reasons.append({'rule': 'repeated_contact', 'points': 20,
                        'explanation': 'At least 10 contacts from this source to this sensor within 10 minutes.'})
    score = min(100, sum(r['points'] for r in reasons))
    severity = 'critical' if score >= 90 else 'high' if score >= 70 else 'medium' if score >= 40 else 'low'
    return score, severity, reasons


def protected_ip(value, protected_cidrs):
    address = ipaddress.ip_address(value)
    if not address.is_global or address.is_multicast or address.is_unspecified or getattr(address, 'ipv4_mapped', None):
        return True
    return any(address in ipaddress.ip_network(cidr) for cidr in protected_cidrs)
