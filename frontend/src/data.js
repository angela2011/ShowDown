export const severityOrder = ["critical", "high", "medium", "low"];
export function utcDate(value) {
  if (typeof value !== 'string' || !value.trim()) return new Date(NaN);
  const text=value.trim();
  const match=/^(\d{4})-(\d{2})-(\d{2})(?:T| )/.exec(text);
  if(!match)return new Date(NaN);
  const [,y,m,d]=match.map(Number);
  if(m<1||m>12||d<1||d>new Date(Date.UTC(y,m,0)).getUTCDate())return new Date(NaN);
  return new Date(/(?:Z|[+-]\d{2}:?\d{2})$/i.test(text)?text:text+'Z');
}
export function dateLabel(value) {
 const date=utcDate(value);
 return Number.isFinite(date.getTime())?date.toLocaleString(undefined,{year:'numeric',month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',timeZoneName:'short'}):'—';
}
export function derive(domains, scans) {
  const assets = [],
    findings = [];
  const latest = new Map();
  for (const s of [...scans].sort(
    (a, b) => utcDate(b.created_at) - utcDate(a.created_at),
  ))
    if (s.status === "completed" && !latest.has(s.domain_id))
      latest.set(s.domain_id, s);
  for (const [id, s] of latest) {
    const domain = domains.find((d) => d.id === id)?.name || id;
    const hosts = new Set([
      ...(Array.isArray(s.subdomains)
        ? s.subdomains
        : Object.keys(s.subdomains || {})),
      ...Object.keys(s.open_ports || {}),
    ]);
    const add = (host, port, flag, source) => {
      let severity = "low";
      if (
        flag === "plaintext_response_on_expected_tls_port" ||
        flag === "weak_tls_protocol"
      )
        severity = "high";
      else if (flag === "certificate_expiring_soon") severity = "medium";
      findings.push({
        id: `${id}:${host}:${port}:${source}:${flag}`,
        host,
        port,
        flag,
        title: flag.replaceAll("_", " "),
        severity,
        source,
        scan: s.id,
      });
    };
    for (const [host, rows] of Object.entries(s.socket_findings || {}))
      for (const row of Array.isArray(rows) ? rows : [])
        for (const flag of row.flags || []) add(host, row.port, flag, "Socket");
    const tls = Array.isArray(s.tls_findings)
      ? { [domain]: s.tls_findings }
      : s.tls_findings || {};
    for (const [host, rows] of Object.entries(tls))
      for (const row of Array.isArray(rows) ? rows : [])
        for (const flag of row.flags || []) add(host, row.port, flag, "TLS");
    for (const host of hosts) {
      const rows = Array.isArray(s.socket_findings?.[host]) ? s.socket_findings[host] : [];
      assets.push({
        id: `${id}:${host}`,
        host,
        domain,
        ports: Array.isArray(s.open_ports?.[host]) ? s.open_ports[host] : [],
        isNew: !s.diff?.first_scan && (s.diff?.new_subdomains || []).includes(host),
        services: [
          ...new Set(
            rows.map((r) => r.fingerprint).filter((f) => f && f !== "unknown"),
          ),
        ],
        findings: findings.filter((f) => f.host === host && f.scan === s.id),
        scan: s.id,
      });
    }
  }
  findings.sort(
    (a, b) =>
      severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity),
  );
  return {
    assets,
    findings,
    ports: assets.reduce((n, a) => n + a.ports.length, 0),
  };
}
export function demoData() {
  const domains = [
    {
      id: "demo-1",
      name: "acme.example",
      verified: true,
      verification_token: "asm-verify=demo-only",
    },
    {
      id: "demo-2",
      name: "sandbox.example",
      verified: false,
      verification_token: "asm-verify=demo-only",
    },
  ];
  const hosts = [
    "acme.example",
    "api.acme.example",
    "app.acme.example",
    "mail.acme.example",
    "dev.acme.example",
    "vpn.acme.example",
    "cdn.acme.example",
    "status.acme.example",
    "docs.acme.example",
    "auth.acme.example",
    "stage.acme.example",
    "db.acme.example",
  ];
  const scans = Array.from({ length: 24 }, (_, i) => ({
    id: `demo-scan-${i}`,
    domain_id: "demo-1",
    status: "completed",
    created_at: new Date(Date.now() - 60000 - i * 7200000).toISOString(),
    completed_at: new Date(Date.now() - 60000 - i * 7200000 + 30000).toISOString(),
    subdomains: hosts.slice(0, Math.max(3, 12 - Math.floor(i / 4))),
    open_ports: Object.fromEntries(
      hosts.slice(0, Math.max(3, 12 - Math.floor(i / 4))).map((h, j) => [h, j < 4 ? [22, 80, 443] : [80, 443]]),
    ),
    socket_findings: Object.fromEntries(
      hosts.slice(0, Math.max(3, 12 - Math.floor(i / 4))).map((h, j) => [
        h,
        [
          {
            port: j < 2 ? 443 : 80,
            fingerprint: j === 3 ? "ftp_or_smtp" : "http",
            flags:
              j < 2
                ? ["plaintext_response_on_expected_tls_port"]
                : j < 7
                  ? ["possible_version_disclosure"]
                  : [],
          },
        ],
      ]),
    ),
    tls_findings: [
      { port: 443, flags: ["certificate_expiring_soon"], days_until_expiry: 9 },
    ],
    diff: { new_subdomains: ["api.acme.example"], removed_subdomains: [] },
  }));
  return { domains, scans };
}
