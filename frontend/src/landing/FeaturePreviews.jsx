// Small, static illustrations for the feature sections. Everything shown uses
// reserved ".example" hostnames and sample values, and each is labelled as an
// illustration. Flag names, statuses and severity levels mirror what the
// ShowDown worker and dashboard actually produce.
import { Check, LoaderCircle, TriangleAlert, Clock } from "lucide-react";

function Figure({ label, children }) {
  return (
    <div className="lp-figure" role="img" aria-label={`${label} (illustrative sample data)`}>
      <div className="lp-card">{children}</div>
      <span className="lp-caption">Illustrative sample data.</span>
    </div>
  );
}

const Port = ({ n }) => <span className="lp-port">{n}</span>;
const Badge = ({ tone, severity, children }) => (
  <span className={`lp-badge lp-badge--${tone}${severity ? " lp-cap" : ""}`}>{children}</span>
);

export function AssetsPreview() {
  const rows = [
    ["acme.example", [80, 443], "http"],
    ["api.acme.example", [443, 8080], "http"],
    ["mail.acme.example", [25, 143, 993], "imap"],
    ["dev.acme.example", [22, 80], "ssh"],
  ];
  return (
    <Figure label="Example list of discovered hosts with their open ports and services">
      <div className="lp-card-head">
        <span>Host</span>
        <span>Open ports</span>
        <span className="lp-hide-xs">Service</span>
      </div>
      {rows.map(([host, ports, service]) => (
        <div className="lp-row lp-row--assets" key={host}>
          <span className="lp-mono lp-ellipsis">{host}</span>
          <span className="lp-ports">{ports.map((p) => <Port key={p} n={p} />)}</span>
          <span className="lp-mono lp-muted lp-hide-xs">{service}</span>
        </div>
      ))}
    </Figure>
  );
}

export function ScanPreview() {
  return (
    <Figure label="Example of a service banner and the observations raised for it">
      <div className="lp-svc">
        <div className="lp-svc-head">
          <Port n={22} />
          <span className="lp-mono">ssh</span>
          <span className="lp-muted">fingerprinted from banner</span>
        </div>
        <pre className="lp-pre">SSH-2.0-OpenSSH_9.6</pre>
        <div className="lp-flags">
          <Badge tone="low">possible version disclosure</Badge>
        </div>
      </div>
      <div className="lp-svc">
        <div className="lp-svc-head">
          <Port n={8443} />
          <span className="lp-mono">http</span>
          <span className="lp-muted">expected to use TLS</span>
        </div>
        <pre className="lp-pre">HTTP/1.1 400 Bad Request</pre>
        <div className="lp-flags">
          <Badge tone="high">plaintext response on expected tls port</Badge>
        </div>
      </div>
      <div className="lp-svc lp-svc--last">
        <div className="lp-svc-head">
          <Port n={443} />
          <span className="lp-mono">tls</span>
          <span className="lp-muted">certificate and protocol checked</span>
        </div>
        <div className="lp-flags">
          <Badge tone="medium">certificate expiring soon</Badge>
        </div>
      </div>
    </Figure>
  );
}

export function FindingsPreview() {
  const rows = [
    ["high", "Plaintext response on expected TLS port", "admin.acme.example:8443", "Socket"],
    ["medium", "Certificate expiring soon", "acme.example:443", "TLS"],
    ["low", "Possible version disclosure", "dev.acme.example:22", "Socket"],
  ];
  return (
    <Figure label="Example findings list with high, medium and low severity badges">
      {rows.map(([tone, title, where, source]) => (
        <div className="lp-row lp-row--finding" key={title}>
          <Badge tone={tone} severity>{tone}</Badge>
          <div className="lp-finding-text">
            <span>{title}</span>
            <span className="lp-mono lp-muted lp-ellipsis">{where}</span>
          </div>
          <span className="lp-source">{source}</span>
        </div>
      ))}
    </Figure>
  );
}

export function HistoryPreview() {
  const rows = [
    ["running", "Running", LoaderCircle, "acme.example"],
    ["completed", "Completed", Check, "acme.example"],
    ["failed", "Failed", TriangleAlert, "sandbox.example"],
    ["queued", "Queued", Clock, "acme.example"],
  ];
  return (
    <Figure label="Example scan history showing running, completed, failed and queued scans, and the changes between two scans">
      {rows.map(([tone, label, Icon, domain]) => (
        <div className="lp-row lp-row--history" key={`${tone}-${domain}`}>
          <span className={`lp-status lp-status--${tone}`}>
            <Icon size={14} aria-hidden="true" />
            {label}
          </span>
          <span className="lp-mono lp-ellipsis">{domain}</span>
        </div>
      ))}
      <div className="lp-diff">
        <span className="lp-diff-title">Changes since previous scan</span>
        <span className="lp-diff-item lp-diff-item--add">New subdomain found</span>
        <span className="lp-diff-item lp-diff-item--add">Port opened</span>
        <span className="lp-diff-item lp-diff-item--remove">Port closed</span>
      </div>
    </Figure>
  );
}
