import { useEffect, useRef } from "react";
import {
  X,
  ArrowUpRight,
  Box,
  Network,
  TriangleAlert,
  History,
} from "lucide-react";
import { severityOrder, dateLabel, utcDate } from "./data";
export function Badge({ children, tone = "" }) {
  return <span className={`badge ${tone}`}>{children}</span>;
}
export function Panel({ title, subtitle, action, children, className = "" }) {
  return (
    <section className={`panel ${className}`}>
      <header className="panel-head">
        <div>
          <h2>{title}</h2>
          {subtitle && <p>{subtitle}</p>}
        </div>
        {action}
      </header>
      {children}
    </section>
  );
}
export function Modal({ title, onClose, children }) {
  const ref = useRef();
  const returnFocus = useRef(document.activeElement);
  useEffect(() => {
    const previous = returnFocus.current;
    const dialog = ref.current;
    dialog.showModal();
    return () => {
      dialog.close();
      // Restore focus after React removes the modal; focusing during removal can
      // be overridden by the browser's native dialog cleanup.
      queueMicrotask(() => { if(!dialog.open && previous?.isConnected) previous.focus(); });
    };
  }, []);
  return (
    <dialog
      aria-label={title}
      ref={ref}
      onCancel={onClose}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="dialog-head">
        <h2>{title}</h2>
        <button
          className="icon-button"
          aria-label="Close dialog"
          onClick={onClose}
        >
          <X size={20} />
        </button>
      </div>
      {children}
    </dialog>
  );
}
export function Metrics({ assets, ports, findings, scans }) {
  return (
    <div className="metrics">
      {[
        [Box, "Assets discovered", assets, "Latest completed snapshots"],
        [Network, "Open ports", ports, "Across discovered assets"],
        [
          TriangleAlert,
          "Security findings",
          findings,
          "Socket & TLS observations",
        ],
        [History, "Scans completed", scans, "Across selected scope"],
      ].map(([Icon, label, value, caption]) => (
        <div className="metric" key={label}>
          <span className="metric-icon">
            <Icon size={21} />
          </span>
          <div>
            <p>{label}</p>
            <strong>{value}</strong>
            <small>{caption}</small>
          </div>
        </div>
      ))}
    </div>
  );
}
export function Activity({ scans }) {
  const sorted = [...scans]
    .filter((s) => s.status === "completed" && Number.isFinite(utcDate(s.created_at).getTime()))
    .sort((a, b) => utcDate(a.created_at) - utcDate(b.created_at))
    .slice(-24);
  const values = sorted.map((s) =>
    Array.isArray(s.subdomains)
      ? s.subdomains.length
      : Object.keys(s.subdomains || {}).length,
  );
  const max = Math.max(4, ...values);
  const pts = values.map(
    (v, i) =>
      `${45 + (i * 640) / Math.max(1, values.length - 1)},${170 - (v / max) * 135}`,
  );
  return (
    <Panel
      title="Scan activity"
      subtitle="Assets discovered over time."
      action={<Badge>Last 24 completed scans</Badge>}
    >
      {!values.length ? (
        <div className="empty chart-empty">
          Completed scans will appear here.
        </div>
      ) : (
        <>
          <svg
            className="activity"
            viewBox="0 0 720 210"
            role="img"
            aria-label={`Asset counts across ${values.length} completed scans: ${values.join(", ")}`}
          >
            <defs>
              <linearGradient id="area" x1="0" y1="0" x2="0" y2="1">
                <stop stopColor="#75e5bf" stopOpacity=".25" />
                <stop offset="1" stopColor="#75e5bf" stopOpacity="0" />
              </linearGradient>
            </defs>
            {[0, 1, 2, 3].map((i) => (
              <g key={i}>
                <line
                  x1="45"
                  x2="690"
                  y1={35 + i * 45}
                  y2={35 + i * 45}
                  stroke="#243133"
                />
                <text x="10" y={39 + i * 45}>
                  {Math.round(max * (1 - i / 3))}
                </text>
              </g>
            ))}
            <polygon
              points={`45,170 ${pts.join(" ")} ${45 + ((values.length - 1) * 640) / Math.max(1, values.length - 1)},170`}
              fill="url(#area)"
            />
            <polyline
              points={pts.join(" ")}
              fill="none"
              stroke="#86efca"
              strokeWidth="2"
            />
            {pts.map((p, i) => (
              <circle
                key={i}
                cx={p.split(",")[0]}
                cy={p.split(",")[1]}
                r="3"
                fill="#a4f7d8"
              >
                <title>
                  {dateLabel(sorted[i].created_at)}: {values[i]} assets
                </title>
              </circle>
            ))}
            <text x="45" y="200">
              {dateLabel(sorted[0].created_at)}
            </text>
            <text x="685" y="200" textAnchor="end">
              {dateLabel(sorted.at(-1).created_at)}
            </text>
          </svg>
        </>
      )}
    </Panel>
  );
}
export function Risk({ findings }) {
  let at = 0;
  const colors = ["#ff4f9a", "#f9ac68", "#ecd371", "#80e4be"];
  const counts = severityOrder.map(
    (s) => findings.filter((f) => f.severity === s).length,
  );
  const gradient = counts
    .map((n, i) => {
      const from = at;
      at += (n / Math.max(1, findings.length)) * 100;
      return `${colors[i]} ${from}% ${at}%`;
    })
    .join(",");
  return (
    <Panel
      title="Risk distribution"
      subtitle="Frontend severity mapping · observed flags"
    >
      <div className="risk-body">
        <div
          className="donut"
          style={{
            background: findings.length
              ? `conic-gradient(${gradient})`
              : "#253234",
          }}
        >
          <div>
            <strong>{findings.length}</strong>
            <small>findings</small>
          </div>
        </div>
        <div className="legend">
          {severityOrder.map((s, i) => (
            <div key={s}>
              <i style={{ background: colors[i] }} />
              <span>{s}</span>
              <b>{counts[i]}</b>
              <small>
                {Math.round((counts[i] / Math.max(1, findings.length)) * 100)}%
              </small>
            </div>
          ))}
        </div>
      </div>
    </Panel>
  );
}
export function Assets({ assets, onSelect, limit }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Hostname</th>
            <th>Ports</th>
            <th>Services</th>
            <th>Findings</th>
            <th>
              <span className="sr-only">Details</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {assets.slice(0, limit || assets.length).map((a) => (
            <tr key={`${a.id}:${a.scan}`} className={a.isNew ? "asset-new" : undefined}>
              <td>
                <button
                  className="text-button mono"
                  onClick={() => onSelect(a)}
                >
                  {a.host}
                </button>
                {a.isNew && <span className="new-asset-label">New</span>}
              </td>
              <td>
                <div className="port-list">
                  {a.ports.map((p) => (
                    <code key={p}>{p}</code>
                  ))}
                </div>
              </td>
              <td>{a.services.join(", ") || "Not identified"}</td>
              <td>
                <Badge tone={a.findings.length ? "medium" : "neutral"}>
                  {a.findings.length}
                </Badge>
              </td>
              <td>
                <button
                  className="icon-button"
                  aria-label={`Inspect ${a.host}`}
                  onClick={() => onSelect(a)}
                >
                  <ArrowUpRight size={15} />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {!assets.length && (
        <div className="empty">No assets match this view.</div>
      )}
    </div>
  );
}
export function Findings({ findings, onSelect, limit }) {
  return (
    <div className="finding-list">
      {findings.slice(0, limit || findings.length).map((f) => (
        <button key={f.id} className="finding" onClick={() => onSelect(f)}>
          <span className={`severity-dot ${f.severity}`} />
          <span>
            <strong>{f.title}</strong>
            <small>
              {f.host} : {f.port}
            </small>
          </span>
          <Badge tone={f.severity}>{f.severity}</Badge>
        </button>
      ))}
      {!findings.length && (
        <div className="empty">No findings match this view.</div>
      )}
    </div>
  );
}
export function HistoryTable({ scans, domains, onSelect, limit }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Started at</th>
            <th>Scope</th>
            <th>Scan ID</th>
            <th>Status</th>
            <th>Completed at</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {[...scans]
            .sort((a, b) => utcDate(b.created_at) - utcDate(a.created_at))
            .slice(0, limit || scans.length)
            .map((s) => (
              <tr key={s.id}>
                <td>{dateLabel(s.created_at)}</td>
                <td className="mono">
                  {domains.find((d) => d.id === s.domain_id)?.name ||
                    s.domain_id}
                </td>
                <td className="muted mono">{s.id.slice(0, 12)}</td>
                <td>
                  <Badge
                    tone={
                      s.status === "completed"
                        ? "low"
                        : s.status === "failed"
                          ? "critical"
                          : "medium"
                    }
                  >
                    {s.status}
                  </Badge>
                </td>
                <td>{dateLabel(s.completed_at)}</td>
                <td>
                  <button
                    className="icon-button"
                    aria-label={`Inspect scan ${s.id}`}
                    onClick={() => onSelect(s)}
                  >
                    <ArrowUpRight size={16} />
                  </button>
                </td>
              </tr>
            ))}
        </tbody>
      </table>
      {!scans.length && (
        <div className="empty">
          No scans yet. Verify a domain to start your first scan.
        </div>
      )}
    </div>
  );
}
