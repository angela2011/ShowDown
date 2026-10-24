import { useState } from "react";
import { Radio, Play, RefreshCw } from "lucide-react";
import { Panel } from "./components";
import { severityOrder, dateLabel, utcDate } from "./data";

const levels = [...severityOrder, "clean"];
function assetSeverity(asset) {
  return severityOrder.find(level => asset.findings.some(f => f.severity === level)) || "clean";
}
// Host-derived angles keep points stationary across refreshes. Distance encodes
// observed severity only; it does not represent network or geographic distance.
function position(asset, severity) {
  let hash = 0;
  for (const char of asset.id) hash = (hash * 31 + char.charCodeAt(0)) >>> 0;
  const angle = (hash % 360) * Math.PI / 180;
  const radius = {critical: 13, high: 23, medium: 32, low: 40, clean: 45}[severity] + ((hash >>> 8) % 5 - 2);
  return {left: `${50 + Math.cos(angle) * radius}%`, top: `${50 + Math.sin(angle) * radius}%`};
}
export function SurfaceRadar({assets, onSelect, demo}) {
  const [paused, setPaused] = useState(false);
  const counts = Object.fromEntries(levels.map(level => [level, assets.filter(a => assetSeverity(a) === level).length]));
  return <Panel className="surface-radar" title="Surface radar" subtitle={`${assets.length} discovered hosts · ${demo ? "sample snapshot" : "latest completed snapshots"}`} action={<button className="text-button" onClick={() => setPaused(p => !p)} aria-pressed={paused}>{paused ? "Resume sweep" : "Pause sweep"}</button>}>
    <div className="radar-layout">
      <div className={`radar-stage ${paused ? "paused" : ""}`} role="group" aria-label="Asset radar. Select a host to inspect its findings.">
        <div className="radar-grid" aria-hidden="true"><span/><span/><span/><span/><i className="radar-cross horizontal"/><i className="radar-cross vertical"/><div className="radar-sweep"/><div className="radar-core"/></div>
        {assets.map(asset => {const level = assetSeverity(asset);return <button key={`${asset.id}:${asset.scan}`} className={`radar-host ${level} ${asset.isNew ? "asset-new" : ""}`} style={position(asset,level)} aria-label={`Inspect radar host ${asset.host}, ${level === "clean" ? "no observed flags" : level + " severity"}`} title={`${asset.host} · ${level === "clean" ? "No observed flags" : level}`} onClick={() => onSelect(asset)}><span/></button>})}
        {!assets.length && <div className="radar-empty">No discovered hosts<br/><small>Completed scans populate the radar.</small></div>}
      </div>
      <div className="radar-key"><h3>Your perimeter, in focus.</h3><p>Select a host to inspect it. Hosts closer to the center have higher-severity observations.</p><div className="radar-legend">{levels.map(level => <div key={level}><i className={`severity-dot ${level}`}/><span>{level === "clean" ? "No flags" : level}</span><strong>{counts[level]}</strong></div>)}</div><small>The sweep is a visual animation, not scan progress.</small></div>
    </div>
  </Panel>;
}
export function ScanControls({scans, demo, connected, busy, error, cooldown=0, onScan, onRefresh}) {
  const running = scans.filter(s => s.status === "running").length;
  const queued = scans.filter(s => s.status === "queued").length;
  const latest = [...scans].sort((a,b) => utcDate(b.created_at) - utcDate(a.created_at))[0];
  const active = !demo && connected && !error && running > 0;
  const status = demo ? "Demo snapshot" : error ? "Scan status unavailable" : !connected ? busy ? "Connecting…" : "API offline" : running ? `${running} scan${running === 1 ? "" : "s"} running${queued ? ` · ${queued} queued` : ""}` : queued ? `${queued} scan${queued === 1 ? "" : "s"} queued` : latest?.status === "failed" ? "Latest scan failed" : "No active scans";
  return <div className="scan-controls"><div className={`scan-status ${active ? "is-active" : ""}`} role="status" aria-live="polite"><Radio size={16}/><div><strong>{status}</strong><small>{latest ? `Last started ${dateLabel(latest.created_at)}` : "Selected domain scope"}{!demo && connected ? " · 30s refresh" : ""}</small></div></div><div className="scan-actions"><button className="secondary scan-refresh" onClick={onRefresh} disabled={busy || demo || cooldown>0} aria-label="Refresh scan status"><RefreshCw size={15} className={busy ? "spin" : ""}/>{cooldown>0 && !demo ? `Wait ${cooldown}s` : "Refresh"}</button><button className="primary scan-primary" onClick={onScan}><Play size={16}/>New scan</button></div></div>;
}
