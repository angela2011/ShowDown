import { useState, useEffect, useMemo, useCallback, useRef } from "react";
import {
  Shield,
  LayoutDashboard,
  Layers,
  TriangleAlert,
  History,
  Globe,
  Settings,
  Plus,
  ArrowRight,
  RefreshCw,
  Search,
  Download,
  Menu,
  Radio,
  Check,
  Copy,
} from "lucide-react";
import { api } from "./api";
import {RiskDetails, RiskSummary} from "./RiskDetails";
import { SurfaceRadar, ScanControls } from "./ScanVisuals";
import { derive, dateLabel } from "./data";
import { useMonitor } from "./useMonitor";
import {
  Badge,
  Panel,
  Modal,
  Metrics,
  Activity,
  Risk,
  Assets,
  Findings,
  HistoryTable,
} from "./components";
const navigation = [
  ["Overview", LayoutDashboard],
  ["Assets", Layers],
  ["Findings", TriangleAlert],
  ["Scan history", History],
  ["Domains", Globe],
  ["Settings", Settings],
];
export default function App({user,onLogout}) {
  const [page,setPage]=useState('Overview'),[mobile,setMobile]=useState(false),[scope,setScope]=useState('all'),[search,setSearch]=useState(''),[severity,setSeverity]=useState('all'),[modal,setModal]=useState(null),[notice,setNotice]=useState(''),[mutating,setMutating]=useState(false);
  const monitor=useMonitor();
  const {demo,data,error,setError,busy:loading,connected,lastSync,cooldown,load}=monitor;
  const busy=loading||mutating;
  const mutationLock=useRef(false),menuButton=useRef(null);
  const refresh=()=>load(true);
  function switchMode(value){setScope('all');setModal(null);monitor.switchMode(value);}
  useEffect(()=>{if(!mobile)return;const close=e=>{if(e.key==='Escape'){setMobile(false);menuButton.current?.focus();}};window.addEventListener('keydown',close);return()=>window.removeEventListener('keydown',close);},[mobile]);
  const domains =
    scope === "all" ? data.domains : data.domains.filter((d) => d.id === scope);
  const scans = data.scans.filter((s) =>
    domains.some((d) => d.id === s.domain_id),
  );
  const failedScans=scans.filter(s=>s.status==="failed");
  const derived = useMemo(() => derive(domains, scans), [data, scope]);
  // Animate a new completed snapshot without remounting controls or losing focus.
  const snapshotRef = useRef(null);
  const snapshotKey = `${demo}:${scope}:` + [...new Set(scans.filter(s => s.status === "completed").map(s => `${s.domain_id}:${s.id}`))].sort().join("|");
  useEffect(() => {
    const node = snapshotRef.current;
    const motion = window.matchMedia("(prefers-reduced-motion: reduce)");
    if (!node || motion.matches) return;
    const animation = node.animate([{opacity:.65}, {opacity:1}], {duration:280, easing:"ease-out"});
    const stop = () => { if(motion.matches) animation.cancel(); };
    motion.addEventListener("change", stop);
    return () => { animation.cancel(); motion.removeEventListener("change", stop); };
  }, [snapshotKey]);
  const assets = derived.assets.filter((a) =>
    a.host.toLowerCase().includes(search.toLowerCase()),
  );
  const findings = derived.findings.filter(
    (f) =>
      (severity === "all" || f.severity === severity) &&
      `${f.host} ${f.title}`.toLowerCase().includes(search.toLowerCase()),
  );
  function navigate(next) {
    setPage(next);
    setSearch("");
    setMobile(false);
  }
  async function mutate(action) {
    if(mutationLock.current)return;
    mutationLock.current=true;setMutating(true);setError('');
    try{await action();setModal(null);setNotice('Saved successfully.');await monitor.afterMutation();}
    catch(e){setError(e.message);}
    finally{mutationLock.current=false;setMutating(false);}
  }
  function exportData() {
    const blob = new Blob(
      [
        JSON.stringify(
          {
            source: demo ? "demo" : "backend",
            exported_at: new Date().toISOString(),
            partial_response: Boolean(error),
            domains,
            scans,
            assets: derived.assets,
            findings: derived.findings,
          },
          null,
          2,
        ),
      ],
      { type: "application/json" },
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `showdown-${demo ? "demo" : "live"}-export.json`;
    a.click();
    URL.revokeObjectURL(url);
    setNotice("Snapshot exported.");
  }
  const viewAll = (name) => (
    <button className="text-button" onClick={() => navigate(name)}>
      View all <ArrowRight size={14} />
    </button>
  );
  return (
    <div className="app">
      <aside id="workspace-sidebar" aria-label="Workspace navigation" className={mobile ? "sidebar open" : "sidebar"}>
        <a
          className="brand"
          href="/"
          aria-label="ShowDown home"
        >
          <Shield size={31} />
          <span>
            ShowDown<span className="brand-dot">.</span>
          </span>
        </a>
        <div className="workspace">
          <span className="workspace-icon">S</span>
          <div>
            Security workspace<small>Attack surface intelligence</small>
          </div>
        </div>
        <p className="nav-caption">WORKSPACE</p>
        <nav>
          {navigation.map(([name, Icon]) => (
            <button
              key={name}
              className={page === name ? "nav-item active" : "nav-item"}
              onClick={() => navigate(name)}
            >
              <Icon size={18} />
              {name}
              {name === "Findings" && derived.findings.length > 0 && (
                <span className="nav-count">{derived.findings.length}</span>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="account-controls"><span>{user?.username}</span><button className="text-button" onClick={onLogout}>Sign out</button></div>
          <div className="connection">
            <span className={`status-dot ${connected || demo ? "on" : ""}`} />
            <div>
              {demo
                ? "Demo environment"
                : connected
                  ? "API connected"
                  : "API disconnected"}
              <small>
                {demo ? "Illustrative data only" : "Refreshes every 30 seconds"}
              </small>
            </div>
          </div>
          <button className="mode-button" onClick={() => switchMode(!demo)}>
            {demo ? "Connect to backend" : "Explore demo data"}
            <ArrowRight size={14} />
          </button>
          <div className="sidebar-footer">
            <Shield size={14} /> External visibility. Clear priorities.
          </div>
        </div>
      </aside>
      <main>
        <div className="topbar">
          <button
            className="icon-button mobile-menu"
            aria-label="Toggle navigation"
            aria-expanded={mobile}
            aria-controls="workspace-sidebar"
            ref={menuButton}
            onClick={() => setMobile(!mobile)}
          >
            <Menu size={21} />
          </button>
          <div className="breadcrumb">
            Workspace <span>/</span> <b>{page}</b>
          </div>
          <div className="top-controls">
            <span className="source">
              <span className={`status-dot ${connected || demo ? "on" : ""}`} />
              {demo ? "Demo data" : connected ? "Live API" : "Offline"}
            </span>
            <button
              className="icon-button"
              aria-label="Refresh data"
              disabled={busy || demo || cooldown > 0}
              onClick={refresh}
            >
              <RefreshCw size={16} className={busy ? "spin" : ""} />
            </button>
          </div>
        </div>
        <div className="content">
          <header className="page-head">
            <div>
              <h1>{page === "Overview" ? "Attack surface overview" : page}</h1>
              <p>
                {page === "Overview"
                  ? "Visibility across your external perimeter."
                  : page === "Assets"
                    ? "Every discovered host, port, and service in one place."
                    : page === "Findings"
                      ? "Prioritize the observations that need your attention."
                      : page === "Scan history"
                        ? "Trace your perimeter, one scan at a time."
                        : page === "Domains"
                          ? "Define and verify the domains you monitor."
                          : "Your connection and data preferences."}
              </p>
            </div>
            <ScanControls scans={scans} demo={demo} connected={connected} busy={busy} error={error} cooldown={cooldown} onScan={() => setModal({type: "scan"})} onRefresh={refresh} />
          </header>
          {demo && (
            <div className="demo-strip">
              <Radio size={15} />
              <span>
                Demo data · Illustrative assets and scans. No backend changes
                are made.
              </span>
              <button className="text-button" onClick={() => switchMode(false)}>
                Connect API <ArrowRight size={14} />
              </button>
            </div>
          )}
          {error && (
            <div className="alert" role="alert">
              <TriangleAlert size={18} />
              <div>
                <strong>Backend needs attention</strong>
                <p>{error}</p>
              </div>
              <button className="text-button" onClick={refresh} disabled={busy || cooldown > 0}>
                Retry
              </button>
            </div>
          )}
          {notice && (
            <div className="notice" role="status">
              <Check size={16} />
              {notice}
              <button className="text-button" onClick={() => setNotice("")}>
                Dismiss
              </button>
            </div>
          )}
          {page !== "Settings" && (
            <div className="toolbar">
              <label className="scope">
                <Globe size={15} />
                <select
                  aria-label="Domain scope"
                  value={scope}
                  onChange={(e) => setScope(e.target.value)}
                >
                  <option value="all">All domains</option>
                  {data.domains.map((d) => (
                    <option key={d.id} value={d.id}>
                      {d.name}
                    </option>
                  ))}
                </select>
              </label>
              <span className="toolbar-note">
                {domains.length} domains in scope
              </span>
              <button className="secondary export" onClick={exportData}>
                <Download size={14} />
                Export snapshot
              </button>
            </div>
          )}
          <div className="sync-state" role="status">{busy ? 'Refreshing data…' : lastSync ? `Last synchronized ${dateLabel(lastSync)}` : demo ? 'Demonstration data only' : 'Waiting for API data'}{cooldown>0 && !demo && ` · Refresh available in ${cooldown}s`}</div>
          {failedScans.length>0 && <div className="alert" role="status"><TriangleAlert size={18}/><div><strong>{failedScans.length} failed scan{failedScans.length===1?'':'s'} in scope</strong><p>{failedScans.slice(0,3).map(scan=>`${dateLabel(scan.created_at)}: ${scan.diff?.error||'The worker reported a failure. Inspect scan details.'}`).join(' · ')}</p><button className="text-button" onClick={()=>navigate('Scan history')}>View scan history</button></div></div>}
          {page === "Overview" && (
            <div ref={snapshotRef} className="snapshot-view">
              <Metrics
                assets={derived.assets.length}
                ports={derived.ports}
                findings={derived.findings.length}
                scans={scans.filter((s) => s.status === "completed").length}
              />
              <Panel title="Risk assessments and changes"><RiskSummary scans={derived.snapshots} domains={domains} demo={demo} onSelect={s=>setModal({type:"detail",value:s})}/></Panel>
              <SurfaceRadar assets={derived.assets} demo={demo} onSelect={a => setModal({type: "asset", value:a})}/>
              <div className="charts">
                <Activity scans={scans} />
                <Risk findings={derived.findings} />
              </div>
              <div className="data-grid">
                <Panel
                  title="Discovered assets"
                  subtitle="Latest observed external assets."
                  action={viewAll("Assets")}
                >
                  <Assets
                    assets={derived.assets}
                    limit={5}
                    onSelect={(a) => setModal({ type: "asset", value: a })}
                  />
                </Panel>
                <Panel
                  title="Priority findings"
                  subtitle="Socket and TLS observations."
                  action={viewAll("Findings")}
                >
                  <Findings
                    findings={derived.findings}
                    limit={4}
                    onSelect={(f) => setModal({ type: "finding", value: f })}
                  />
                </Panel>
              </div>
              <Panel
                title="Recent scan history"
                subtitle="Latest scans and their current state."
                action={viewAll("Scan history")}
              >
                <HistoryTable
                  domains={domains}
                  scans={scans}
                  limit={4}
                  onSelect={(s) => setModal({ type: "detail", value: s })}
                />
              </Panel>
            </div>
          )}
          {["Assets", "Findings"].includes(page) && (
            <Panel
              title={
                page === "Assets"
                  ? `Discovered assets (${assets.length})`
                  : `Security findings (${findings.length})`
              }
              subtitle={
                page === "Findings"
                  ? "Backend severity and scores where available. Legacy flag classifications are labelled."
                  : null
              }
            >
              <div className="filters">
                <label className="search">
                  <Search size={16} />
                  <input
                    aria-label="Search results"
                    placeholder="Search hosts or findings…"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                  />
                </label>
                {page === "Findings" && (
                  <select
                    aria-label="Severity filter"
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value)}
                  >
                    {["all", "critical", "high", "medium", "low"].map((s) => (
                      <option key={s} value={s}>
                        {s === "all" ? "All severities" : s}
                      </option>
                    ))}
                  </select>
                )}
              </div>
              {page === "Assets" ? (
                <Assets
                  assets={assets}
                  onSelect={(a) => setModal({ type: "asset", value: a })}
                />
              ) : (
                <Findings
                  findings={findings}
                  onSelect={(f) => setModal({ type: "finding", value: f })}
                />
              )}
            </Panel>
          )}
          {page === "Scan history" && (
            <Panel
              title="Scan history"
              subtitle="Select a scan to inspect its raw results and changes."
            >
              <HistoryTable
                domains={domains}
                scans={scans}
                onSelect={(s) => setModal({ type: "detail", value: s })}
              />
            </Panel>
          )}
          {page === "Domains" && (
            <Panel
              title="Registered domains"
              subtitle="DNS ownership verification is required before scanning."
              action={
                <button
                  className="secondary"
                  onClick={() => setModal({ type: "domain" })}
                >
                  <Plus size={15} />
                  Add domain
                </button>
              }
            >
              <div className="domain-list">
                {domains.map((d) => (
                  <div className="domain-row" key={d.id}>
                    <Globe size={23} />
                    <div>
                      <strong>{d.name}</strong>
                      <small>
                        {d.verified
                          ? "Ownership verified"
                          : "DNS verification required"}
                      </small>
                    </div>
                    <Badge tone={d.verified ? "low" : "medium"}>
                      {d.verified ? "Verified" : "Pending"}
                    </Badge>
                    <button
                      className="secondary"
                      onClick={() => setModal({ type: "verify", value: d })}
                    >
                      {d.verified ? "View details" : "Verify domain"}
                    </button>
                  </div>
                ))}
                {!domains.length && (
                  <div className="empty">
                    Add your first domain to begin monitoring.
                  </div>
                )}
              </div>
            </Panel>
          )}
          {page === "Settings" && (
            <Panel
              title="Connection & data"
              subtitle="The frontend uses your existing API gateway."
            >
              <div className="settings">
                <div>
                  <h3>Data source</h3>
                  <p>
                    {demo
                      ? "Demo mode is active. All displayed records are sample data."
                      : "Live mode is active. API failures never silently substitute demo data."}
                  </p>
                  <button
                    className="secondary"
                    onClick={() => switchMode(!demo)}
                  >
                    {demo ? "Use live backend" : "Use demo data"}
                  </button>
                </div>
                <div>
                  <h3>API gateway</h3>
                  <code>/api → API_PROXY_TARGET</code>
                  <p>
                    Configure the gateway address in frontend/.env and restart
                    Vite. Default: http://localhost:8080.
                  </p>
                </div>
                <div>
                  <h3>Available integrations</h3>
                  <p>
                    Domain registration, DNS verification, scan creation, scan
                    history, asset discovery, socket flags, TLS flags and scan
                    differences.
                  </p>
                </div>
                <div>
                  <h3>Backend limitations</h3>
                  <p>
                    Honeypot and WAF controls are not available in the supplied
                    routes. Backend risk assessments drive severity when available; legacy scans retain labelled flag classifications.
                  </p>
                </div>
              </div>
            </Panel>
          )}
          <footer className="page-footer">
            <span>ShowDown · Attack surface intelligence</span>
            <span>
              {demo ? "Sample data" : "Latest completed snapshots"}{" "}
              <span className="footer-dot">•</span> All times shown locally
            </span>
          </footer>
        </div>
      </main>
      {modal && (
        <Modal
          title={
            modal.type === "scan"
              ? "Start a new scan"
              : modal.type === "domain"
                ? "Register a domain"
                : modal.type === "verify"
                  ? "Domain verification"
                  : modal.type === "asset"
                    ? "Asset details"
                    : modal.type === "finding"
                      ? "Security observation"
                      : "Scan details"
          }
          onClose={() => setModal(null)}
        >
          {modal.type === "scan" && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                const id = new FormData(e.currentTarget).get("domain");
                if (demo) {
                  setNotice(
                    "Demo mode: no scan was sent. Connect to the backend to run a scan.",
                  );
                  setModal(null);
                } else mutate(() => api.start(id));
              }}
            >
              <p className="muted">
                Discover subdomains, open ports, socket services and TLS
                observations for a verified domain.
              </p>
              <label className="field">
                Target domain
                <select name="domain" required>
                  {data.domains
                    .filter((d) => d.verified)
                    .map((d) => (
                      <option key={d.id} value={d.id}>
                        {d.name}
                      </option>
                    ))}
                </select>
              </label>
              {!data.domains.some((d) => d.verified) && (
                <p className="muted">
                  Register and verify a domain in Domains first.
                </p>
              )}
              <button
                className="primary"
                disabled={busy || !data.domains.some((d) => d.verified)}
              >
                {demo ? "Preview scan action" : "Start scan"}
              </button>
            </form>
          )}
          {modal.type === "domain" && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                const name = new FormData(e.currentTarget)
                  .get("name")
                  .trim()
                  .toLowerCase();
                if (demo) {
                  setNotice("Domain registration is available in live mode.");
                  setModal(null);
                } else mutate(() => api.register(name));
              }}
            >
              <p className="muted">
                Add a domain you own or are authorized to assess.
              </p>
              <label className="field">
                Domain name
                <input
                  name="name"
                  required
                  placeholder="example.com"
                  pattern="[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)+"
                />
              </label>
              <button className="primary" disabled={busy || cooldown > 0}>
                Register domain
              </button>
            </form>
          )}
          {modal.type === "verify" && (
            <div className="details">
              <p>Add this DNS TXT record, then verify ownership.</p>
              <label>
                Record name<code>_asm-verify.{modal.value.name}</code>
              </label>
              <label>
                TXT value<code>{modal.value.verification_token}</code>
              </label>
              <button
                className="secondary"
                onClick={async () => {
                  try {
                    await navigator.clipboard.writeText(
                      modal.value.verification_token,
                    );
                    setNotice("TXT value copied.");
                  } catch {
                    setNotice(
                      "Clipboard unavailable. Select and copy the displayed TXT value.",
                    );
                  }
                }}
              >
                <Copy size={15} />
                Copy TXT value
              </button>
              <button
                className="primary"
                disabled={busy || demo || modal.value.verified}
                onClick={() => mutate(() => api.verify(modal.value.id))}
              >
                {modal.value.verified ? "Already verified" : "Verify ownership"}
              </button>
              {demo && (
                <p className="muted">
                  Verification is disabled for sample domains.
                </p>
              )}
            </div>
          )}
          {["asset", "finding", "detail"].includes(modal.type) && (
            <div className="details">
              {modal.type === "finding" && (
                <>
                  <Badge tone={modal.value.severity}>
                    {modal.value.severity}
                  </Badge>
                  <h3>{modal.value.title}</h3>
                  {modal.value.provenance==='backend'?<><p>Backend score: {modal.value.score}/100 · Rule: {modal.value.rule_id}</p><p>{modal.value.reason}</p><h4>Supporting evidence</h4><pre>{JSON.stringify(modal.value.evidence??null,null,2)}</pre></>:<p>Legacy flag classification; no backend score or structured evidence available.</p>}
                </>
              )}
              {modal.type==="detail" && <RiskDetails scan={modal.value} onFinding={f=>setModal({type:"finding",value:f})}/>}
              <details><summary>Raw details</summary><pre>{JSON.stringify(modal.value, null, 2)}</pre></details>
            </div>
          )}
          {error && (
            <p className="form-error" role="alert">
              {error}
            </p>
          )}
        </Modal>
      )}
    </div>
  );
}
