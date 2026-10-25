import {Badge, Findings} from './components';
import {riskView,changesView,changeKinds} from './risk';
import {dateLabel} from './data';
import './risk-details.css';
export function RiskDetails({scan,onFinding}){
 const risk=riskView(scan),changes=changesView(scan);
 return <div className="risk-details">
 <p className="muted">Selected scan: {dateLabel(scan.completed_at||scan.created_at)}</p>
 <h3>Risk assessment</h3>
 {risk.status==='backend'?<><p><Badge tone={risk.severity||''}>{risk.severity||'No matched rules'}</Badge> <strong>{risk.score}/100</strong> · Backend score</p><p>{risk.method}</p><Findings findings={risk.findings} onSelect={onFinding}/></>:<p role={risk.status==='invalid'?'alert':undefined}>{risk.status==='legacy'?'Legacy scan: no backend risk assessment. Dashboard findings use labelled flag-based classifications; no backend score is available.':'Backend risk data is invalid. Findings are unavailable; local classifications have not been substituted.'}</p>}
 <h3>Changes since previous scan</h3>
 {scan.diff?.first_scan?<p>First scan — initial inventory, not newly exposed since a previous scan.</p>:<p>Baseline scan: {scan.diff?.baseline_scan_id||'Not supplied'}</p>}
 <p>No longer detected does not establish removal or remediation.</p>
 {(Array.isArray(scan.diff?.comparison_notes)?scan.diff.comparison_notes:[]).map((note,i)=><p key={i}>{note}</p>)}
 {changes.status==='legacy'?<p>Legacy scan: structured changes are unavailable. Existing legacy differences remain in raw scan data below.</p>:changes.status==='invalid'?<p role="alert">Invalid backend change data.</p>:changeKinds.map(kind=>{
 const group=changes.groups[kind];return <details key={kind} className="change-group"><summary>{kind[0].toUpperCase()+kind.slice(1)}{group?` — ${group.new.length} new · ${group.changed.length} changed · ${group.no_longer_detected.length} no longer detected`:' — unavailable'}</summary>
 {!group?<p role="alert">Missing or invalid change group; not treated as zero changes.</p>:['new','changed','no_longer_detected'].map(type=><section key={type}><h4>{type==='no_longer_detected'?'No longer detected':type==='new'?'New':'Changed'}</h4>{!group[type].length?<p>None reported.</p>:group[type].map((row,i)=><div key={i} className="change-row">{type==='changed'?<><strong>Before</strong><pre>{JSON.stringify(row.before,null,2)}</pre><strong>After</strong><pre>{JSON.stringify(row.after,null,2)}</pre></>:<pre>{JSON.stringify(row,null,2)}</pre>}</div>)}</section>)}
 </details>;
 })}
 </div>;
}
export function RiskSummary({scans,domains,onSelect,demo}){
 return <div className="risk-details"><p>{demo?'Illustrative demo data. ':'Backend assessments for the latest completed scan of each domain. '}Legacy classifications are labelled and have no backend score.</p>{scans.map(scan=>{const risk=riskView(scan);return <button className="finding" key={scan.id} onClick={()=>onSelect(scan)}><span><strong>{domains.find(d=>d.id===scan.domain_id)?.name||scan.domain_id}</strong><small>{dateLabel(scan.completed_at||scan.created_at)}</small></span><span>{risk.status==='backend'?<><Badge tone={risk.severity||''}>{risk.severity||'No matched rules'}</Badge> {risk.score}/100</>:risk.status==='legacy'?'Legacy · no backend score':'Invalid risk data'}<small>View evidence and changes</small></span></button>;})}{!scans.length&&<p>No completed scans available.</p>}</div>;
}
