import {useEffect,useRef,useState} from 'react';
import {request} from './api';
import {Panel,Badge} from './components';
import {dateLabel} from './data';

export default function HoneypotPanel({demo}) {
 const [sensors,setSensors]=useState([]),[sensor,setSensor]=useState(''),[kind,setKind]=useState('events'),[rows,setRows]=useState([]),[next,setNext]=useState(null),[offset,setOffset]=useState(0),[error,setError]=useState(''),[busy,setBusy]=useState(false);
 const epoch=useRef(0);
 useEffect(()=>{
  let alive=true;
  if(demo)return;
  request('/honeypots/sensors').then(value=>{if(!Array.isArray(value))throw Error('Invalid sensor response');if(alive){setSensors(value);setSensor(value[0]?.id||'');}}).catch(e=>{if(alive)setError(e.status===404?'This backend does not yet provide honeypot history.':e.message);});
  return()=>{alive=false;};
 },[demo]);
 useEffect(()=>{
  const id=++epoch.current;
  setRows([]);setNext(null);
  if(demo||!sensor)return;
  setBusy(true);setError('');
  request(`/honeypots/sensors/${encodeURIComponent(sensor)}/${kind}?limit=25&offset=${offset}`).then(value=>{
   if(!Array.isArray(value?.items))throw Error('Invalid honeypot history response');
   if(epoch.current===id){setRows(value.items);setNext(value.next_offset);}
  }).catch(e=>{if(epoch.current===id)setError(e.message);}).finally(()=>{if(epoch.current===id)setBusy(false);});
  return()=>{epoch.current++;};
 },[sensor,kind,offset,demo]);
 return <Panel title="Honeypot detections & audit" subtitle="Passive decoy observations · responses affect only the selected decoy.">
 <div className="settings">
 {demo?<p>No honeypot events are fabricated in demo mode. Switch to live data to inspect your sensors.</p>:<>
 <p>Confidence reflects observed patterns, not proof of an attack. Blocks require explicit configuration; Azure-wide WAF blocking is not enabled.</p>
 {error&&<p role="alert" className="form-error">{error}</p>}
 {!sensors.length&&!error&&<p>No sensors registered. Provision an isolated decoy using the authenticated honeypot API.</p>}
 {!!sensors.length&&<><label className="field">Sensor<select aria-label="Sensor" value={sensor} onChange={e=>{setSensor(e.target.value);setOffset(0);}}>{sensors.map(s=><option key={s.id} value={s.id}>{s.name}{s.enabled?'':' (revoked)'}</option>)}</select></label>
 <label className="field">History<select aria-label="History" value={kind} onChange={e=>{setKind(e.target.value);setOffset(0);}}><option value="events">Detections</option><option value="blocks">Blocks</option><option value="audit">Audit log</option></select></label>
 {busy?<p role="status">Loading history…</p>:rows.length?rows.map(row=><details key={row.id}><summary>{dateLabel(row.observed_at||row.created_at)} · {row.source_ip||row.action} {row.severity&&<Badge tone={row.severity}>{row.severity} · {row.confidence}/100</Badge>} {row.status&&<Badge>{row.status}</Badge>}</summary><pre style={{whiteSpace:'pre-wrap',overflowWrap:'anywhere'}}>{JSON.stringify(row,null,2)}</pre></details>):!error&&<p>No records on this page.</p>}
 <div><button className="secondary" disabled={busy||offset===0} onClick={()=>setOffset(Math.max(0,offset-25))}>Previous</button> <button className="secondary" disabled={busy||next==null} onClick={()=>setOffset(next)}>Next</button></div></>}
 </>}
 </div></Panel>;
}
