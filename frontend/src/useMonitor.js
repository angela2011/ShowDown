import {useCallback,useEffect,useRef,useState} from 'react';
import {api} from './api';
import {demoData} from './data';
import {validateDomains,validateScans} from './validation';
export function useMonitor(){
 const [demo,setDemo]=useState(false),[data,setData]=useState({domains:[],scans:[]}),[error,setError]=useState(''),[busy,setBusy]=useState(false),[connected,setConnected]=useState(false),[lastSync,setLastSync]=useState(null),[cooldown,setCooldown]=useState(0);
 const epoch=useRef(0),job=useRef(null),manualUntil=useRef(0),retryUntil=useRef(0),mode=useRef(false),mounted=useRef(true);
 const load=useCallback((manual=false)=>{
  if(mode.current||Date.now()<retryUntil.current)return Promise.resolve();
  if(job.current?.epoch===epoch.current)return job.current.promise;
  if(manual&&Date.now()<manualUntil.current)return Promise.resolve();
  if(manual){manualUntil.current=Date.now()+5000;setCooldown(5);}
  const token=epoch.current;setBusy(true);
  const active=()=>mounted.current&&epoch.current===token;
  const promise=(async()=>{try{
   const domains=validateDomains(await api.domains());const scans=[],failures=[];
   // Bound fan-out. The current gateway limits requests; avoid an unbounded burst.
   for(let i=0;i<domains.length;i+=3){
    if(!active())return;
    const batch=await Promise.allSettled(domains.slice(i,i+3).map(async d=>validateScans(await api.scans(d.id),d.id)));
    batch.forEach((result,index)=>{if(result.status==='fulfilled')scans.push(...result.value);else {failures.push(`${domains[i+index].name}: ${result.reason.message}`);if(result.reason.retryAfter)retryUntil.current=Math.max(retryUntil.current,Date.now()+result.reason.retryAfter*1000);}});
    if(Date.now()<retryUntil.current){if(i+3<domains.length)failures.push(`${domains.length-i-3} additional domains skipped due to rate limit.`);break;}
   }
   if(!active())return;
   setData({domains,scans});setConnected(true);setLastSync(new Date().toISOString());setError(failures.length?`Partial API response. Counts exclude unavailable domain histories. ${failures.join(' ')}`:'');
  }catch(e){if(!active())return;setError(e.message);setConnected(false);setData({domains:[],scans:[]});if(e.retryAfter)retryUntil.current=Date.now()+e.retryAfter*1000;
  }finally{if(active()){setBusy(false);setCooldown(Math.max(0,Math.ceil((Math.max(manualUntil.current,retryUntil.current)-Date.now())/1000)));}if(job.current?.epoch===token)job.current=null;}})();
  job.current={epoch:token,promise};return promise;
 },[]);
 useEffect(()=>{mounted.current=true;load();const poll=setInterval(()=>load(),30000),clock=setInterval(()=>setCooldown(Math.max(0,Math.ceil((Math.max(manualUntil.current,retryUntil.current)-Date.now())/1000))),1000);return()=>{mounted.current=false;clearInterval(poll);clearInterval(clock);}},[load]);
 function switchMode(value){epoch.current++;mode.current=value;setDemo(value);setData(value?demoData():{domains:[],scans:[]});setError('');setConnected(false);setBusy(false);setLastSync(null);if(!value)load();}
 async function afterMutation(){if(job.current)await job.current.promise;await load();}
 return {demo,data,error,setError,busy,connected,lastSync,cooldown,load,switchMode,afterMutation};
}
