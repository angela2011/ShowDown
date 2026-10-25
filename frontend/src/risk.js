const levels=['critical','high','medium','low'];
const object=value=>value!==null && typeof value==='object' && !Array.isArray(value);
const score=value=>typeof value==='number' && Number.isFinite(value) && value>=0 && value<=100;
export function riskView(scan){
 const risk=scan.diff?.risk;
 if(risk==null)return {status:'legacy',findings:[]};
 if(!object(risk)||!score(risk.score)||!(levels.includes(risk.severity)||(risk.severity===null&&risk.score===0))||!Array.isArray(risk.findings)||risk.findings.some(f=>!object(f)||typeof f.id!=='string'||typeof f.host!=='string'||typeof f.title!=='string'||!levels.includes(f.severity)||!score(f.score)))return {status:'invalid',findings:[]};
 return {...risk,status:'backend',findings:risk.findings.map(f=>({...f,backendId:f.id,id:`${scan.domain_id}:${scan.id}:${f.id}`,scan:scan.id,source:'Backend',provenance:'backend'}))};
}
export const changeKinds=['assets','ports','services','certificates','findings'];
export function changesView(scan){
 const changes=scan.diff?.changes;
 if(changes==null)return {status:'legacy',groups:{}};
 if(!object(changes))return {status:'invalid',groups:{}};
 const groups=Object.fromEntries(changeKinds.map(kind=>{
  const group=changes[kind];
  const valid=object(group)&&['new','changed','no_longer_detected'].every(key=>Array.isArray(group[key])&&group[key].every(row=>object(row)&&(key!=='changed'||(object(row.before)&&object(row.after)))));
  return [kind,valid?group:null];
 }));
 return {status:Object.values(groups).every(Boolean)?'backend':'partial',groups};
}
