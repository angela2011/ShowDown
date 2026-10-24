export class ApiError extends Error {
 constructor(message,status=0,retryAfter=0){super(message);this.name='ApiError';this.status=status;this.retryAfter=retryAfter;}
}
export function retryDelay(value,now=Date.now()) {
 if(value==null)return 30;
 const seconds=Number(value);
 if(Number.isFinite(seconds))return Math.max(1,Math.ceil(seconds));
 const date=Date.parse(value);return Number.isFinite(date)?Math.max(1,Math.ceil((date-now)/1000)):30;
}
const pending=new Map();
async function send(path,options){
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),15000);
 try {
  const response=await fetch(`/api${path}`,{...options,signal:controller.signal,headers:{'Content-Type':'application/json',...options.headers}});
  const body=await response.json().catch(()=>null);
  if(!response.ok){
   const retry=response.status===429?retryDelay(response.headers?.get('Retry-After')):0;
   const detail=typeof body?.detail==='string'?body.detail:`API request failed (${response.status}). Check the backend service.`;
   throw new ApiError(response.status===429?`Rate limit reached. Try again in ${retry}s. ${typeof body?.detail==='string'?body.detail:''}`:detail,response.status,retry);
  }
  if(body===null)throw new ApiError('The API returned an invalid response. Check the gateway connection.');
  return body;
 }catch(e){if(e.name==='AbortError')throw new ApiError('API request timed out. Check that the backend is running.');if(e instanceof ApiError)throw e;throw new ApiError(`Cannot reach the API. ${e.message}`);}finally{clearTimeout(timer);}
}
export function request(path,options={}){
 const isRead=!options.method||options.method==='GET';
 if(!isRead)return send(path,options);
 if(pending.has(path))return pending.get(path);
 const job=send(path,options).finally(()=>pending.delete(path));pending.set(path,job);return job;
}
export const api={domains:()=>request('/domains/'),register:name=>request('/domains/',{method:'POST',body:JSON.stringify({name})}),verify:id=>request(`/verify/${id}`,{method:'POST'}),scans:id=>request(`/scans/domain/${id}`),scan:id=>request(`/scans/${id}`),start:id=>request(`/scans/${id}`,{method:'POST'})};
