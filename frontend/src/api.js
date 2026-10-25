import { getSession, clearSession } from './session.js';
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
async function send(path,options,token){
 const {publicRequest=false,...fetchOptions}=options;
 const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),15000);
 try {
  const response=await fetch(`/api${path}`,{...fetchOptions,cache:'no-store',signal:controller.signal,headers:{'Content-Type':'application/json',...options.headers,...(token?{Authorization:`Bearer ${token}`}:{})}});
  // Discard responses from a prior account/session, including late 401s.
  if(!publicRequest && getSession()?.access_token!==token) throw new ApiError('Session changed; response discarded.',401);
  if(response.status===401 && !publicRequest) clearSession('expired',token);
  if(response.ok && response.status===204) return null;
  const body=await response.json().catch(()=>null);
  if(!response.ok){
   if(response.status===404 && publicRequest && ['/auth/register','/auth/login'].includes(path))throw new ApiError('The connected backend does not provide this authentication endpoint. Check that the updated ShowDown API is running and the development proxy targets the correct gateway or API.',404);
   const retry=response.status===429?retryDelay(response.headers?.get('Retry-After')):0;
   const detail=typeof body?.detail==='string'?body.detail:Array.isArray(body?.detail)?body.detail.map(e=>e.msg).join(' '):`API request failed (${response.status}). Check the backend service.`;
   throw new ApiError(response.status===429?`Rate limit reached. Try again in ${retry}s. ${typeof body?.detail==='string'?body.detail:''}`:detail,response.status,retry);
  }
  if(body===null)throw new ApiError('The API returned an invalid response. Check the gateway connection.');
  return body;
 }catch(e){if(e.name==='AbortError')throw new ApiError('API request timed out. Check that the backend is running.');if(e instanceof ApiError)throw e;throw new ApiError(`Cannot reach the API. ${e.message}`);}finally{clearTimeout(timer);}
}
export function request(path,options={}){
 const active=getSession();
 const token=options.publicRequest?null:active?.access_token;
 if(!options.publicRequest && (!token || Date.parse(active.expires_at)<=Date.now())) {
  clearSession('expired',token);
  return Promise.reject(new ApiError('Please sign in to continue.',401));
 }
 const isRead=!options.method||options.method==='GET';
 if(!isRead)return send(path,options,token);
 const key=`${token || 'public'}:${path}`;
 if(pending.has(key))return pending.get(key);
 const job=send(path,options,token).finally(()=>pending.delete(key));pending.set(key,job);return job;
}
export const authApi={
 register:(username,password)=>request('/auth/register',{publicRequest:true,method:'POST',body:JSON.stringify({username,password})}),
 login:(username,password)=>request('/auth/login',{publicRequest:true,method:'POST',body:JSON.stringify({username,password})}),
 me:()=>request('/auth/me'),
 logout:()=>request('/auth/logout',{method:'POST'}),
};
export const api={domains:()=>request('/domains/'),register:name=>request('/domains/',{method:'POST',body:JSON.stringify({name})}),verify:id=>request(`/verify/${id}`,{method:'POST'}),scans:id=>request(`/scans/domain/${id}`),scan:id=>request(`/scans/${id}`),start:id=>request(`/scans/${id}`,{method:'POST'})};
