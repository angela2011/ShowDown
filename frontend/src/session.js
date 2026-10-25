// The existing backend issues bearer tokens, not HttpOnly cookies. Keep them
// tab-scoped; never store passwords or protected results in browser storage.
const KEY = 'showdown.session.v1';
const listeners = new Set();
let reason = '', timer;
function storage() { try { return globalThis.sessionStorage; } catch { return undefined; } }
export function validSession(value, now=Date.now()) {
  return value && /^[A-Za-z0-9_-]{43}$/.test(value.access_token || '') &&
    value.token_type === 'bearer' && typeof value.expires_at === 'string' &&
    Number.isFinite(Date.parse(value.expires_at)) && Date.parse(value.expires_at) > now;
}
function read() {
  try { const value=JSON.parse(storage()?.getItem(KEY) || 'null'); if(validSession(value)) return value; }
  catch { /* Unavailable/corrupt storage means signed out. */ }
  try { storage()?.removeItem(KEY); } catch { /* No storage access. */ }
  return null;
}
let session=read();
function arm() {
  clearTimeout(timer);
  if(session) {
    timer=setTimeout(()=>clearSession('expired'),Math.max(0,Date.parse(session.expires_at)-Date.now()));
    timer.unref?.();
  }
}
function publish() { arm(); for(const fn of listeners) fn(); }
export function getSession() { return session; }
export function sessionReason() { return reason; }
export function subscribeSession(fn) { listeners.add(fn); return ()=>listeners.delete(fn); }
export function setSession(value) {
  if(!validSession(value)) throw new Error('The server returned an invalid or expired session.');
  const next={access_token:value.access_token,token_type:'bearer',expires_at:value.expires_at};
  try {
    const store=storage();
    if(typeof window!=='undefined' && !store)throw new Error();
    store?.setItem(KEY,JSON.stringify(next));
  } catch { throw new Error('Browser session storage is unavailable. Enable it to sign in.'); }
  session=next;reason='';
  publish();
}
export function clearSession(why='signed-out', expectedToken) {
  if(expectedToken && session?.access_token!==expectedToken) return;
  session=null;reason=why;
  try { storage()?.removeItem(KEY); } catch { /* Still clear memory. */ }
  publish();
}
arm();
