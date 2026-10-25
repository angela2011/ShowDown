import { useEffect, useRef, useState, useSyncExternalStore, useId } from 'react';
import { Shield, ArrowRight, Eye, EyeOff } from 'lucide-react';
import { authApi } from './api';
import { getSession, setSession, clearSession, subscribeSession, sessionReason } from './session';
import './auth.css';

export function useSession() { return useSyncExternalStore(subscribeSession,getSession,()=>null); }
export function Redirect({to}) {
  useEffect(()=>{window.location.replace(to);},[to]);
  return <div className="auth-screen"><p role="status">Opening sign in…</p></div>;
}
function Frame({children}) {
 return <div className="auth-screen"><div className="auth-card">
   <a className="auth-brand" href="/" aria-label="ShowDown home"><Shield size={27}/>ShowDown<span>.</span></a>
   {children}
 </div></div>;
}
function PasswordField({label,...props}) {
 const [visible,setVisible]=useState(false);
 const id=useId();
 return <div className="field"><label htmlFor={id}>{label}</label><div className="auth-password-input">
  <input {...props} id={id} type={visible?'text':'password'}/>
  <button type="button" className="auth-password-toggle" aria-label={`${visible?'Hide':'Show'} ${label.toLowerCase()}`} aria-controls={id} disabled={props.disabled} onClick={()=>setVisible(value=>!value)}>
   {visible?<EyeOff size={18} aria-hidden="true"/>:<Eye size={18} aria-hidden="true"/>}
  </button>
 </div></div>;
}
export function AuthPage({register=false}) {
 const [username,setUsername]=useState(''),[password,setPassword]=useState(''),[confirmation,setConfirmation]=useState('');
 const [busy,setBusy]=useState(false),[error,setError]=useState(''),[until,setUntil]=useState(0),[now,setNow]=useState(Date.now());
 const lock=useRef(false);
 const params=new URLSearchParams(window.location.search);
 const notice=params.get('registered')==='1'?'Account created. Sign in to open your dashboard.':
   params.get('reason')==='expired'?'Your session expired or was revoked. Please sign in again.':
   params.get('reason')==='logout-unconfirmed'?'Signed out on this device. The server could not confirm logout; its session will expire automatically.':
   params.get('reason')==='signed-out'?'You have been signed out.':'';
 const wait=Math.max(0,Math.ceil((until-now)/1000));
 useEffect(()=>{document.title=`ShowDown | ${register?'Create account':'Sign in'}`;},[register]);
 useEffect(()=>{if(!until)return;const id=setInterval(()=>setNow(Date.now()),1000);return()=>clearInterval(id);},[until]);
 async function submit(e) {
  e.preventDefault();if(lock.current || Date.now()<until)return;
  if(register && password!==confirmation){setError('Passwords do not match.');return;}
  lock.current=true;setBusy(true);setError('');
  try {
   if(register){await authApi.register(username.trim(),password);window.location.assign('/login?registered=1');}
   else {const result=await authApi.login(username.trim(),password);setSession(result);window.location.assign('/dashboard');}
  }catch(err){setError(err.message);if(err.retryAfter){setNow(Date.now());setUntil(Date.now()+err.retryAfter*1000);}}
  finally{lock.current=false;setBusy(false);}
 }
 return <Frame><h1>{register?'Create your account':'Welcome back'}</h1>
  <p className="auth-intro">{register?'Your verified domains, scans and security findings in one workspace.':'Sign in to your ShowDown security workspace.'}</p>
  {notice && <p className="auth-notice" role="status">{notice}</p>}
  <form onSubmit={submit}>
   <label className="field">Username<input autoComplete="username" required minLength={3} maxLength={64} pattern="[a-zA-Z0-9][a-zA-Z0-9_.\-]{2,63}" value={username} onChange={e=>setUsername(e.target.value)} disabled={busy} aria-describedby="username-help"/></label>
   <small id="username-help">3–64 letters, numbers, dots, underscores or hyphens.</small>
   <PasswordField label="Password" autoComplete={register?'new-password':'current-password'} required minLength={6} maxLength={128} value={password} onChange={e=>setPassword(e.target.value)} disabled={busy} aria-describedby="password-help"/>
   <small id="password-help">6–128 characters. Use a unique passphrase.</small>
   {register && <PasswordField label="Confirm password" autoComplete="new-password" required minLength={6} maxLength={128} value={confirmation} onChange={e=>setConfirmation(e.target.value)} disabled={busy}/>}
   {error && <p className="form-error" role="alert">{error}</p>}
   <button className="primary auth-submit" disabled={busy || wait>0}>{busy?'Please wait…':wait>0?`Try again in ${wait}s`:register?'Create account':'Sign in'}<ArrowRight size={16}/></button>
  </form>
  <p className="auth-switch">{register?'Already have an account?':'New to ShowDown?'} <a href={register?'/login':'/register'}>{register?'Sign in':'Create an account'}</a></p>
  <a className="auth-home" href="/">Back to homepage</a>
 </Frame>;
}
export function ProtectedDashboard({children}) {
 const session=useSession();const [state,setState]=useState({phase:'checking'}),[retry,setRetry]=useState(0);
 useEffect(()=>{
  if(!session)return;
  let alive=true;setState({phase:'checking'});
  authApi.me().then(user=>{
   if(!user?.id || typeof user.username!=='string')throw new Error('The API returned an invalid user response.');
   if(alive)setState({phase:'ready',user});
  }).catch(e=>{if(alive)setState({phase:'error',message:e.message});});
  return()=>{alive=false;};
 },[session,retry]);
 useEffect(()=>{
  // A restored browser history page must revalidate, not reuse a cached dashboard.
  const restored=e=>{if(e.persisted)window.location.reload();};
  window.addEventListener('pageshow',restored);return()=>window.removeEventListener('pageshow',restored);
 },[]);
 async function logout(){
  setState({phase:'logout'});
  try{await authApi.logout();clearSession('signed-out');}
  catch(e){clearSession(e.status===401?'signed-out':'logout-unconfirmed');}
 }
 if(!session)return <Redirect to={`/login${sessionReason()?`?reason=${encodeURIComponent(sessionReason())}`:''}`}/>;
 if(state.phase==='ready')return children({user:state.user,onLogout:logout});
 return <Frame><h1>{state.phase==='logout'?'Signing out':'Checking your session'}</h1>
  {state.phase==='error'?<><p role="alert">{state.message}</p><button className="primary" onClick={()=>setRetry(n=>n+1)}>Retry</button><button className="secondary" onClick={logout}>Sign out</button></>:<p role="status">Please wait…</p>}
 </Frame>;
}
