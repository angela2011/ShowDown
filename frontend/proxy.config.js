// Gateway removes /api itself; a direct FastAPI connection needs Vite to remove it.
export function apiProxy(env={}) {
  const mode=env.API_PROXY_MODE || 'gateway';
  if(!['gateway','direct'].includes(mode))throw new Error('API_PROXY_MODE must be gateway or direct');
  return {target:env.API_PROXY_TARGET || 'http://localhost:8080',changeOrigin:true,
    ...(mode==='direct'?{rewrite:path=>path.replace(/^\/api(?=\/|$)/,'') || '/'}:{})};
}
