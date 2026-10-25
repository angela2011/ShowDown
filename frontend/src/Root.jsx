import App from "./App";
import Landing from "./landing/Landing";
import {AuthPage, ProtectedDashboard} from "./Auth";

// Ordinary links use document navigation, so direct loads, reloads and browser
// Back/Forward all resolve the same pathname without a router dependency.
export default function Root() {
  const path = window.location.pathname;
  if (path === "/") return <Landing />;
  if (path === "/login" || path === "/login/") return <AuthPage />;
  if (path === "/register" || path === "/register/") return <AuthPage register />;
  if (path === "/dashboard" || path === "/dashboard/") return <ProtectedDashboard>{props=><App {...props}/>}</ProtectedDashboard>;
  return <main style={{ margin: 0, padding: 32 }}>
    <h1>Page not found</h1>
    <p><a href="/">ShowDown home</a> · <a href="/dashboard">Dashboard</a></p>
  </main>;
}
