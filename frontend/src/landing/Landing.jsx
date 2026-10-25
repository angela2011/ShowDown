import { useEffect, useRef } from "react";
import {
  ArrowRight,
  Check,
  Eye,
  Globe,
  History,
  Layers,
  Lock,
  Scale,
  Shield,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import "./landing.css";
import { useReveal } from "./useReveal";
import RadarPreview from "./RadarPreview";
import { AssetsPreview, ScanPreview, FindingsPreview, HistoryPreview } from "./FeaturePreviews";

// The existing dashboard lives at this path (see src/Root.jsx).
export const DASHBOARD_HREF = "/dashboard";

const FEATURES = [
  {
    id: "asset-discovery",
    icon: Layers,
    title: "Asset discovery",
    body: "Start with one verified domain. ShowDown looks for subdomains in certificate transparency logs and through DNS lookups, then checks which common ports are open on each host you find.",
    points: [
      "Subdomains from certificate transparency logs and DNS lookups",
      "TCP checks across common service ports",
      "One inventory of hosts, open ports and detected services",
    ],
    Preview: AssetsPreview,
  },
  {
    id: "security-scanning",
    icon: ShieldCheck,
    title: "Security scanning",
    body: "For every open port, ShowDown reads the service banner, fingerprints the protocol and runs basic socket-level checks. TLS checks look at the certificate and the protocol version in use.",
    points: [
      "Banner grabbing and protocol fingerprinting",
      "Plain-text responses on ports that should use TLS",
      "TLS protocol and certificate expiry checks",
    ],
    note: "Checks are read-only. ShowDown never tries to exploit what it finds.",
    Preview: ScanPreview,
  },
  {
    id: "risk-findings",
    icon: TriangleAlert,
    title: "Risk findings",
    body: "Socket and TLS observations are turned into findings with a severity, so you know where to start. Severity is assigned in the dashboard from the flags the scanner reports. It is not a separate backend risk score.",
    points: [
      "Findings grouped by severity",
      "Search by host and filter by severity",
      "Open any finding to see the observation behind it",
    ],
    Preview: FindingsPreview,
  },
  {
    id: "scan-history",
    icon: History,
    title: "Scan history",
    body: "Every scan is recorded with its status and results. The backend compares each scan with the previous completed one and stores new and removed subdomains and newly opened or closed ports.",
    points: [
      "Status for every scan: queued, running, completed or failed",
      "Activity across scans in one chart",
      "Export a JSON snapshot of what you are viewing",
    ],
    Preview: HistoryPreview,
  },
];

const STEPS = [
  {
    title: "Register a domain",
    body: "Add a domain you own or are authorized to assess.",
  },
  {
    title: "Verify ownership",
    body: "Publish the DNS TXT record ShowDown gives you. Scans stay locked until it is found.",
  },
  {
    title: "Run a scan",
    body: "A worker discovers subdomains, checks common ports, inspects services and checks TLS.",
  },
  {
    title: "Review the results",
    body: "Browse assets, findings and scan history in the dashboard, and export a snapshot.",
  },
];

const PRINCIPLES = [
  {
    icon: Lock,
    title: "Authorization first",
    body: "The API refuses to start a scan until a domain has been verified with a DNS record, so you can only scan domains you can prove you control.",
  },
  {
    icon: Eye,
    title: "Read-only checks",
    body: "ShowDown looks at what is exposed and what it reveals. It does not send exploits or attempt to break in.",
  },
  {
    icon: Scale,
    title: "Plain about severity",
    body: "Findings are observations with a severity chosen by the dashboard. They are prompts to review a service, not proof of a vulnerability.",
  },
];

function DashboardLink({ size = "md", children = "Open Security Dashboard" }) {
  return (
    <a className={`lp-btn lp-btn--primary${size === "sm" ? " lp-btn--sm" : ""}`} href={DASHBOARD_HREF}>
      {children}
      <ArrowRight size={size === "sm" ? 15 : 17} aria-hidden="true" />
    </a>
  );
}

export default function Landing() {
  const root = useRef(null);
  useReveal(root);

  useEffect(() => {
    const previousTitle = document.title;
    document.title = "ShowDown | See your attack surface";
    document.documentElement.classList.add("lp-smooth");

    // Arriving from the dashboard with an in-page anchor (e.g. #features)? Scroll to it.
    const id = window.location.hash.slice(1);
    const target = id && !id.startsWith("/") ? document.getElementById(id) : null;
    if (target) target.scrollIntoView();
    else window.scrollTo(0, 0);

    return () => {
      document.title = previousTitle;
      document.documentElement.classList.remove("lp-smooth");
    };
  }, []);

  return (
    <div className="lp" ref={root}>
      <a className="lp-skip" href="#lp-content">
        Skip to content
      </a>

      <header className="lp-header">
        <div className="lp-container lp-header-inner">
          <a className="lp-brand" href="/" aria-label="ShowDown home">
            <Shield size={28} aria-hidden="true" />
            <span>
              ShowDown<span className="lp-brand-dot">.</span>
            </span>
          </a>
          <nav className="lp-nav" aria-label="Page sections">
            <a href="#features">Features</a>
            <a href="#how-it-works">How it works</a>
            <a href="#principles">Principles</a>
          </nav>
          <DashboardLink size="sm">Open dashboard</DashboardLink>
        </div>
      </header>

      <main id="lp-content" className="lp-main" tabIndex={-1}>
        <section className="lp-hero" id="top" aria-labelledby="lp-hero-title">
          <div className="lp-container lp-hero-grid">
            <div className="lp-hero-copy">
              <h1 id="lp-hero-title">
                <span className="lp-h1-line">
                  <span className="lp-nb">See Your</span> <span className="lp-nb">Attack Surface.</span>
                </span>
                <span className="lp-h1-line lp-h1-accent">
                  <span className="lp-nb">Secure</span> <span className="lp-nb">What Matters.</span>
                </span>
              </h1>
              <p className="lp-lead">
                ShowDown is an attack surface management platform. It maps the domains, subdomains, open ports and
                services you expose to the internet, flags risky configurations, and keeps a record of every scan so
                you can see what changes.
              </p>
              <div className="lp-cta-row">
                <DashboardLink />
                <a className="lp-btn lp-btn--ghost" href="#how-it-works">
                  See how it works
                </a>
              </div>
              <p className="lp-hero-note">
                <Check size={15} aria-hidden="true" />
                Scans run only against domains you have verified with a DNS record.
              </p>
            </div>
            <div className="lp-hero-visual">
              <RadarPreview />
            </div>
          </div>
        </section>

        <section className="lp-section lp-about" aria-labelledby="lp-about-title">
          <div className="lp-container lp-about-grid">
            <h2 id="lp-about-title" data-reveal>
              What is attack surface management?
            </h2>
            <div className="lp-prose" data-reveal>
              <p>
                Your attack surface is everything about your organization that can be reached from the internet:
                domains, subdomains, servers, open ports, running services and certificates. It changes whenever a team
                launches a test server or opens a port, and it is easy to lose track of.
              </p>
              <p>
                Attack surface management keeps an up-to-date inventory of those assets and points out the ones worth a
                closer look. ShowDown does this for the domains you own, with a focus on defensive visibility.
              </p>
            </div>
          </div>
        </section>

        <section className="lp-section" id="features" aria-labelledby="lp-features-title">
          <div className="lp-container">
            <div className="lp-section-head" data-reveal>
              <h2 id="lp-features-title">What ShowDown does</h2>
              <p>From a single domain to a reviewed list of exposed services, in four parts.</p>
            </div>
            <div className="lp-features">
              {FEATURES.map(({ id, icon: Icon, title, body, points, note, Preview }, i) => (
                <article
                  key={id}
                  id={id}
                  className={`lp-feature${i % 2 ? " lp-feature--flip" : ""}`}
                  aria-labelledby={`${id}-title`}
                  data-reveal
                >
                  <div className="lp-feature-copy">
                    <span className="lp-icon-box">
                      <Icon size={20} aria-hidden="true" />
                    </span>
                    <h3 id={`${id}-title`}>{title}</h3>
                    <p>{body}</p>
                    <ul className="lp-points">
                      {points.map((p) => (
                        <li key={p}>{p}</li>
                      ))}
                    </ul>
                    {note && <p className="lp-feature-note">{note}</p>}
                  </div>
                  <div className="lp-feature-visual">
                    <Preview />
                  </div>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className="lp-section lp-how" id="how-it-works" aria-labelledby="lp-how-title">
          <div className="lp-container">
            <div className="lp-section-head" data-reveal>
              <h2 id="lp-how-title">How it works</h2>
              <p>Four steps from adding a domain to reviewing what it exposes.</p>
            </div>
            <ol className="lp-steps">
              {STEPS.map(({ title, body }, i) => (
                <li key={title} className="lp-step" data-reveal style={{ "--d": `${i * 70}ms` }}>
                  <span className="lp-step-num" aria-hidden="true">
                    {i + 1}
                  </span>
                  <h3>{title}</h3>
                  <p>{body}</p>
                </li>
              ))}
            </ol>
          </div>
        </section>

        <section className="lp-section" id="principles" aria-labelledby="lp-principles-title">
          <div className="lp-container">
            <div className="lp-section-head" data-reveal>
              <h2 id="lp-principles-title">Built to stay on the defensive side</h2>
            </div>
            <div className="lp-principles">
              {PRINCIPLES.map(({ icon: Icon, title, body }, i) => (
                <div key={title} className="lp-principle" data-reveal style={{ "--d": `${i * 70}ms` }}>
                  <span className="lp-icon-box">
                    <Icon size={20} aria-hidden="true" />
                  </span>
                  <h3>{title}</h3>
                  <p>{body}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="lp-section lp-final" aria-labelledby="lp-final-title">
          <div className="lp-container">
            <div className="lp-final-card" data-reveal>
              <h2 id="lp-final-title">Open the dashboard and see what you expose.</h2>
              <p>Want to look around first? The dashboard has a demo mode with illustrative data.</p>
              <DashboardLink />
            </div>
          </div>
        </section>
      </main>

      <footer className="lp-footer">
        <div className="lp-container">
          <div className="lp-footer-grid">
            <div>
              <a className="lp-brand" href="#top" aria-label="Back to top">
                <Shield size={24} aria-hidden="true" />
                <span>
                  ShowDown<span className="lp-brand-dot">.</span>
                </span>
              </a>
              <p className="lp-footer-tag">External visibility. Clear priorities.</p>
            </div>
            <nav aria-label="Footer">
              <ul className="lp-footer-links">
                <li>
                  <a href="#features">Features</a>
                </li>
                <li>
                  <a href="#how-it-works">How it works</a>
                </li>
                <li>
                  <a href="#principles">Principles</a>
                </li>
                <li>
                  <a href={DASHBOARD_HREF}>
                    <Globe size={14} aria-hidden="true" /> Security dashboard
                  </a>
                </li>
              </ul>
            </nav>
          </div>
          <div className="lp-footer-base">
            <span>© {new Date().getFullYear()} ShowDown</span>
            <span>Only scan domains you own or are authorized to assess.</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
