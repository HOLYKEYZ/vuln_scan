import React, { useEffect, useRef, useState } from 'react';
import {
  ShieldCheck,
  FileText,
  UploadCloud,
  Bug,
  AlertTriangle,
  Lock,
  Database,
  Link2,
  Box,
  Layers,
  Search,
  ScanLine,
  BarChart3,
  CheckCircle2,
  ChevronRight,
  Mail,
  Phone,
  Code,
  TerminalSquare,
  GitBranch,
  FileCode2,
  KeyRound,
  Globe,
} from 'lucide-react';

// Minimal IntersectionObserver hook for reveal-on-scroll
const useInView = (options?: IntersectionObserverInit) => {
  const ref = useRef<HTMLDivElement | null>(null);
  const [inView, setInView] = useState(false);

  useEffect(() => {
    if (!ref.current) return;
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setInView(true);
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.15, rootMargin: '0px 0px -5% 0px', ...(options || {}) }
    );
    observer.observe(ref.current);
    return () => observer.disconnect();
  }, [options]);

  return { ref, inView };
};

const cx = (...classes: Array<string | false | undefined>) =>
  classes.filter(Boolean).join(' ');

// Static feature card
const FeatureCard: React.FC<{
  icon: React.ReactNode;
  title: string;
  text: string;
  delay?: number;
}> = ({ icon, title, text, delay = 0 }) => {
  const { ref, inView } = useInView();
  return (
    <div
      ref={ref}
      style={{ transitionDelay: `${delay}ms` }}
      className={cx(
        'border border-[#030303] p-6 bg-transparent',
        'opacity-0 translate-y-4 transition-all duration-700',
        inView ? 'opacity-100 translate-y-0' : ''
      )}
    >
      <div className="flex items-center gap-3 mb-3">
        <div className="text-[#030303]">{icon}</div>
        <h3 className="text-[#030303] text-base font-semibold">{title}</h3>
      </div>
      <p className="text-sm text-[#030303]/80 leading-6">{text}</p>
    </div>
  );
};

// Static stat block
const Stat: React.FC<{ label: string; value: string; delay?: number }> = ({ label, value, delay = 0 }) => {
  const { ref, inView } = useInView();
  return (
    <div
      ref={ref}
      style={{ transitionDelay: `${delay}ms` }}
      className={cx(
        'border border-[#030303] p-6 bg-transparent',
        'opacity-0 translate-y-4 transition-all duration-700',
        inView ? 'opacity-100 translate-y-0' : ''
      )}
    >
      <div className="text-2xl font-semibold text-[#030303]">{value}</div>
      <div className="text-sm text-[#030303]/70 mt-1">{label}</div>
    </div>
  );
};

// Static pricing card
const PricingCard: React.FC<{
  title: string;
  price: string;
  features: string[];
  cta: string;
  highlighted?: boolean;
  delay?: number;
}> = ({ title, price, features, cta, highlighted, delay = 0 }) => {
  const { ref, inView } = useInView();
  return (
    <div
      ref={ref}
      style={{ transitionDelay: `${delay}ms` }}
      className={cx(
        'border border-[#030303] p-6 bg-transparent flex flex-col',
        'opacity-0 translate-y-4 transition-all duration-700',
        inView ? 'opacity-100 translate-y-0' : '',
        highlighted ? 'bg-[#030303] text-[#FAFAF8]' : ''
      )}
    >
      <div className="flex items-baseline justify-between">
        <h4 className={cx('text-lg font-semibold', highlighted ? 'text-[#FAFAF8]' : 'text-[#030303]')}>{title}</h4>
        <div className={cx('text-xl font-medium', highlighted ? 'text-[#FAFAF8]' : 'text-[#030303]')}>{price}</div>
      </div>
      <ul className="mt-4 space-y-2">
        {features.map((f, i) => (
          <li
            key={i}
            className={cx(
              'flex items-start gap-2 text-sm',
              highlighted ? 'text-[#FAFAF8]/90' : 'text-[#030303]/80'
            )}
          >
            <CheckCircle2
              className={cx('w-4 h-4 mt-0.5', highlighted ? 'text-[#FAFAF8]' : 'text-[#030303]')}
            />
            <span>{f}</span>
          </li>
        ))}
      </ul>
      <button
        className={cx(
          'mt-6 h-11 px-5 uppercase tracking-wide text-sm',
          highlighted
            ? 'bg-[#FAFAF8] text-[#030303] border border-[#FAFAF8]'
            : 'bg-[#030303] text-[#FAFAF8] border border-[#030303]'
        )}
        type="button"
        aria-label={cta}
      >
        {cta}
      </button>
    </div>
  );
};

// Main static landing page
const FileSecurityLanding: React.FC = () => {
  const hero = useInView();
  const trust = useInView();
  const features = useInView();
  const how = useInView();
  const pricing = useInView();
  const finalCta = useInView();

  return (
    <div className="min-h-screen" style={{ backgroundColor: '#FAFAF8' }}>
      {/* NAVBAR */}
      <header className="border-b border-[#030303]">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <ShieldCheck className="w-6 h-6 text-[#030303]" />
            <span className="text-[#030303] font-semibold tracking-wide uppercase">FileSecure</span>
          </div>
          <nav className="hidden md:flex items-center gap-8">
            <a className="text-sm text-[#030303] hover:underline" href="#features">Features</a>
            <a className="text-sm text-[#030303] hover:underline" href="#how">How it works</a>
            <a className="text-sm text-[#030303] hover:underline" href="#pricing">Pricing</a>
            <a className="text-sm text-[#030303] hover:underline" href="#contact">Contact</a>
          </nav>
          <div className="flex items-center gap-3">
            <button className="h-10 px-4 border border-[#030303] text-[#030303] uppercase tracking-wide text-sm" type="button">Sign in</button>
            <button className="h-10 px-4 bg-[#030303] text-[#FAFAF8] border border-[#030303] uppercase tracking-wide text-sm" type="button">Get started</button>
          </div>
        </div>
      </header>

      {/* HERO */}
      <section
        ref={hero.ref}
        className={cx(
          'max-w-6xl mx-auto px-6 py-20 md:py-28 grid md:grid-cols-2 gap-12',
          'opacity-0 translate-y-4 transition-all duration-700',
          hero.inView ? 'opacity-100 translate-y-0' : ''
        )}
      >
        <div>
          <h1 className="text-4xl md:text-5xl font-semibold leading-tight text-[#030303]">
            Enterprise-grade file security analysis, without the noise.
          </h1>
          <p className="mt-5 text-[#030303]/80 text-lg leading-7">
            Upload source archives and code bundles. We surface vulnerabilities, secrets, and insecure configurations before they reach production.
          </p>

          {/* Static CTA block (no actual upload functionality) */}
          <div className="mt-8">
            <div
              className={cx(
                'border border-[#030303] bg-transparent transition-colors',
                'flex flex-col items-center justify-center gap-4',
                'px-8 py-16 select-none'
              )}
              aria-label="Static upload area"
            >
              <UploadCloud className="w-10 h-10 text-[#030303]" />
              <div className="text-center">
                <p className="text-[#030303] text-lg font-medium">Drag and drop your code bundle</p>
                <p className="text-[#030303]/70 text-sm mt-1">Demo landing — uploads disabled</p>
              </div>
              <div className="flex items-center gap-3 mt-2">
                <span className="text-xs text-[#030303]/70">Supported: ZIP/TAR of repos, JS/TS, Python, Go, Java, .NET</span>
              </div>
              <button
                type="button"
                className="mt-4 px-5 h-11 bg-[#030303] text-[#FAFAF8] border border-[#030303] uppercase tracking-wide text-sm"
                aria-disabled="true"
              >
                Upload Code
              </button>
            </div>

            {/* Static placeholder list */}
            <div className="mt-4 border border-[#030303]">
              <div className="px-4 py-3 border-b border-[#030303] flex items-center justify-between">
                <span className="text-sm text-[#030303]/80">Sample repositories (preview only)</span>
                <button
                  className="h-9 px-3 bg-[#030303] text-[#FAFAF8] border border-[#030303] uppercase tracking-wide text-xs"
                  type="button"
                  aria-disabled="true"
                >
                  Start analysis
                </button>
              </div>
              <ul className="divide-y divide-[#030303]">
                {[
                  { name: 'billing-service.tar.gz', size: '12.4 MB' },
                  { name: 'frontend-app.zip', size: '6.1 MB' },
                  { name: 'infra-terraform.zip', size: '2.9 MB' },
                ].map((f) => (
                  <li key={f.name} className="px-4 py-3 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <FileText className="w-4 h-4 text-[#030303]" />
                      <span className="text-sm text-[#030303]">{f.name}</span>
                      <span className="text-xs text-[#030303]/60">{f.size}</span>
                    </div>
                    <button
                      className="h-8 px-3 border border-[#030303] text-[#030303] uppercase tracking-wide text-xs"
                      type="button"
                      aria-disabled="true"
                    >
                      Remove
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          <div className="mt-6 flex items-center gap-6 text-sm text-[#030303]/70">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-[#030303]" />
              <span>Dependency auditing</span>
            </div>
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-[#030303]" />
              <span>Secrets detection</span>
            </div>
            <div className="flex items-center gap-2">
              <ScanLine className="w-4 h-4 text-[#030303]" />
              <span>Static analysis (SAST)</span>
            </div>
          </div>
        </div>

        <div className="md:pl-8">
          <div className="border border-[#030303] p-6">
            <h2 className="text-[#030303] text-lg font-semibold">What we analyze</h2>
            <div className="grid grid-cols-2 gap-4 mt-4">
              <div className="flex items-start gap-3">
                <Code className="w-4 h-4 mt-1 text-[#030303]" />
                <p className="text-sm text-[#030303]/80">Static code analysis for common CWEs (e.g., SQLi, XSS, RCE)</p>
              </div>
              <div className="flex items-start gap-3">
                <GitBranch className="w-4 h-4 mt-1 text-[#030303]" />
                <p className="text-sm text-[#030303]/80">Dependency and SBOM auditing against known CVEs</p>
              </div>
              <div className="flex items-start gap-3">
                <KeyRound className="w-4 h-4 mt-1 text-[#030303]" />
                <p className="text-sm text-[#030303]/80">Secrets detection: API keys, tokens, credentials, certificates</p>
              </div>
              <div className="flex items-start gap-3">
                <TerminalSquare className="w-4 h-4 mt-1 text-[#030303]" />
                <p className="text-sm text-[#030303]/80">Config hardening: Dockerfiles, Helm charts, Terraform, CI pipelines</p>
              </div>
              <div className="flex items-start gap-3">
                <FileCode2 className="w-4 h-4 mt-1 text-[#030303]" />
                <p className="text-sm text-[#030303]/80">Framework best practices for JS/TS, Python, Go, Java, .NET</p>
              </div>
              <div className="flex items-start gap-3">
                <Globe className="w-4 h-4 mt-1 text-[#030303]" />
                <p className="text-sm text-[#030303]/80">Supply chain risks: typosquatting, malicious packages, license issues</p>
              </div>
            </div>
            <div className="mt-6">
              <button
                className="h-11 px-5 bg-[#030303] text-[#FAFAF8] border border-[#030303] uppercase tracking-wide text-sm"
                type="button"
                aria-disabled="true"
              >
                Analyze code
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* TRUST / STATS */}
      <section
        ref={trust.ref}
        className={cx(
          'max-w-6xl mx-auto px-6 py-12 grid md:grid-cols-4 gap-4',
          'opacity-0 translate-y-4 transition-all duration-700',
          trust.inView ? 'opacity-100 translate-y-0' : ''
        )}
      >
        <Stat label="Repos analyzed" value="84,219" delay={0} />
        <Stat label="Vulnerabilities surfaced" value="1,203,444" delay={100} />
        <Stat label="Secrets revoked" value="58,031" delay={200} />
        <Stat label="Avg. time to report" value="9.8s" delay={300} />
      </section>

      {/* FEATURES GRID (scanner capabilities) */}
      <section id="features" className="border-t border-[#030303]">
        <div
          ref={features.ref}
          className={cx(
            'max-w-6xl mx-auto px-6 py-16',
            'opacity-0 translate-y-4 transition-all duration-700',
            features.inView ? 'opacity-100 translate-y-0' : ''
          )}
        >
          <h2 className="text-2xl font-semibold text-[#030303]">Code security capabilities</h2>
          <p className="text-[#030303]/80 mt-2">Identify exploitable patterns, insecure dependencies, and leaked credentials across your codebase.</p>
          <div className="grid md:grid-cols-3 gap-4 mt-8">
            <FeatureCard
              icon={<Bug className="w-5 h-5" />}
              title="SAST findings"
              text="Detects injection, deserialization, SSRF, path traversal, and other high-impact CWEs."
              delay={0}
            />
            <FeatureCard
              icon={<GitBranch className="w-5 h-5" />}
              title="Dependency risk"
              text="Maps SBOMs and flags vulnerable or outdated packages with fix guidance."
              delay={100}
            />
            <FeatureCard
              icon={<KeyRound className="w-5 h-5" />}
              title="Secrets hygiene"
              text="Identifies hardcoded secrets and provides rotation and mitigation steps."
              delay={200}
            />
            <FeatureCard
              icon={<TerminalSquare className="w-5 h-5" />}
              title="Config security"
              text="Checks IaC and container configs for insecure defaults and privilege issues."
              delay={300}
            />
            <FeatureCard
              icon={<FileCode2 className="w-5 h-5" />}
              title="Framework guidance"
              text="Highlights framework-specific pitfalls and secure coding best practices."
              delay={400}
            />
            <FeatureCard
              icon={<Globe className="w-5 h-5" />}
              title="Supply chain"
              text="Detects malicious packages, license conflicts, and provenance anomalies."
              delay={500}
            />
          </div>
        </div>
      </section>

      {/* HOW IT WORKS */}
      <section id="how" className="border-t border-[#030303]">
        <div
          ref={how.ref}
          className={cx(
            'max-w-6xl mx-auto px-6 py-16',
            'opacity-0 translate-y-4 transition-all duration-700',
            how.inView ? 'opacity-100 translate-y-0' : ''
          )}
        >
          <h2 className="text-2xl font-semibold text-[#030303]">How it works</h2>
          <div className="grid md:grid-cols-3 gap-4 mt-8">
            <div className="border border-[#030303] p-6">
              <div className="flex items-center gap-3 mb-3">
                <UploadCloud className="w-5 h-5 text-[#030303]" />
                <h3 className="text-[#030303] font-semibold">1. Upload</h3>
              </div>
              <p className="text-sm text-[#030303]/80">Provide a repository bundle or archive. We support multi-language monorepos.</p>
            </div>
            <div className="border border-[#030303] p-6">
              <div className="flex items-center gap-3 mb-3">
                <ScanLine className="w-5 h-5 text-[#030303]" />
                <h3 className="text-[#030303] font-semibold">2. Analyze</h3>
              </div>
              <p className="text-sm text-[#030303]/80">Run static analysis, SBOM generation, and secrets scanning with policy checks.</p>
            </div>
            <div className="border border-[#030303] p-6">
              <div className="flex items-center gap-3 mb-3">
                <BarChart3 className="w-5 h-5 text-[#030303]" />
                <h3 className="text-[#030303] font-semibold">3. Report</h3>
              </div>
              <p className="text-sm text-[#030303]/80">Get prioritized findings with remediation guidance and exportable summaries.</p>
            </div>
          </div>
          <div className="mt-8">
            <button
              className="h-11 px-5 bg-[#030303] text-[#FAFAF8] border border-[#030303] uppercase tracking-wide text-sm"
              type="button"
              onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
            >
              Upload code <ChevronRight className="inline w-4 h-4 ml-1" />
            </button>
          </div>
        </div>
      </section>

      {/* PRICING */}
      <section id="pricing" className="border-t border-[#030303]">
        <div
          ref={pricing.ref}
          className={cx(
            'max-w-6xl mx-auto px-6 py-16',
            'opacity-0 translate-y-4 transition-all duration-700',
            pricing.inView ? 'opacity-100 translate-y-0' : ''
          )}
        >
          <h2 className="text-2xl font-semibold text-[#030303]">Simple, transparent options</h2>
          <p className="text-[#030303]/80 mt-2">Choose a plan or connect with a security consultant for tailored guidance.</p>
          <div className="grid md:grid-cols-3 gap-4 mt-8">
            <PricingCard
              title="Starter"
              price="$0"
              features={[
                'Up to 2 repos/day',
                'SAST essentials',
                'Secrets detection',
                'Basic SBOM',
              ]}
              cta="Get started"
              delay={0}
            />
            <PricingCard
              title="Professional"
              price="$39/mo"
              features={[
                'Unlimited repos',
                'Advanced rules & policies',
                'Dependency & license risk',
                'Exportable reports',
              ]}
              cta="Start trial"
              highlighted
              delay={100}
            />
            <PricingCard
              title="Enterprise / Consultant"
              price="Contact us"
              features={[
                'Custom policies & CI/CD',
                'SAML/SCIM & audit logs',
                'SLAs & dedicated support',
                'Expert remediation workshops',
              ]}
              cta="Talk to sales"
              delay={200}
            />
          </div>
        </div>
      </section>

      {/* FINAL CTA */}
      <section
        ref={finalCta.ref}
        className={cx(
          'border-t border-[#030303] bg-transparent',
          'opacity-0 translate-y-4 transition-all duration-700',
          finalCta.inView ? 'opacity-100 translate-y-0' : ''
        )}
      >
        <div className="max-w-6xl mx-auto px-6 py-16">
          <div className="border border-[#030303] p-8 md:flex items-center justify-between">
            <div>
              <h3 className="text-xl font-semibold text-[#030303]">Ship code with confidence.</h3>
              <p className="text-sm text-[#030303]/80 mt-2">Surface vulnerabilities early and keep secrets out of your repos.</p>
            </div>
            <div className="mt-6 md:mt-0 flex items-center gap-3">
              <button
                className="h-11 px-5 bg-[#030303] text-[#FAFAF8] border border-[#030303] uppercase tracking-wide text-sm"
                type="button"
                onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
              >
                Upload code
              </button>
              <button className="h-11 px-5 border border-[#030303] text-[#030303] uppercase tracking-wide text-sm" type="button">
                Learn more
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* FOOTER */}
      <footer id="contact" className="border-t border-[#030303]">
        <div className="max-w-6xl mx-auto px-6 py-12 grid md:grid-cols-4 gap-8">
          <div>
            <div className="flex items-center gap-3">
              <ShieldCheck className="w-5 h-5 text-[#030303]" />
              <span className="text-[#030303] font-semibold tracking-wide uppercase">FileSecure</span>
            </div>
            <p className="text-sm text-[#030303]/80 mt-3">
              Minimal, enterprise-grade code scanning to protect your software supply chain.
            </p>
          </div>
          <div>
            <h4 className="text-sm font-semibold text-[#030303]">Product</h4>
            <ul className="mt-3 space-y-2">
              <li><a className="text-sm text-[#030303]/80 hover:underline" href="#features">Features</a></li>
              <li><a className="text-sm text-[#030303]/80 hover:underline" href="#how">How it works</a></li>
              <li><a className="text-sm text-[#030303]/80 hover:underline" href="#pricing">Pricing</a></li>
            </ul>
          </div>
          <div>
            <h4 className="text-sm font-semibold text-[#030303]">Company</h4>
            <ul className="mt-3 space-y-2">
              <li><a className="text-sm text-[#030303]/80 hover:underline" href="#">About</a></li>
              <li><a className="text-sm text-[#030303]/80 hover:underline" href="#">Security</a></li>
              <li><a className="text-sm text-[#030303]/80 hover:underline" href="#">Compliance</a></li>
            </ul>
          </div>
          <div>
            <h4 className="text-sm font-semibold text-[#030303]">Contact</h4>
            <ul className="mt-3 space-y-2">
              <li className="flex items-center gap-2 text-sm text-[#030303]/80"><Mail className="w-4 h-4" /> support@filesecure.io</li>
              <li className="flex items-center gap-2 text-sm text-[#030303]/80"><Phone className="w-4 h-4" /> +1 (555) 010-2233</li>
            </ul>
          </div>
        </div>
        <div className="border-t border-[#030303]">
          <div className="max-w-6xl mx-auto px-6 py-6 text-xs text-[#030303]/70 flex items-center justify-between">
            <span>© {new Date().getFullYear()} FileSecure Inc. All rights reserved.</span>
            <div className="flex items-center gap-4">
              <a className="hover:underline" href="#">Privacy</a>
              <a className="hover:underline" href="#">Terms</a>
              <a className="hover:underline" href="#">Status</a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default FileSecurityLanding;