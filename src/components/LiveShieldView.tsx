import React, { useMemo, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  Loader2,
  RefreshCw,
  ShieldAlert,
  ShieldBan,
  ShieldCheck,
  ShieldOff,
  Trash2,
} from 'lucide-react';
import {
  DnsSinkholeVerdict,
  IntrusionEvent,
  LiveShieldPolicy,
  RawShieldTelemetry,
  ThreatSeverity,
} from '../security/types';
import {
  evaluateDnsDomainThreat,
  evaluateIntegritySweep,
  normalizeDomainInput,
} from '../security/liveShield';

interface LiveShieldViewProps {
  policy: LiveShieldPolicy;
  telemetry: RawShieldTelemetry;
  events: IntrusionEvent[];
  customBlockedDomains: string[];
  isSweeping: boolean;
  onToggleShieldArmed: () => void;
  onUpdatePolicy: (nextPolicy: LiveShieldPolicy) => void;
  onRunIntegritySweep: () => void;
  onAddBlockedDomain: (domain: string) => void;
  onRemoveBlockedDomain: (domain: string) => void;
  onRecordEvaluatedBlock: (verdict: DnsSinkholeVerdict) => void;
  onClearEvents: () => void;
}

const POLICY_CONTROLS: Array<{
  key: keyof Omit<LiveShieldPolicy, 'enabled'>;
  title: string;
  description: string;
  apiMechanism: string;
}> = [
  {
    key: 'dnsSinkholeEnabled',
    title: 'On-Device DNS Threat Sinkhole & Malware Resolver',
    description:
      'Routes DNS locally on tun0 (10.215.173.1/30) and resolves clean queries through Cloudflare Security (1.1.1.2) and Quad9 (9.9.9.9) without external VPN tunneling.',
    apiMechanism: 'VpnService + 1.1.1.2 / 9.9.9.9',
  },
  {
    key: 'dgaEntropyGuard',
    title: 'Shannon-Entropy DGA & DNS Exfiltration Blocker',
    description:
      'Calculates per-label Shannon entropy in real time to sinkhole algorithmic C2 beacons and covert DNS data exfiltration.',
    apiMechanism: 'H(X) >= 3.85 bits/char Filter',
  },
  {
    key: 'punycodeHomographBlock',
    title: 'IDN Punycode Homograph Sinkhole',
    description:
      'Blocks deceptive xn-- Cyrillic/Greek lookalike domains at the DNS layer before any app or WebView socket connects.',
    apiMechanism: 'RFC 3492 + Skeleton Confusable Trap',
  },
  {
    key: 'dynamicDnsC2Block',
    title: 'Mobile RAT Dynamic DNS C2 Blocker',
    description:
      'Sinkholes dynamic DNS relay domains commonly used by SpyNote, Cerberus, and stalkerware command-and-control servers.',
    apiMechanism: 'DDNS C2 Suffix Sinkhole',
  },
  {
    key: 'overlayTapjackShield',
    title: 'Tapjacking Overlay & Screen-Capture Hardening',
    description:
      'Enforces Android 12+ SurfaceFlinger non-system overlay blocking and Window FLAG_SECURE against screen-scraping trojans.',
    apiMechanism: 'Window.setHideOverlayWindows + FLAG_SECURE',
  },
  {
    key: 'usbAdbWatchdog',
    title: 'USB Juice-Jacking & Wireless ADB Watchdog',
    description:
      'Monitors physical USB attachment while ADB is active and watches Settings.Global for unauthorized Wireless ADB (adb_wifi_enabled) activation.',
    apiMechanism: 'BroadcastReceiver + ContentObserver',
  },
];

export function LiveShieldView({
  policy,
  telemetry,
  events,
  customBlockedDomains,
  isSweeping,
  onToggleShieldArmed,
  onUpdatePolicy,
  onRunIntegritySweep,
  onAddBlockedDomain,
  onRemoveBlockedDomain,
  onRecordEvaluatedBlock,
  onClearEvents,
}: LiveShieldViewProps) {
  const [domainProbeInput, setDomainProbeInput] = useState('');
  const [probeError, setProbeError] = useState<string | null>(null);
  const [probeVerdict, setProbeVerdict] = useState<DnsSinkholeVerdict | null>(null);

  const [blocklistInput, setBlocklistInput] = useState('');
  const [blocklistError, setBlocklistError] = useState<string | null>(null);

  const integrityChecks = useMemo(() => evaluateIntegritySweep(telemetry), [telemetry]);

  const activeDefenseCount = useMemo(() => {
    return POLICY_CONTROLS.filter((item) => policy[item.key]).length;
  }, [policy]);

  const criticalEventCount = useMemo(
    () => events.filter((e) => e.severity === ThreatSeverity.CRITICAL).length,
    [events]
  );

  const handleEvaluateDomain = (e: React.FormEvent) => {
    e.preventDefault();
    const normalized = normalizeDomainInput(domainProbeInput);
    if (!normalized) {
      setProbeError('Enter a valid domain or URL (for example, login.example.com) to evaluate.');
      setProbeVerdict(null);
      return;
    }
    setProbeError(null);
    const verdict = evaluateDnsDomainThreat(normalized, policy, customBlockedDomains);
    setProbeVerdict(verdict);
    if (verdict.blocked) {
      onRecordEvaluatedBlock(verdict);
    }
  };

  const handleAddBlocklistSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const normalized = normalizeDomainInput(blocklistInput);
    if (!normalized) {
      setBlocklistError('Enter a valid hostname (for example, telemetry-c2.example.net) to block.');
      return;
    }
    setBlocklistError(null);
    onAddBlockedDomain(normalized);
    setBlocklistInput('');
    if (probeVerdict && (probeVerdict.domain === normalized || probeVerdict.domain.endsWith(`.${normalized}`))) {
      setProbeVerdict(
        evaluateDnsDomainThreat(probeVerdict.domain, policy, [...customBlockedDomains, normalized])
      );
    }
  };

  const renderCheckStatus = (status: ThreatSeverity | 'Pending' | 'NativeOnly') => {
    if (status === ThreatSeverity.CRITICAL) {
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-red-700 whitespace-nowrap">
          <ShieldAlert className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
          <span>Critical</span>
        </span>
      );
    }
    if (status === ThreatSeverity.WARNING) {
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-amber-700 whitespace-nowrap">
          <AlertTriangle className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
          <span>Warning</span>
        </span>
      );
    }
    if (status === 'Pending') {
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-500 whitespace-nowrap">
          <Clock className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
          <span>Awaiting Sweep</span>
        </span>
      );
    }
    if (status === 'NativeOnly') {
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-500 whitespace-nowrap">
          <Clock className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
          <span>Android APK Sensor</span>
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-700 whitespace-nowrap">
        <CheckCircle2 className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
        <span>Nominal</span>
      </span>
    );
  };

  return (
    <div className="space-y-8">
      {/* Header & Primary Arm/Sweep Controls */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
        <div className="space-y-1.5 max-w-2xl">
          <p className="text-xs font-medium text-slate-500">
            Real-Time Intrusion Prevention · RASP Memory &amp; CA Audit · On-Device DNS Sinkhole
          </p>
          <h1
            className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-950"
            style={{ textWrap: 'balance' }}
          >
            Live Shield Anti-Intrusion &amp; Anti-Hacking Guard
          </h1>
          <p className="text-sm text-slate-600 leading-relaxed">
            Monitors active network interfaces, TLS Root CA stores, process memory maps, Wireless ADB state, sideloaded package installations, and outbound DNS queries in real time without routing traffic to external servers.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <button
            type="button"
            onClick={onRunIntegritySweep}
            disabled={isSweeping}
            className="inline-flex items-center gap-2 px-3.5 py-2 min-h-[42px] text-xs font-medium text-slate-800 bg-white border border-slate-300 rounded-lg hover:bg-slate-50 disabled:opacity-60 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            {isSweeping ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin shrink-0" aria-hidden="true" />
            ) : (
              <RefreshCw className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
            )}
            <span>{isSweeping ? 'Sweeping…' : 'Run Integrity Sweep'}</span>
          </button>

          <button
            type="button"
            onClick={onToggleShieldArmed}
            aria-pressed={telemetry.shieldArmed}
            className={`inline-flex items-center gap-2 px-4 py-2 min-h-[42px] text-xs font-semibold rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              telemetry.shieldArmed
                ? 'bg-slate-900 text-white hover:bg-slate-800'
                : 'bg-blue-600 text-white hover:bg-blue-700'
            }`}
          >
            {telemetry.shieldArmed ? (
              <>
                <ShieldOff className="w-4 h-4 shrink-0" aria-hidden="true" />
                <span>Pause Live Shield</span>
              </>
            ) : (
              <>
                <ShieldCheck className="w-4 h-4 shrink-0" aria-hidden="true" />
                <span>Enable Live Shield</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Live Telemetry Summary Strip */}
      <section
        aria-label="Live Shield Status Overview"
        className="bg-white border border-slate-200 rounded-xl overflow-hidden"
      >
        <div className="grid grid-cols-2 lg:grid-cols-4">
          <div className="p-5 border-b border-r border-slate-200 lg:border-b-0">
            <p className="text-xs text-slate-500">Protection State</p>
            <div className="mt-1.5 flex items-center gap-2">
              {telemetry.shieldArmed ? (
                <ShieldCheck className="w-5 h-5 text-emerald-700 shrink-0" aria-hidden="true" />
              ) : (
                <ShieldOff className="w-5 h-5 text-slate-400 shrink-0" aria-hidden="true" />
              )}
              <span className="text-xl font-bold text-slate-950">
                {telemetry.shieldArmed ? 'Armed' : 'Standby'}
              </span>
            </div>
            <p className="mt-1 text-xs text-slate-500">
              {telemetry.platform === 'android-native'
                ? 'Android OS Sensors + tun0'
                : 'Browser Transport + DNS Probe'}
            </p>
          </div>

          <div className="p-5 border-b border-slate-200 lg:border-b-0 lg:border-r">
            <p className="text-xs text-slate-500">DNS Queries Inspected / Sinkholed</p>
            <p className="mt-1 text-2xl font-bold text-slate-950 font-mono tabular-nums">
              {telemetry.inspectedDnsQueries} / {telemetry.blockedDnsQueries}
            </p>
            <p className="mt-1 text-xs text-slate-500 font-mono tabular-nums">
              Upstream 1.1.1.2 · 9.9.9.9
            </p>
          </div>

          <div className="p-5 border-r border-slate-200">
            <p className="text-xs text-slate-500">Active Defense Modules</p>
            <p className="mt-1 text-2xl font-bold text-slate-950 font-mono tabular-nums">
              {activeDefenseCount} / {POLICY_CONTROLS.length}
            </p>
            <p className="mt-1 text-xs text-slate-500">
              {customBlockedDomains.length} custom blocked domain(s)
            </p>
          </div>

          <div className="p-5">
            <p className="text-xs text-slate-500">Recorded Intrusion Alerts</p>
            <p
              className={`mt-1 text-2xl font-bold font-mono tabular-nums ${
                criticalEventCount > 0 ? 'text-red-700' : 'text-slate-950'
              }`}
            >
              {events.length}
            </p>
            <p className="mt-1 text-xs text-slate-500 font-mono tabular-nums">
              {telemetry.lastSweepIso
                ? `Last sweep ${telemetry.lastSweepIso.slice(11, 19)}Z`
                : 'No sweep run yet'}
            </p>
          </div>
        </div>
      </section>

      {/* Live RASP & OS Anti-Hacking Integrity Checks */}
      <section
        aria-label="Live RASP and Anti-Hacking Integrity Sweep"
        className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-200"
      >
        <div className="p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h2 className="text-base font-bold text-slate-950">
              Runtime Intrusion &amp; Tamper Surface Verification
            </h2>
            <p className="mt-0.5 text-xs text-slate-600">
              Live checks against rogue MITM Root CAs, Frida/Xposed memory injection, HTTP proxy hijacking, Wireless ADB, and overlay tapjacking.
            </p>
          </div>
          <span className="text-xs font-mono text-slate-500 tabular-nums shrink-0">
            {integrityChecks.length} active surface checks
          </span>
        </div>

        <div className="divide-y divide-slate-200">
          {integrityChecks.map((check) => (
            <div
              key={check.id}
              className="p-4 px-5 flex flex-col md:flex-row md:items-center justify-between gap-2 text-sm"
            >
              <div className="space-y-0.5 max-w-3xl">
                <div className="font-semibold text-slate-950">{check.label}</div>
                <p className="text-xs text-slate-600 leading-relaxed">{check.detail}</p>
              </div>
              <div className="flex items-center gap-4 shrink-0">
                <span className="text-xs font-mono text-slate-400">{check.method}</span>
                {renderCheckStatus(check.status)}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Active Defense Layer Policy Switches */}
      <section
        aria-label="Live Shield Protection Policy Modules"
        className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-200"
      >
        <div className="p-5">
          <h2 className="text-base font-bold text-slate-950">
            Real-Time Defense Policy Configuration
          </h2>
          <p className="mt-0.5 text-xs text-slate-600">
            Configure which kernel, window, and network sinkhole guards enforce protection while Live Shield is armed. Settings persist in AES-256-GCM encrypted storage.
          </p>
        </div>

        <div className="divide-y divide-slate-200">
          {POLICY_CONTROLS.map((ctrl) => {
            const checked = policy[ctrl.key];
            return (
              <div
                key={ctrl.key}
                className="p-4 px-5 flex items-center justify-between gap-4"
              >
                <div className="space-y-0.5 max-w-3xl">
                  <div className="text-sm font-semibold text-slate-950">{ctrl.title}</div>
                  <p className="text-xs text-slate-600 leading-relaxed">{ctrl.description}</p>
                  <p className="text-[11px] font-mono text-slate-400 pt-0.5">{ctrl.apiMechanism}</p>
                </div>

                <button
                  type="button"
                  role="switch"
                  aria-checked={checked}
                  aria-label={`Toggle ${ctrl.title}`}
                  onClick={() =>
                    onUpdatePolicy({
                      ...policy,
                      [ctrl.key]: !checked,
                    })
                  }
                  className={`min-h-[44px] min-w-[76px] px-3 py-2 text-xs font-semibold rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    checked
                      ? 'bg-slate-900 text-white hover:bg-slate-800'
                      : 'bg-slate-100 text-slate-700 hover:bg-slate-200'
                  }`}
                >
                  {checked ? 'Enabled' : 'Disabled'}
                </button>
              </div>
            );
          })}
        </div>
      </section>

      {/* Two-Column Split: Live DNS Threat Evaluator + Custom Encrypted Blocklist */}
      <section
        aria-label="DNS Threat Sinkhole Inspector and Custom Blocklist"
        className="bg-white border border-slate-200 rounded-xl grid grid-cols-1 lg:grid-cols-12 divide-y lg:divide-y-0 lg:divide-x divide-slate-200"
      >
        {/* Left 7 Columns: Live DNS QNAME & C2 Entropy Evaluator */}
        <div className="lg:col-span-7 p-5 sm:p-6 space-y-4">
          <div>
            <h2 className="text-base font-bold text-slate-950">
              Live DNS QNAME &amp; C2 Entropy Evaluator
            </h2>
            <p className="mt-0.5 text-xs text-slate-600">
              Test any outbound domain or hostname against the active tun0 DNS sinkhole rules (Shannon DGA entropy, Punycode homographs, RAT dynamic DNS, and custom blocklist).
            </p>
          </div>

          <form onSubmit={handleEvaluateDomain} className="space-y-2">
            <label htmlFor="shield-domain-input" className="block text-xs font-semibold text-slate-700">
              Target Hostname or URL
            </label>
            <div className="flex flex-col sm:flex-row gap-2.5">
              <input
                id="shield-domain-input"
                type="text"
                value={domainProbeInput}
                onChange={(e) => setDomainProbeInput(e.target.value)}
                placeholder="Enter hostname (e.g. login.example.com)"
                className="flex-1 h-11 px-3.5 text-sm font-mono bg-slate-50 border border-slate-300 rounded-lg text-slate-950 placeholder:text-slate-400 focus:outline-none focus:bg-white focus:border-blue-600"
              />
              <button
                type="submit"
                className="px-4 h-11 text-xs font-semibold text-white bg-blue-600 rounded-lg hover:bg-blue-700 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                Evaluate Hostname
              </button>
            </div>
            {probeError && (
              <p role="alert" className="text-xs font-medium text-red-700">
                {probeError}
              </p>
            )}
          </form>

          {probeVerdict ? (
            <div className="pt-2 border-t border-slate-200 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="font-mono text-sm font-semibold text-slate-950 break-all">
                  {probeVerdict.domain}
                </div>
                {probeVerdict.blocked ? (
                  <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-red-700">
                    <ShieldBan className="w-4 h-4 shrink-0" aria-hidden="true" />
                    <span>Sinkholed (NXDOMAIN)</span>
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-700">
                    <CheckCircle2 className="w-4 h-4 shrink-0" aria-hidden="true" />
                    <span>Permitted to 1.1.1.2</span>
                  </span>
                )}
              </div>

              <div className="text-xs text-slate-500 font-mono tabular-nums">
                Max Subdomain Entropy: {probeVerdict.shannonEntropy.toFixed(2)} bits/char · Rule:{' '}
                {probeVerdict.matchedRule}
              </div>

              <ul className="space-y-1 text-xs text-slate-700 list-disc pl-4">
                {probeVerdict.reasons.map((r, idx) => (
                  <li key={idx}>{r}</li>
                ))}
              </ul>

              {!customBlockedDomains.includes(probeVerdict.domain) && (
                <div>
                  <button
                    type="button"
                    onClick={() => {
                      onAddBlockedDomain(probeVerdict.domain);
                      setProbeVerdict(
                        evaluateDnsDomainThreat(probeVerdict.domain, policy, [
                          ...customBlockedDomains,
                          probeVerdict.domain,
                        ])
                      );
                    }}
                    className="px-3.5 py-2 min-h-[38px] text-xs font-semibold text-slate-900 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors whitespace-nowrap cursor-pointer"
                  >
                    Add {probeVerdict.domain} to Sinkhole Blocklist
                  </button>
                </div>
              )}
            </div>
          ) : (
            <p className="text-xs text-slate-500 pt-1">
              Enter any domain above to inspect its Shannon entropy, IDN script safety, and C2 sinkhole disposition.
            </p>
          )}
        </div>

        {/* Right 5 Columns: Custom Encrypted DNS Sinkhole Blocklist */}
        <div className="lg:col-span-5 p-5 sm:p-6 bg-slate-50/50 space-y-4">
          <div>
            <h2 className="text-base font-bold text-slate-950">
              Custom DNS Sinkhole Blocklist
            </h2>
            <p className="mt-0.5 text-xs text-slate-600">
              Exact and subdomain matches return immediate NXDOMAIN inside LocalLoopbackVpnService.
            </p>
          </div>

          <form onSubmit={handleAddBlocklistSubmit} className="space-y-2">
            <label htmlFor="custom-blocklist-input" className="block text-xs font-semibold text-slate-700">
              Block Domain &amp; Subdomains
            </label>
            <div className="flex gap-2">
              <input
                id="custom-blocklist-input"
                type="text"
                value={blocklistInput}
                onChange={(e) => setBlocklistInput(e.target.value)}
                placeholder="tracker-host.net"
                className="flex-1 h-10 px-3 text-xs font-mono bg-white border border-slate-300 rounded-lg text-slate-950 placeholder:text-slate-400 focus:outline-none focus:border-blue-600"
              />
              <button
                type="submit"
                className="px-3.5 h-10 text-xs font-semibold text-white bg-slate-900 rounded-lg hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                Block Domain
              </button>
            </div>
            {blocklistError && (
              <p role="alert" className="text-xs font-medium text-red-700">
                {blocklistError}
              </p>
            )}
          </form>

          {customBlockedDomains.length === 0 ? (
            <div className="py-6 text-center space-y-1">
              <p className="text-xs font-medium text-slate-700">No custom domains blocked yet</p>
              <p className="text-xs text-slate-500">
                Add domains above to enforce immediate on-device NXDOMAIN sinkholing.
              </p>
            </div>
          ) : (
            <ul className="divide-y divide-slate-200 border-t border-slate-200 text-xs">
              {customBlockedDomains.map((dom) => (
                <li key={dom} className="py-2.5 flex items-center justify-between gap-2">
                  <span className="font-mono text-slate-900 break-all">{dom}</span>
                  <button
                    type="button"
                    onClick={() => onRemoveBlockedDomain(dom)}
                    aria-label={`Remove ${dom} from blocklist`}
                    className="inline-flex items-center gap-1 px-2.5 py-1.5 min-h-[34px] text-xs font-medium text-slate-600 hover:text-red-700 cursor-pointer shrink-0"
                  >
                    <Trash2 className="w-3.5 h-3.5" aria-hidden="true" />
                    <span>Remove</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

      {/* Real-Time Intrusion Event Log */}
      <section
        aria-label="Real-Time Intrusion Event Log"
        className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-200"
      >
        <div className="p-5 flex items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-bold text-slate-950">
              Real-Time Intrusion &amp; Sinkhole Event Log
            </h2>
            <p className="mt-0.5 text-xs text-slate-600">
              Live security events captured from OS network callbacks, APK installation receivers, ADB observers, and DNS sinkhole blocks.
            </p>
          </div>
          {events.length > 0 && (
            <button
              type="button"
              onClick={onClearEvents}
              className="px-3 py-1.5 min-h-[36px] text-xs font-medium text-slate-600 bg-slate-100 hover:bg-slate-200 hover:text-slate-900 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              Clear Log
            </button>
          )}
        </div>

        {events.length === 0 ? (
          <div className="p-10 text-center space-y-2">
            <ShieldCheck className="w-6 h-6 text-slate-400 mx-auto" aria-hidden="true" />
            <p className="text-sm font-medium text-slate-900">Zero intrusion alerts recorded</p>
            <p className="text-xs text-slate-500 max-w-md mx-auto">
              Real-time alerts appear here automatically if a malicious DNS query, rogue HTTP proxy, Wireless ADB toggle, or high-risk sideloaded APK is detected.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-slate-200">
            {events.map((evt) => (
              <div
                key={evt.id}
                className="p-4 px-5 flex flex-col sm:flex-row sm:items-start justify-between gap-2 text-xs"
              >
                <div className="space-y-1 max-w-3xl">
                  <div className="flex flex-wrap items-center gap-2">
                    {renderCheckStatus(evt.severity)}
                    <span className="font-semibold text-slate-950 text-sm">{evt.title}</span>
                    <span className="text-slate-400">·</span>
                    <span className="font-mono text-slate-500">{evt.surface}</span>
                  </div>
                  <p className="text-slate-600 leading-relaxed">{evt.detail}</p>
                  {evt.indicator && (
                    <p className="font-mono text-slate-800">Indicator: {evt.indicator}</p>
                  )}
                </div>
                <span className="font-mono text-slate-400 tabular-nums shrink-0">
                  {evt.timestampIso.slice(0, 19).replace('T', ' ')}Z
                </span>
              </div>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
