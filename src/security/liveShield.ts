import {
  DnsSinkholeVerdict,
  LiveShieldPolicy,
  RawShieldTelemetry,
  ShieldIntegrityCheck,
  ThreatSeverity,
} from './types';
import { analyzeUrlSafety } from './urlAnalyzer';

export const DEFAULT_LIVE_SHIELD_POLICY: LiveShieldPolicy = {
  enabled: false,
  dnsSinkholeEnabled: true,
  dgaEntropyGuard: true,
  punycodeHomographBlock: true,
  dynamicDnsC2Block: true,
  overlayTapjackShield: true,
  usbAdbWatchdog: true,
};

const DYNAMIC_DNS_C2_SUFFIXES = [
  'duckdns.org',
  'ddns.net',
  'no-ip.org',
  'no-ip.biz',
  'hopto.org',
  'zapto.org',
  'sytes.net',
  'myftp.biz',
  'myftp.org',
  'servehttp.com',
  'onion.ws',
  'tor2web.org',
];

const HIGH_RISK_EXPLOIT_TLDS = ['.zip', '.mov', '.top', '.tk', '.gq', '.ml', '.cf'];

/**
 * Computes Shannon entropy in bits per character for a DNS label to detect
 * algorithmic Domain Generation Algorithm (DGA) C2 beacons and DNS tunneling.
 */
export function calculateShannonEntropy(label: string): number {
  const clean = label.trim().toLowerCase();
  if (clean.length === 0) return 0;

  const counts = new Map<string, number>();
  for (const ch of clean) {
    counts.set(ch, (counts.get(ch) ?? 0) + 1);
  }

  let entropy = 0;
  const len = clean.length;
  for (const count of counts.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 100) / 100;
}

/**
 * Validates and normalizes either a raw hostname or an HTTP/HTTPS URL into a clean
 * lowercase DNS hostname. Returns null if empty or invalid RFC 1123 syntax.
 */
export function normalizeDomainInput(raw: string): string | null {
  const trimmed = raw.trim().toLowerCase();
  if (!trimmed) return null;

  let candidate = trimmed;
  if (trimmed.includes('://')) {
    try {
      const parsed = new URL(trimmed);
      candidate = parsed.hostname.toLowerCase();
    } catch {
      return null;
    }
  } else {
    candidate = trimmed.split('/')[0].split(':')[0];
  }

  candidate = candidate.replace(/\.$/, '');
  if (!candidate || candidate.length > 253 || !candidate.includes('.')) {
    return null;
  }

  const labels = candidate.split('.');
  for (const label of labels) {
    if (!label || label.length > 63) return null;
    if (!/^[a-z0-9-]+$/i.test(label) && !/^[^\s./:@]+$/u.test(label)) {
      return null;
    }
    if (label.startsWith('-') || label.endsWith('-')) return null;
  }

  return candidate;
}

/**
 * Evaluates an outbound DNS query hostname against Live Shield's real-time
 * sinkhole rules (Custom Blocklist, IDN Punycode Homograph, RAT Dynamic DNS C2,
 * File-Confusion TLDs, and Shannon-Entropy DGA / DNS Tunneling heuristics).
 */
export function evaluateDnsDomainThreat(
  rawDomain: string,
  policy: LiveShieldPolicy = DEFAULT_LIVE_SHIELD_POLICY,
  customBlockedDomains: string[] = []
): DnsSinkholeVerdict {
  const normalized = normalizeDomainInput(rawDomain);
  if (!normalized) {
    return {
      domain: rawDomain.trim(),
      blocked: true,
      severity: ThreatSeverity.WARNING,
      shannonEntropy: 0,
      matchedRule: 'MALFORMED_QNAME',
      reasons: ['Invalid DNS hostname syntax rejected before resolver dispatch.'],
    };
  }

  const labels = normalized.split('.');
  const primarySubdomain = labels[0] ?? '';
  const maxLabelEntropy = Math.max(...labels.slice(0, -1).map(calculateShannonEntropy), 0);
  const reasons: string[] = [];
  let severity = ThreatSeverity.NOMINAL;
  let blocked = false;
  let matchedRule = 'CLEAN_PASS';

  // 1. User-defined encrypted DNS blocklist (exact or parent domain match)
  const blockSet = new Set(customBlockedDomains.map((d) => d.trim().toLowerCase()).filter(Boolean));
  for (const entry of blockSet) {
    if (normalized === entry || normalized.endsWith(`.${entry}`)) {
      blocked = true;
      severity = ThreatSeverity.CRITICAL;
      matchedRule = 'CUSTOM_SINKHOLE_BLOCKLIST';
      reasons.push(`Domain matches encrypted user blocklist rule "${entry}" — sinkholed with NXDOMAIN.`);
      break;
    }
  }

  // 2. Punycode / IDN Homograph & Brand Impersonation analysis
  const urlCheck = analyzeUrlSafety(`https://${normalized}/`);
  if (policy.punycodeHomographBlock && (urlCheck.isPunycodeHomograph || urlCheck.impersonatedBrand)) {
    blocked = true;
    severity = ThreatSeverity.CRITICAL;
    if (matchedRule === 'CLEAN_PASS') matchedRule = 'IDN_HOMOGRAPH_OR_SPOOF';
    if (urlCheck.impersonatedBrand) {
      reasons.push(
        `Impersonates ${urlCheck.impersonatedBrand.brandDomain} via ${urlCheck.impersonatedBrand.technique}.`
      );
    } else {
      reasons.push(
        `Deceptive IDN Punycode label (${urlCheck.rawHostname} -> ${urlCheck.unicodeHostname}) blocked at DNS layer.`
      );
    }
  }

  // 3. Stalkerware & Mobile RAT Dynamic DNS C2 Infrastructure
  if (policy.dynamicDnsC2Block) {
    const matchedDdns = DYNAMIC_DNS_C2_SUFFIXES.find(
      (suffix) => normalized === suffix || normalized.endsWith(`.${suffix}`)
    );
    if (matchedDdns) {
      blocked = true;
      severity = ThreatSeverity.CRITICAL;
      if (matchedRule === 'CLEAN_PASS') matchedRule = 'RAT_DYNAMIC_DNS_C2';
      reasons.push(
        `Resolves under dynamic DNS / relay infrastructure (${matchedDdns}) frequently abused by mobile RATs (SpyNote, Cerberus, AsyncRAT).`
      );
    }
  }

  // 4. DGA (Domain Generation Algorithm) & DNS Exfiltration Tunneling Check
  const hasDigitMix = /\d/.test(primarySubdomain) && /[a-z]/.test(primarySubdomain);
  if (
    policy.dgaEntropyGuard &&
    ((primarySubdomain.length >= 16 && maxLabelEntropy >= 3.85 && hasDigitMix) ||
      (primarySubdomain.length >= 24 && maxLabelEntropy >= 3.95))
  ) {
    blocked = true;
    severity = ThreatSeverity.CRITICAL;
    if (matchedRule === 'CLEAN_PASS') matchedRule = 'DGA_HIGH_ENTROPY_BEACON';
    reasons.push(
      `High Shannon entropy (${maxLabelEntropy.toFixed(2)} bits/char across ${primarySubdomain.length}-char label) matches algorithmic C2 beacon or DNS data exfiltration.`
    );
  }

  // 5. High-risk file-confusion & phishing TLDs
  const matchedTld = HIGH_RISK_EXPLOIT_TLDS.find((tld) => normalized.endsWith(tld));
  if (matchedTld && !blocked) {
    severity = ThreatSeverity.WARNING;
    matchedRule = 'SUSPICIOUS_TLD_CAUTION';
    reasons.push(
      `Top-level domain "${matchedTld}" is heavily abused for mobile payload delivery and credential phishing.`
    );
  }

  if (reasons.length === 0) {
    reasons.push(
      `Clean ASCII QNAME (entropy ${maxLabelEntropy.toFixed(2)} bits/char) — permitted to Malware-Blocking upstream resolver (1.1.1.2 / 9.9.9.9).`
    );
  }

  return {
    domain: normalized,
    blocked,
    severity,
    shannonEntropy: maxLabelEntropy,
    matchedRule,
    reasons,
  };
}

/**
 * Evaluates live RASP (Runtime Application Self-Protection) and OS intrusion
 * telemetry into clear, zero-mock defense checks.
 */
export function evaluateIntegritySweep(telemetry: RawShieldTelemetry): ShieldIntegrityCheck[] {
  const isAndroid = telemetry.platform === 'android-native';
  const checks: ShieldIntegrityCheck[] = [];

  // 1. On-Device DNS Threat Sinkhole & Malware Resolver
  if (isAndroid) {
    checks.push({
      id: 'dns-sinkhole',
      label: 'On-Device VpnService DNS Sinkhole (tun0)',
      status: telemetry.vpnTunnelActive ? ThreatSeverity.NOMINAL : ThreatSeverity.WARNING,
      detail: telemetry.vpnTunnelActive
        ? `Active on tun0 · ${telemetry.inspectedDnsQueries} QNAMEs inspected, ${telemetry.blockedDnsQueries} malicious queries sinkholed via 1.1.1.2 / 9.9.9.9.`
        : 'Loopback DNS sinkhole is not active; arm Live Shield to intercept C2 & phishing domains on-device.',
      method: 'VpnService + Malware-Blocking DNS (1.1.1.2)',
    });
  } else {
    checks.push({
      id: 'dns-sinkhole',
      label: 'Malware-Filtering Upstream DNS Probe',
      status:
        telemetry.malwareDnsReachable === null
          ? 'Pending'
          : telemetry.malwareDnsReachable
          ? ThreatSeverity.NOMINAL
          : ThreatSeverity.WARNING,
      detail:
        telemetry.malwareDnsReachable === null
          ? 'Run Integrity Sweep or arm Live Shield to verify Cloudflare Security DNS (1.1.1.2) reachability.'
          : telemetry.malwareDnsReachable
          ? `Verified threat-blocking resolver reachability (${telemetry.malwareDnsLatencyMs ?? 0} ms round-trip).`
          : 'Threat-filtering DNS probe timed out or was blocked by local network.',
      method: 'DNS-over-UDP/HTTPS Probe (1.1.1.2)',
    });
  }

  // 2. TLS Root CA Store Integrity (MITM SSL Decryption Detection)
  if (telemetry.userRootCaCount === null) {
    checks.push({
      id: 'ca-store',
      label: 'TLS Certificate Authority Store & Transport',
      status: telemetry.secureTransportTls ? ThreatSeverity.NOMINAL : ThreatSeverity.WARNING,
      detail: telemetry.secureTransportTls
        ? 'Encrypted TLS context verified in browser; full AndroidCAStore user-CA audit runs natively on Android.'
        : 'Insecure plaintext origin detected; TLS transport protection is not active.',
      method: isAndroid ? 'KeyStore("AndroidCAStore")' : 'Window.isSecureContext',
    });
  } else if (telemetry.userRootCaCount > 0) {
    checks.push({
      id: 'ca-store',
      label: 'User-Installed TLS Root Certificates (MITM Check)',
      status: ThreatSeverity.CRITICAL,
      detail: `${telemetry.userRootCaCount} non-system Root CA(s) installed (${telemetry.userRootCaSubjects
        .slice(0, 2)
        .join('; ')}) — capable of decrypting HTTPS traffic.`,
      method: 'KeyStore("AndroidCAStore") user:* aliases',
    });
  } else {
    checks.push({
      id: 'ca-store',
      label: 'User-Installed TLS Root Certificates (MITM Check)',
      status: ThreatSeverity.NOMINAL,
      detail: 'Zero user-installed Root CAs found in AndroidCAStore; HTTPS pinning cannot be bypassed by local proxy CAs.',
      method: 'KeyStore("AndroidCAStore") user:* aliases',
    });
  }

  // 3. Dynamic Instrumentation, Debugger & Memory Hook RASP Check
  if (telemetry.fridaOrXposedDetected === null && telemetry.debuggerAttached === null) {
    checks.push({
      id: 'rasp-hooks',
      label: 'Runtime DOM & Script Injection Guard',
      status: telemetry.domInjectionCount > 0 ? ThreatSeverity.CRITICAL : ThreatSeverity.NOMINAL,
      detail:
        telemetry.domInjectionCount > 0
          ? `Detected ${telemetry.domInjectionCount} unauthorized runtime script/iframe injection attempt(s).`
          : 'Live MutationObserver active; zero unauthorized script or iframe injections observed.',
      method: 'DOM MutationObserver + CSP Integrity',
    });
  } else if (telemetry.fridaOrXposedDetected || telemetry.debuggerAttached || telemetry.rootIndicatorsFound) {
    const flags: string[] = [];
    if (telemetry.fridaOrXposedDetected) flags.push('Frida/Xposed shared library in /proc/self/maps');
    if (telemetry.debuggerAttached) flags.push('JDWP Debugger attached');
    if (telemetry.rootIndicatorsFound) flags.push('su / test-keys root indicator');
    checks.push({
      id: 'rasp-hooks',
      label: 'RASP Memory Hook & Root Tamper Detection',
      status: ThreatSeverity.CRITICAL,
      detail: `Active instrumentation or privilege tamper detected: ${flags.join(', ')}.`,
      method: '/proc/self/maps + Debug.isDebuggerConnected()',
    });
  } else {
    checks.push({
      id: 'rasp-hooks',
      label: 'RASP Memory Hook & Root Tamper Detection',
      status: ThreatSeverity.NOMINAL,
      detail: 'No Frida, LSPosed/Xposed, JDWP debugger, or su binary hooks found in process memory.',
      method: '/proc/self/maps + Debug.isDebuggerConnected()',
    });
  }

  // 4. Network Proxy & Wireless/USB ADB Exploit Surface
  if (telemetry.httpProxyHost) {
    checks.push({
      id: 'proxy-adb',
      label: 'HTTP Proxy & ADB Exploitation Surface',
      status: ThreatSeverity.CRITICAL,
      detail: `Active HTTP proxy (${telemetry.httpProxyHost}) is intercepting outbound device connections.`,
      method: 'LinkProperties.getHttpProxy()',
    });
  } else if (telemetry.wirelessAdbEnabled || telemetry.usbAdbEnabled) {
    checks.push({
      id: 'proxy-adb',
      label: 'HTTP Proxy & ADB Exploitation Surface',
      status: telemetry.wirelessAdbEnabled ? ThreatSeverity.CRITICAL : ThreatSeverity.WARNING,
      detail: telemetry.wirelessAdbEnabled
        ? 'Wireless ADB (adb_wifi_enabled) is active — exposes shell pairing over untrusted LANs.'
        : 'USB ADB debugging is enabled — vulnerable to Juice-Jacking over untrusted USB cables.',
      method: 'Settings.Global (adb_enabled / adb_wifi_enabled)',
    });
  } else {
    checks.push({
      id: 'proxy-adb',
      label: 'HTTP Proxy & ADB Exploitation Surface',
      status: isAndroid ? ThreatSeverity.NOMINAL : 'NativeOnly',
      detail: isAndroid
        ? 'Zero HTTP MITM proxies configured; both USB ADB and Wireless ADB are disabled.'
        : 'Android LinkProperties HTTP proxy and Wireless ADB sensors activate natively inside the APK.',
      method: 'ConnectivityManager + ContentObserver',
    });
  }

  // 5. Tapjacking Overlay & Accessibility Screen-Scraper Defense
  if (isAndroid) {
    const hasA11y = telemetry.enabledAccessibilityPackages.length > 0;
    checks.push({
      id: 'overlay-a11y',
      label: 'Tapjacking Overlay & Screen-Scraper Shield',
      status: hasA11y
        ? ThreatSeverity.WARNING
        : telemetry.overlayShieldActive
        ? ThreatSeverity.NOMINAL
        : ThreatSeverity.WARNING,
      detail: hasA11y
        ? `${telemetry.enabledAccessibilityPackages.length} third-party Accessibility Service(s) active (${telemetry.enabledAccessibilityPackages.join(
            ', '
          )}); Window FLAG_SECURE + setHideOverlayWindows(${telemetry.overlayShieldActive}) applied.`
        : telemetry.overlayShieldActive
        ? 'Android 12+ setHideOverlayWindows(true) and FLAG_SECURE block non-system overlays and screen capture.'
        : 'Overlay & screen-capture window hardening is currently disabled.',
      method: 'Window.setHideOverlayWindows + FLAG_SECURE',
    });
  }

  return checks;
}
