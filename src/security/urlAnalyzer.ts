import {
  ConfusableChar,
  RedirectHop,
  ThreatSeverity,
  UrlAnalysisResult,
} from './types';

const PROTECTED_BRAND_DOMAINS = [
  'google.com',
  'paypal.com',
  'apple.com',
  'microsoft.com',
  'chase.com',
  'github.com',
  'amazon.com',
  'coinbase.com',
  'netflix.com',
  'bankofamerica.com',
  'wellsfargo.com',
  'whatsapp.com',
  'instagram.com',
  'dhl.com',
  'usps.com',
];

const URL_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'is.gd',
  'rb.gy',
  'ow.ly',
  'cutt.ly',
  'rebrand.ly',
  'shorturl.at',
]);

const DANGEROUS_PAYLOAD_EXTENSIONS = new Set([
  '.apk',
  '.xapk',
  '.apks',
  '.dex',
  '.jar',
  '.exe',
  '.scr',
  '.msi',
  '.hta',
  '.bat',
  '.sh',
  '.elf',
]);

const SUSPICIOUS_TLDS = new Set(['.zip', '.mov', '.top', '.tk', '.gq', '.ml', '.cf', '.Click'.toLowerCase()]);

// Map common Cyrillic, Greek, and digit/symbol homoglyphs to Latin equivalents
const CONFUSABLE_MAP: Record<
  string,
  { latin: string; script: 'Cyrillic' | 'Greek' | 'Digit/Symbol' }
> = {
  '\u0430': { latin: 'a', script: 'Cyrillic' }, // Cyrillic small a
  '\u0435': { latin: 'e', script: 'Cyrillic' }, // Cyrillic small ie
  '\u043E': { latin: 'o', script: 'Cyrillic' }, // Cyrillic small o
  '\u0440': { latin: 'p', script: 'Cyrillic' }, // Cyrillic small er
  '\u0441': { latin: 'c', script: 'Cyrillic' }, // Cyrillic small es
  '\u0443': { latin: 'y', script: 'Cyrillic' }, // Cyrillic small u
  '\u0445': { latin: 'x', script: 'Cyrillic' }, // Cyrillic small ha
  '\u0456': { latin: 'i', script: 'Cyrillic' }, // Cyrillic small byelorussian-ukrainian i
  '\u0455': { latin: 's', script: 'Cyrillic' }, // Cyrillic small dze
  '\u04CF': { latin: 'l', script: 'Cyrillic' }, // Cyrillic small palochka
  '\u03B1': { latin: 'a', script: 'Greek' }, // Greek small alpha
  '\u03BF': { latin: 'o', script: 'Greek' }, // Greek small omicron
  '\u03C1': { latin: 'p', script: 'Greek' }, // Greek small rho
  '\u03BD': { latin: 'v', script: 'Greek' }, // Greek small nu
  '\u03B5': { latin: 'e', script: 'Greek' }, // Greek small epsilon
  '0': { latin: 'o', script: 'Digit/Symbol' },
  '1': { latin: 'l', script: 'Digit/Symbol' },
};

// RFC 3492 Bootstring Punycode decoder for `xn--` host labels
const BASE = 36;
const TMIN = 1;
const TMAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;

function adaptBias(delta: number, numPoints: number, firstTime: boolean): number {
  let d = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  d += Math.floor(d / numPoints);
  let k = 0;
  while (d > (((BASE - TMIN) * TMAX) >> 1)) {
    d = Math.floor(d / (BASE - TMIN));
    k += BASE;
  }
  return Math.floor(k + (((BASE - TMIN + 1) * d) / (d + SKEW)));
}

function decodeDigit(cp: number): number {
  if (cp - 48 < 10) return cp - 22;
  if (cp - 65 < 26) return cp - 65;
  if (cp - 97 < 26) return cp - 97;
  return BASE;
}

export function decodePunycodeLabel(label: string): string {
  const lower = label.toLowerCase();
  if (!lower.startsWith('xn--')) return label;
  const input = lower.slice(4);

  const output: number[] = [];
  const lastDelim = input.lastIndexOf('-');
  let pos = 0;

  if (lastDelim > -1) {
    for (let j = 0; j < lastDelim; j++) {
      output.push(input.charCodeAt(j));
    }
    pos = lastDelim + 1;
  }

  let n = INITIAL_N;
  let i = 0;
  let bias = INITIAL_BIAS;

  while (pos < input.length) {
    const oldi = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (pos >= input.length) return label;
      const digit = decodeDigit(input.charCodeAt(pos++));
      if (digit >= BASE) return label;
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }
    const outLen = output.length + 1;
    bias = adaptBias(i - oldi, outLen, oldi === 0);
    n += Math.floor(i / outLen);
    i %= outLen;
    output.splice(i++, 0, n);
  }

  return String.fromCodePoint(...output);
}

export function punycodeHostnameToUnicode(hostname: string): string {
  return hostname
    .split('.')
    .map((part) => decodePunycodeLabel(part))
    .join('.');
}

export function getRegistrableDomain(hostname: string): string {
  const clean = hostname.toLowerCase().replace(/\.$/, '');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(clean) || clean.includes(':')) {
    return clean;
  }
  const parts = clean.split('.');
  if (parts.length <= 2) return clean;
  const secondLast = parts[parts.length - 2];
  const last = parts[parts.length - 1];
  if (['co', 'com', 'org', 'net', 'gov', 'ac'].includes(secondLast) && last.length === 2) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

export function damerauLevenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + 1);
      }
    }
  }
  return dp[m][n];
}

function skeletonNormalize(domain: string): string {
  let out = '';
  for (const ch of domain.toLowerCase()) {
    if (CONFUSABLE_MAP[ch]) {
      out += CONFUSABLE_MAP[ch].latin;
    } else {
      out += ch;
    }
  }
  return out.replace(/rn/g, 'm');
}

// Simulated local Safe Browsing prefix hash / threat signature patterns
const KNOWN_THREAT_PATTERNS: Array<{
  pattern: RegExp;
  category: 'SOCIAL_ENGINEERING' | 'MALWARE' | 'UNWANTED_SOFTWARE';
  reason: string;
}> = [
  {
    pattern: /(signin|verify|account-update|wallet-connect|auth-session).*(login|secure|confirm|token)/i,
    category: 'SOCIAL_ENGINEERING',
    reason: 'Matches Safe Browsing SOCIAL_ENGINEERING credential-harvesting URL path signature.',
  },
  {
    pattern: /(systempatch|flashplayer|whatsapp-gold|bank-security-update)\.(apk|xapk|dex|exe)/i,
    category: 'MALWARE',
    reason: 'Matches Safe Browsing MALWARE dropper payload signature.',
  },
  {
    pattern: /(free-cleaner|battery-saver-pro|adblock-plus-mod)\.apk/i,
    category: 'UNWANTED_SOFTWARE',
    reason: 'Matches Safe Browsing UNWANTED_SOFTWARE potentially harmful application (PHA) signature.',
  },
];

export function analyzeUrlSafety(
  rawInput: string,
  hops: RedirectHop[] = [],
  resolvedFinalUrl?: string,
  expansionMode?: string
): UrlAnalysisResult {
  const trimmed = rawInput.trim();
  if (!trimmed) {
    return {
      inputUrl: rawInput,
      finalUrl: '',
      validSyntax: false,
      errorMessage: 'Enter a complete URL (for example, https://example.com) to inspect.',
      scheme: '',
      rawHostname: '',
      unicodeHostname: '',
      registrableDomain: '',
      isShortenedUrl: false,
      isPunycodeHomograph: false,
      confusableChars: [],
      severity: ThreatSeverity.NOMINAL,
      verdictAction: 'BLOCK_INTENT',
      findings: [],
      hops: [],
    };
  }

  let initialParsed: URL;
  try {
    initialParsed = new URL(trimmed);
  } catch {
    return {
      inputUrl: trimmed,
      finalUrl: trimmed,
      validSyntax: false,
      errorMessage: 'Malformed URL syntax. Include an explicit scheme such as https:// or http://.',
      scheme: '',
      rawHostname: '',
      unicodeHostname: '',
      registrableDomain: '',
      isShortenedUrl: false,
      isPunycodeHomograph: false,
      confusableChars: [],
      severity: ThreatSeverity.WARNING,
      verdictAction: 'BLOCK_INTENT',
      findings: ['URL failed RFC 3986 parsing in Intent interceptor.'],
      hops: [],
    };
  }

  const effectiveUrlStr = resolvedFinalUrl?.trim() || trimmed;
  let targetParsed: URL;
  try {
    targetParsed = new URL(effectiveUrlStr);
  } catch {
    targetParsed = initialParsed;
  }

  const findings: string[] = [];
  let severity: ThreatSeverity = ThreatSeverity.NOMINAL;
  const raise = (current: ThreatSeverity, next: ThreatSeverity): ThreatSeverity => {
    if (current === ThreatSeverity.CRITICAL || next === ThreatSeverity.CRITICAL) {
      return ThreatSeverity.CRITICAL;
    }
    if (current === ThreatSeverity.WARNING || next === ThreatSeverity.WARNING) {
      return ThreatSeverity.WARNING;
    }
    return ThreatSeverity.NOMINAL;
  };

  const scheme = targetParsed.protocol.replace(/:$/, '').toLowerCase();
  const initialRegDomain = getRegistrableDomain(initialParsed.hostname);
  const isShortenedUrl = URL_SHORTENERS.has(initialRegDomain);

  if (isShortenedUrl) {
    if (hops.length > 1 || targetParsed.hostname !== initialParsed.hostname) {
      findings.push(
        `Shortened URL (${initialParsed.hostname}) expanded across ${Math.max(
          1,
          hops.length - 1
        )} redirect hop(s) to ${targetParsed.hostname}.`
      );
    } else {
      severity = raise(severity, ThreatSeverity.WARNING);
      findings.push(
        `Shortened link service (${initialParsed.hostname}) masks true destination; inspect resolved target before launching browser.`
      );
    }
  }

  // 1. Dangerous URI schemes (XSS / local file / Android Intent URI injection)
  if (['javascript', 'data', 'vbscript', 'file', 'intent', 'content'].includes(scheme)) {
    severity = raise(severity, ThreatSeverity.CRITICAL);
    findings.push(
      `Dangerous "${scheme}:" URI scheme can trigger WebView script execution, local sandbox file exposure, or arbitrary Android Intent component hijacking.`
    );
    return {
      inputUrl: trimmed,
      finalUrl: targetParsed.toString(),
      validSyntax: true,
      scheme,
      rawHostname: targetParsed.hostname,
      unicodeHostname: targetParsed.hostname,
      registrableDomain: targetParsed.hostname,
      isShortenedUrl,
      isPunycodeHomograph: false,
      confusableChars: [],
      severity,
      verdictAction: 'BLOCK_INTENT',
      findings,
      hops,
      expansionMode,
    };
  }

  if (scheme === 'http') {
    severity = raise(severity, ThreatSeverity.WARNING);
    findings.push('Unencrypted HTTP transport allows on-path Wi-Fi attackers to inject payloads or strip cookies.');
  }

  // 2. Userinfo `@` credential spoofing check (`https://google.com@evil.example/login`)
  let impersonatedBrand: UrlAnalysisResult['impersonatedBrand'];
  if (targetParsed.username || targetParsed.password || /^https?:\/\/[^/?#]+@/i.test(targetParsed.toString())) {
    severity = raise(severity, ThreatSeverity.CRITICAL);
    const fakeAuthority = decodeURIComponent(targetParsed.username);
    findings.push(
      `Deceptive URL userinfo ("${fakeAuthority}@") disguises actual destination host "${targetParsed.hostname}".`
    );
    const matchedBrand = PROTECTED_BRAND_DOMAINS.find((b) => fakeAuthority.toLowerCase().includes(b));
    if (matchedBrand) {
      impersonatedBrand = {
        brandDomain: matchedBrand,
        editDistance: 0,
        technique: 'Userinfo Credential Spoof',
      };
    }
  }

  // 3. Raw IP address host check
  const rawHostname = targetParsed.hostname.toLowerCase();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(rawHostname) || /^0x[0-9a-f]+$/i.test(rawHostname)) {
    severity = raise(severity, ThreatSeverity.CRITICAL);
    findings.push(
      `Direct IP-literal host (${rawHostname}) bypasses domain reputation & certificate transparency norms.`
    );
  }

  // 4. Punycode & Unicode Homograph Confusable analysis
  const unicodeHostname = punycodeHostnameToUnicode(rawHostname);
  const registrableDomain = getRegistrableDomain(unicodeHostname);
  const rawRegistrable = getRegistrableDomain(rawHostname);
  const hasPunycodePrefix = rawHostname.split('.').some((l) => l.startsWith('xn--'));

  const confusableChars: ConfusableChar[] = [];
  const chars = Array.from(unicodeHostname);
  chars.forEach((ch, idx) => {
    const code = ch.codePointAt(0) ?? 0;
    const mapped = CONFUSABLE_MAP[ch];
    if (mapped && mapped.script !== 'Digit/Symbol') {
      confusableChars.push({
        index: idx,
        char: ch,
        codePointHex: `U+${code.toString(16).toUpperCase().padStart(4, '0')}`,
        script: mapped.script,
        latinLookalike: mapped.latin,
      });
    } else if (code > 127) {
      confusableChars.push({
        index: idx,
        char: ch,
        codePointHex: `U+${code.toString(16).toUpperCase().padStart(4, '0')}`,
        script: code >= 0x0400 && code <= 0x04ff ? 'Cyrillic' : code >= 0x0370 && code <= 0x03ff ? 'Greek' : 'Latin',
        latinLookalike: '?',
      });
    }
  });

  const isPunycodeHomograph = hasPunycodePrefix || confusableChars.length > 0;
  if (isPunycodeHomograph) {
    severity = raise(severity, ThreatSeverity.CRITICAL);
    findings.push(
      `IDN Punycode / non-ASCII script detected ("${rawHostname}" renders visually as "${unicodeHostname}") — high-confidence homograph vector.`
    );
  }

  // 5. Typosquatting & Brand Impersonation analysis
  if (!PROTECTED_BRAND_DOMAINS.includes(rawRegistrable)) {
    const skeletonReg = skeletonNormalize(registrableDomain);
    for (const brand of PROTECTED_BRAND_DOMAINS) {
      if (skeletonReg === brand && rawRegistrable !== brand) {
        severity = raise(severity, ThreatSeverity.CRITICAL);
        impersonatedBrand = {
          brandDomain: brand,
          editDistance: 1,
          technique: isPunycodeHomograph ? 'IDN Homograph' : 'Typosquatting',
        };
        // Highlight digit homoglyphs if ASCII lookalike (e.g., g00gle.com, paypa1.com)
        if (!isPunycodeHomograph) {
          Array.from(unicodeHostname).forEach((ch, idx) => {
            const mapped = CONFUSABLE_MAP[ch];
            if (mapped && mapped.script === 'Digit/Symbol') {
              confusableChars.push({
                index: idx,
                char: ch,
                codePointHex: `U+${(ch.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}`,
                script: 'Digit/Symbol',
                latinLookalike: mapped.latin,
              });
            }
          });
        }
        findings.push(
          `Visual homoglyph match against protected domain "${brand}" (observed "${unicodeHostname}").`
        );
        break;
      }

      const brandLabel = brand.split('.')[0];
      const regLabel = registrableDomain.split('.')[0];
      const dist = damerauLevenshtein(regLabel, brandLabel);
      if (brandLabel.length >= 5 && dist === 1) {
        severity = raise(severity, ThreatSeverity.CRITICAL);
        impersonatedBrand = {
          brandDomain: brand,
          editDistance: dist,
          technique: 'Typosquatting',
        };
        findings.push(
          `Domain label "${regLabel}" is 1 edit away from "${brand}" (Damerau-Levenshtein typosquatting).`
        );
        break;
      }

      // Subdomain masquerade: e.g., `paypal.com.verify-session.top`
      if (unicodeHostname.includes(`${brand}.`) && registrableDomain !== brand) {
        severity = raise(severity, ThreatSeverity.CRITICAL);
        impersonatedBrand = {
          brandDomain: brand,
          editDistance: 0,
          technique: 'Subdomain Masquerade',
        };
        findings.push(
          `Subdomain masquerade embeds "${brand}" as a prefix under unrelated registrable domain "${registrableDomain}".`
        );
        break;
      }
    }
  }

  // 6. Dangerous Payload Extension / Drive-by APK check
  const pathnameLower = targetParsed.pathname.toLowerCase();
  let dangerousPayloadExtension: string | undefined;
  for (const ext of DANGEROUS_PAYLOAD_EXTENSIONS) {
    if (pathnameLower.endsWith(ext)) {
      dangerousPayloadExtension = ext;
      severity = raise(severity, ThreatSeverity.CRITICAL);
      findings.push(
        `URL points directly to executable/package payload (${ext}) capable of sideloading arbitrary code.`
      );
      break;
    }
  }

  const lastHopMime = hops[hops.length - 1]?.contentType?.toLowerCase() ?? '';
  if (lastHopMime.includes('application/vnd.android.package-archive')) {
    dangerousPayloadExtension = dangerousPayloadExtension ?? '.apk';
    severity = raise(severity, ThreatSeverity.CRITICAL);
    findings.push(
      'HTTP response Content-Type is "application/vnd.android.package-archive" (Android APK binary stream).'
    );
  }

  // 7. Suspicious TLD & excessive subdomain depth
  for (const tld of SUSPICIOUS_TLDS) {
    if (rawHostname.endsWith(tld)) {
      severity = raise(severity, ThreatSeverity.WARNING);
      findings.push(
        `Top-level domain "${tld}" is frequently abused in file-name confusion and credential phishing campaigns.`
      );
      break;
    }
  }

  const subdomainCount = rawHostname.split('.').length - 2;
  if (subdomainCount >= 3) {
    severity = raise(severity, ThreatSeverity.WARNING);
    findings.push(
      `Deep subdomain nesting (${subdomainCount} levels) often conceals the registrable domain on narrow mobile address bars.`
    );
  }

  // 8. Local Threat Feed / Safe Browsing v4 signature evaluation
  let safeBrowsingCategory: UrlAnalysisResult['safeBrowsingCategory'];
  const fullNormalizedUrl = `${unicodeHostname}${targetParsed.pathname}${targetParsed.search}`;
  for (const sig of KNOWN_THREAT_PATTERNS) {
    if (sig.pattern.test(fullNormalizedUrl)) {
      safeBrowsingCategory = sig.category;
      severity = raise(severity, ThreatSeverity.CRITICAL);
      findings.push(sig.reason);
      break;
    }
  }

  if (findings.length === 0) {
    findings.push(
      `Verified HTTPS destination on "${registrableDomain}" with ASCII-clean labels, no homograph confusables, and clean Safe Browsing status.`
    );
  }

  const verdictAction: UrlAnalysisResult['verdictAction'] =
    severity === ThreatSeverity.CRITICAL
      ? 'BLOCK_INTENT'
      : severity === ThreatSeverity.WARNING
      ? 'QUARANTINE_WARNING'
      : 'ALLOW_BROWSER_LAUNCH';

  return {
    inputUrl: trimmed,
    finalUrl: targetParsed.toString(),
    validSyntax: true,
    scheme,
    rawHostname,
    unicodeHostname,
    registrableDomain,
    isShortenedUrl,
    isPunycodeHomograph,
    confusableChars,
    impersonatedBrand,
    dangerousPayloadExtension,
    safeBrowsingCategory,
    severity,
    verdictAction,
    findings,
    hops,
    expansionMode,
  };
}
