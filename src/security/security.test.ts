import test from 'node:test';
import assert from 'node:assert/strict';
import {
  BssidBaseline,
  EncryptionProtocol,
  InstalledAppPackage,
  ThreatSeverity,
  WifiAccessPoint,
} from './types';
import { auditWifiEnvironment, validateLocalGatewayAndTunnel } from './wifiInspector';
import { analyzeUrlSafety, punycodeHostnameToUnicode } from './urlAnalyzer';
import { auditInstalledPackages, evaluateDevicePosture } from './deviceAuditor';
import { EncryptedPreferencesVault, MemoryStorageAdapter } from './encryptedVault';

test('RFC 3492 Punycode decoder resolves Cyrillic homograph xn--pypal-4ve.com', () => {
  const decoded = punycodeHostnameToUnicode('xn--pypal-4ve.com');
  assert.equal(decoded, 'p\u0430ypal.com');
});

test('URL analyzer flags IDN homograph impersonation and blocks browser intent', () => {
  const res = analyzeUrlSafety('https://xn--pypal-4ve.com/signin/session-verify');
  assert.equal(res.validSyntax, true);
  assert.equal(res.isPunycodeHomograph, true);
  assert.equal(res.severity, ThreatSeverity.CRITICAL);
  assert.equal(res.verdictAction, 'BLOCK_INTENT');
  assert.equal(res.impersonatedBrand?.brandDomain, 'paypal.com');
  assert.equal(res.confusableChars.length, 1);
  assert.equal(res.confusableChars[0].codePointHex, 'U+0430');
});

test('URL analyzer catches @ userinfo credential spoofing and APK payload', () => {
  const res = analyzeUrlSafety('http://accounts.google.com@198.51.100.44/update/SystemPatch_v14.apk');
  assert.equal(res.severity, ThreatSeverity.CRITICAL);
  assert.equal(res.verdictAction, 'BLOCK_INTENT');
  assert.equal(res.dangerousPayloadExtension, '.apk');
  assert.equal(res.impersonatedBrand?.technique, 'Userinfo Credential Spoof');
});

test('URL analyzer rejects empty and malformed inputs cleanly without crash', () => {
  const emptyRes = analyzeUrlSafety('   ');
  assert.equal(emptyRes.validSyntax, false);
  assert.ok(emptyRes.errorMessage);

  const malformed = analyzeUrlSafety('not-a-valid-url');
  assert.equal(malformed.validSyntax, false);
  assert.ok(malformed.errorMessage);
});

test('URL analyzer allows clean verified HTTPS URLs', () => {
  const clean = analyzeUrlSafety('https://developer.android.com/reference/android/net/VpnService');
  assert.equal(clean.severity, ThreatSeverity.NOMINAL);
  assert.equal(clean.verdictAction, 'ALLOW_BROWSER_LAUNCH');
  assert.equal(clean.isPunycodeHomograph, false);
});

test('Wi-Fi inspector flags Evil Twin BSSID mismatch and protocol downgrade', () => {
  const baselines: BssidBaseline[] = [
    {
      ssid: 'CorpNet-ZeroTrust',
      trustedBssids: ['A4:83:E7:11:20:01'],
      expectedProtocol: EncryptionProtocol.WPA3_SAE,
      pinnedGatewayMac: 'A4:83:E7:11:20:00',
      pinnedAtIso: '2026-10-01T10:00:00Z',
    },
  ];

  const aps: WifiAccessPoint[] = [
    {
      id: 'legit-1',
      ssid: 'CorpNet-ZeroTrust',
      bssid: 'A4:83:E7:11:20:01',
      protocol: EncryptionProtocol.WPA3_SAE,
      frequencyMhz: 5180,
      rssiDbm: -54,
      channel: 36,
    },
    {
      id: 'rogue-1',
      ssid: 'CorpNet-ZeroTrust',
      bssid: '00:13:37:AA:BB:CC',
      protocol: EncryptionProtocol.OPEN,
      frequencyMhz: 2437,
      rssiDbm: -31,
      channel: 6,
      captivePortal: true,
    },
  ];

  const findings = auditWifiEnvironment(aps, baselines);
  assert.equal(findings[0].severity, ThreatSeverity.NOMINAL);
  assert.equal(findings[0].isPinnedTrusted, true);

  assert.equal(findings[1].severity, ThreatSeverity.CRITICAL);
  assert.equal(findings[1].isEvilTwinSuspect, true);
  assert.ok(findings[1].reasons.some((r) => r.includes('Protocol downgrade')));
});

test('Gateway validator detects ARP MAC mismatch against pinned baseline', () => {
  const baselines: BssidBaseline[] = [
    {
      ssid: 'CorpNet-ZeroTrust',
      trustedBssids: ['A4:83:E7:11:20:01'],
      expectedProtocol: EncryptionProtocol.WPA3_SAE,
      pinnedGatewayMac: 'A4:83:E7:11:20:00',
      pinnedAtIso: '2026-10-01T10:00:00Z',
    },
  ];

  const spoofedAp: WifiAccessPoint = {
    id: 'conn-1',
    ssid: 'CorpNet-ZeroTrust',
    bssid: 'A4:83:E7:11:20:01',
    protocol: EncryptionProtocol.WPA3_SAE,
    frequencyMhz: 5180,
    rssiDbm: -52,
    channel: 36,
    gatewayIp: '10.10.0.1',
    gatewayMac: 'DE:AD:BE:EF:99:11',
    dnsServers: ['1.1.1.1'],
    isConnected: true,
  };

  const validation = validateLocalGatewayAndTunnel(spoofedAp, true, baselines);
  assert.equal(validation.gatewayArpValid, false);
  assert.equal(validation.severity, ThreatSeverity.CRITICAL);
});

test('Device auditor flags Banking Trojan Accessibility + Overlay + SMS triad', () => {
  const packages: InstalledAppPackage[] = [
    {
      packageName: 'com.fin.invoiceviewer.helper',
      appName: 'PDF Invoice Reader',
      installerSource: 'com.chrome.downloader',
      versionName: '1.0.4',
      targetSdk: 29,
      hasLauncherIcon: false,
      enabledAccessibilityService: true,
      canDrawOverlays: true,
      permissions: [
        'android.permission.BIND_ACCESSIBILITY_SERVICE',
        'android.permission.SYSTEM_ALERT_WINDOW',
        'android.permission.RECEIVE_SMS',
      ],
    },
  ];

  const [audit] = auditInstalledPackages(packages);
  assert.equal(audit.severity, ThreatSeverity.CRITICAL);
  assert.ok(audit.threatPatterns.some((p) => p.includes('Banking Trojan')));
  assert.ok(audit.threatPatterns.some((p) => p.includes('Stealth Persistence')));
});

test('Device posture evaluator calculates OS security patch staleness accurately', () => {
  const healthy = evaluateDevicePosture(
    {
      deviceLockSecure: true,
      lockMethod: 'Biometric + PIN',
      securityPatchDate: '2026-10-05',
      playProtectEnabled: true,
      adbDebuggingEnabled: false,
      unknownSourcesAllowed: false,
      selinuxEnforcing: true,
    },
    '2026-10-23'
  );
  assert.equal(healthy.overallSeverity, ThreatSeverity.NOMINAL);
  assert.equal(healthy.patchAgeDays, 18);

  const vulnerable = evaluateDevicePosture(
    {
      deviceLockSecure: false,
      lockMethod: 'Swipe Only',
      securityPatchDate: '2025-12-01',
      playProtectEnabled: false,
      adbDebuggingEnabled: true,
      unknownSourcesAllowed: true,
      selinuxEnforcing: true,
    },
    '2026-10-23'
  );
  assert.equal(vulnerable.overallSeverity, ThreatSeverity.CRITICAL);
  assert.ok(vulnerable.patchAgeDays > 300);
});

test('EncryptedPreferencesVault encrypts values with AES-256-GCM and rejects cross-key AAD tampering', async () => {
  const mem = new MemoryStorageAdapter();
  const vault = new EncryptedPreferencesVault(mem);

  const secretPayload = { ssid: 'Home-WPA3', bssid: 'AA:BB:CC:11:22:33' };
  const record = await vault.putEncrypted('bssid_pin_1', secretPayload);

  // Raw stored JSON must NOT contain plaintext SSID or BSSID
  const rawStored = mem.getItem('bssid_pin_1') ?? '';
  assert.equal(rawStored.includes('Home-WPA3'), false);
  assert.equal(rawStored.includes('AA:BB:CC:11:22:33'), false);
  assert.ok(record.ciphertextBase64.length > 16);

  const decrypted = await vault.getDecrypted<typeof secretPayload>('bssid_pin_1');
  assert.deepEqual(decrypted, secretPayload);

  // Copying ciphertext under a different key name must fail AES-GCM AAD verification
  mem.setItem('spoofed_key_slot', rawStored);
  await assert.rejects(async () => {
    await vault.getDecrypted('spoofed_key_slot');
  });
});

test('Capacitor Android bridge maps ScanResult security capabilities to EncryptionProtocol', async () => {
  const { isRunningOnAndroidNative, mapSecurityStringToEnum } = await import('../native/aegisBridge');
  assert.equal(isRunningOnAndroidNative(), false);
  assert.equal(mapSecurityStringToEnum('WPA3-SAE'), EncryptionProtocol.WPA3_SAE);
  assert.equal(mapSecurityStringToEnum('WPA2-EAP-CCMP'), EncryptionProtocol.WPA2_ENTERPRISE);
  assert.equal(mapSecurityStringToEnum('WPA2-PSK'), EncryptionProtocol.WPA2_PSK);
  assert.equal(mapSecurityStringToEnum('WPA-TKIP'), EncryptionProtocol.WPA_TKIP);
  assert.equal(mapSecurityStringToEnum('WEP'), EncryptionProtocol.WEP);
  assert.equal(mapSecurityStringToEnum('ESS'), EncryptionProtocol.OPEN);
});

test('Live Shield Shannon entropy and domain normalization validate inputs accurately', async () => {
  const { calculateShannonEntropy, normalizeDomainInput } = await import('./liveShield');
  assert.equal(calculateShannonEntropy('aaaaaa'), 0);
  assert.ok(calculateShannonEntropy('x9f8a7k2m4n1q0p8r3t6v5w2') >= 4.0);

  assert.equal(normalizeDomainInput('  HTTPS://Api.GitHub.com:443/repos '), 'api.github.com');
  assert.equal(normalizeDomainInput(''), null);
  assert.equal(normalizeDomainInput('invalid_host_without_tld'), null);
  assert.equal(normalizeDomainInput('-badlabel.com'), null);
});

test('Live Shield DNS sinkhole blocks DGA beacons, RAT DDNS, Punycode homographs, and custom blocklist', async () => {
  const { DEFAULT_LIVE_SHIELD_POLICY, evaluateDnsDomainThreat } = await import('./liveShield');

  const clean = evaluateDnsDomainThreat('developer.android.com', DEFAULT_LIVE_SHIELD_POLICY, []);
  assert.equal(clean.blocked, false);
  assert.equal(clean.severity, ThreatSeverity.NOMINAL);
  assert.equal(clean.matchedRule, 'CLEAN_PASS');

  const customBlocked = evaluateDnsDomainThreat(
    'telemetry.stalker-tracker.net',
    DEFAULT_LIVE_SHIELD_POLICY,
    ['stalker-tracker.net']
  );
  assert.equal(customBlocked.blocked, true);
  assert.equal(customBlocked.severity, ThreatSeverity.CRITICAL);
  assert.equal(customBlocked.matchedRule, 'CUSTOM_SINKHOLE_BLOCKLIST');

  const ratDdns = evaluateDnsDomainThreat(
    'spynote-panel-09.duckdns.org',
    DEFAULT_LIVE_SHIELD_POLICY,
    []
  );
  assert.equal(ratDdns.blocked, true);
  assert.equal(ratDdns.severity, ThreatSeverity.CRITICAL);
  assert.equal(ratDdns.matchedRule, 'RAT_DYNAMIC_DNS_C2');

  const dgaBeacon = evaluateDnsDomainThreat(
    'q8w9e2r7t4y1u6i3o0p5a9s8.org',
    DEFAULT_LIVE_SHIELD_POLICY,
    []
  );
  assert.equal(dgaBeacon.blocked, true);
  assert.equal(dgaBeacon.severity, ThreatSeverity.CRITICAL);
  assert.equal(dgaBeacon.matchedRule, 'DGA_HIGH_ENTROPY_BEACON');

  const homograph = evaluateDnsDomainThreat(
    'xn--pypal-4ve.com',
    DEFAULT_LIVE_SHIELD_POLICY,
    []
  );
  assert.equal(homograph.blocked, true);
  assert.equal(homograph.severity, ThreatSeverity.CRITICAL);
  assert.equal(homograph.matchedRule, 'IDN_HOMOGRAPH_OR_SPOOF');
});

test('Live Shield RASP integrity sweep flags rogue Root CAs, Frida hooks, and Wireless ADB', async () => {
  const { evaluateIntegritySweep } = await import('./liveShield');

  const compromisedChecks = evaluateIntegritySweep({
    platform: 'android-native',
    shieldArmed: true,
    vpnTunnelActive: true,
    overlayShieldActive: true,
    secureTransportTls: true,
    malwareDnsReachable: true,
    malwareDnsLatencyMs: 18,
    userRootCaCount: 1,
    userRootCaSubjects: ['CN=MitmProxy Root CA'],
    fridaOrXposedDetected: true,
    debuggerAttached: false,
    rootIndicatorsFound: false,
    usbAdbEnabled: false,
    wirelessAdbEnabled: true,
    httpProxyHost: null,
    enabledAccessibilityPackages: ['com.stalker.keylogger'],
    domInjectionCount: 0,
    inspectedDnsQueries: 42,
    blockedDnsQueries: 3,
    lastSweepIso: '2026-10-23T18:00:00Z',
  });

  const byId = Object.fromEntries(compromisedChecks.map((c) => [c.id, c]));
  assert.equal(byId['dns-sinkhole'].status, ThreatSeverity.NOMINAL);
  assert.equal(byId['ca-store'].status, ThreatSeverity.CRITICAL);
  assert.equal(byId['rasp-hooks'].status, ThreatSeverity.CRITICAL);
  assert.equal(byId['proxy-adb'].status, ThreatSeverity.CRITICAL);
  assert.equal(byId['overlay-a11y'].status, ThreatSeverity.WARNING);
});

test('EncryptedPreferencesVault removeEntry and removeKeys purge records cleanly', async () => {
  const mem = new MemoryStorageAdapter();
  const vault = new EncryptedPreferencesVault(mem);
  await vault.putEncrypted('legacy_demo_v1', { demo: true });
  await vault.putEncrypted('keep_v2', { live: true });

  vault.removeKeys(['legacy_demo_v1']);
  assert.equal(await vault.getDecrypted('legacy_demo_v1'), null);
  assert.deepEqual(await vault.getDecrypted('keep_v2'), { live: true });

  vault.removeEntry('keep_v2');
  assert.equal(vault.inspectEncryptedEntries().length, 0);
});


