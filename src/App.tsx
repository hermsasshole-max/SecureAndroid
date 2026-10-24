/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useCallback, useEffect, useMemo, useState } from 'react';
import { TopNav, WorkspaceTab } from './components/TopNav';
import { LiveShieldView } from './components/LiveShieldView';
import { WifiInspectorView } from './components/WifiInspectorView';
import { LinkAnalyzerView } from './components/LinkAnalyzerView';
import { DeviceAuditorView } from './components/DeviceAuditorView';
import { AndroidBlueprintView } from './components/AndroidBlueprintView';
import {
  BssidBaseline,
  DeviceHealthState,
  DnsSinkholeVerdict,
  EncryptedVaultEntry,
  InstalledAppPackage,
  IntrusionEvent,
  LiveShieldPolicy,
  RawShieldTelemetry,
  ThreatSeverity,
  UrlAnalysisResult,
  WifiAccessPoint,
} from './security/types';
import {
  BrowserLocalStorageAdapter,
  EncryptedPreferencesVault,
} from './security/encryptedVault';
import { DEFAULT_LIVE_SHIELD_POLICY, normalizeDomainInput } from './security/liveShield';
import { ARCHITECTURE_LAYERS, BLUEPRINT_FILES } from './data/androidBlueprints';
import {
  AegisSecurityNative,
  NativeLiveShieldSnapshot,
  isRunningOnAndroidNative,
  mapSecurityStringToEnum,
} from './native/aegisBridge';

const VAULT_KEYS = {
  WIFI_BASELINES: 'wifi_bssid_baselines_v2',
  URL_HISTORY: 'url_audit_history_v2',
  SHIELD_POLICY: 'live_shield_policy_v2',
  SHIELD_BLOCKLIST: 'live_shield_blocklist_v2',
  SHIELD_EVENTS: 'live_shield_events_v2',
} as const;

const LEGACY_DEMO_KEYS = [
  'wifi_bssid_baselines_v1',
  'device_posture_state_v1',
  'url_audit_history_v1',
];

function getInitialTabFromQuery(): WorkspaceTab {
  if (typeof window === 'undefined') return 'shield';
  const params = new URLSearchParams(window.location.search);
  const tab = params.get('tab');
  if (
    tab === 'shield' ||
    tab === 'wifi' ||
    tab === 'links' ||
    tab === 'device' ||
    tab === 'blueprint'
  ) {
    return tab;
  }
  return 'shield';
}

function createInitialShieldTelemetry(): RawShieldTelemetry {
  const isAndroid = isRunningOnAndroidNative();
  return {
    platform: isAndroid ? 'android-native' : 'web-browser',
    shieldArmed: false,
    vpnTunnelActive: false,
    overlayShieldActive: false,
    secureTransportTls: typeof window !== 'undefined' ? Boolean(window.isSecureContext) : true,
    malwareDnsReachable: null,
    malwareDnsLatencyMs: null,
    userRootCaCount: null,
    userRootCaSubjects: [],
    fridaOrXposedDetected: null,
    debuggerAttached: null,
    rootIndicatorsFound: null,
    usbAdbEnabled: null,
    wirelessAdbEnabled: null,
    httpProxyHost: null,
    enabledAccessibilityPackages: [],
    domInjectionCount: 0,
    inspectedDnsQueries: 0,
    blockedDnsQueries: 0,
    lastSweepIso: null,
  };
}

function mapNativeSnapshotToTelemetry(snapshot: NativeLiveShieldSnapshot): RawShieldTelemetry {
  return {
    platform: 'android-native',
    shieldArmed: snapshot.shieldArmed,
    vpnTunnelActive: snapshot.vpnTunnelActive,
    overlayShieldActive: snapshot.overlayShieldActive,
    secureTransportTls: true,
    malwareDnsReachable: snapshot.vpnTunnelActive ? true : null,
    malwareDnsLatencyMs: null,
    userRootCaCount: snapshot.userRootCaCount,
    userRootCaSubjects: snapshot.userRootCaSubjects ?? [],
    fridaOrXposedDetected: snapshot.fridaOrXposedDetected,
    debuggerAttached: snapshot.debuggerAttached,
    rootIndicatorsFound: snapshot.rootIndicatorsFound,
    usbAdbEnabled: snapshot.usbAdbEnabled,
    wirelessAdbEnabled: snapshot.wirelessAdbEnabled,
    httpProxyHost: snapshot.httpProxyHost ?? null,
    enabledAccessibilityPackages: snapshot.enabledAccessibilityPackages ?? [],
    domInjectionCount: 0,
    inspectedDnsQueries: snapshot.inspectedDnsQueries ?? 0,
    blockedDnsQueries: snapshot.blockedDnsQueries ?? 0,
    lastSweepIso: snapshot.checkedAtIso ?? new Date().toISOString(),
  };
}

export default function App() {
  const [activeTab, setActiveTab] = useState<WorkspaceTab>(getInitialTabFromQuery);

  // Zero demo/seed data: all states start empty or null until populated by real OS scans or user input
  const [accessPoints, setAccessPoints] = useState<WifiAccessPoint[]>([]);
  const [baselines, setBaselines] = useState<BssidBaseline[]>([]);
  const [vpnLoopbackActive, setVpnLoopbackActive] = useState<boolean>(false);
  const [isScanningWifi, setIsScanningWifi] = useState<boolean>(false);
  const [wifiScanMessage, setWifiScanMessage] = useState<string | null>(null);

  const [recentUrlAnalyses, setRecentUrlAnalyses] = useState<UrlAnalysisResult[]>([]);
  const [packages, setPackages] = useState<InstalledAppPackage[]>([]);
  const [deviceHealth, setDeviceHealth] = useState<DeviceHealthState | null>(null);
  const [isAuditingDevice, setIsAuditingDevice] = useState<boolean>(false);
  const [deviceAuditMessage, setDeviceAuditMessage] = useState<string | null>(null);

  const [shieldPolicy, setShieldPolicy] = useState<LiveShieldPolicy>(DEFAULT_LIVE_SHIELD_POLICY);
  const [shieldTelemetry, setShieldTelemetry] = useState<RawShieldTelemetry>(
    createInitialShieldTelemetry
  );
  const [shieldEvents, setShieldEvents] = useState<IntrusionEvent[]>([]);
  const [customBlockedDomains, setCustomBlockedDomains] = useState<string[]>([]);
  const [isSweepingShield, setIsSweepingShield] = useState<boolean>(false);

  const [encryptedEntries, setEncryptedEntries] = useState<EncryptedVaultEntry[]>([]);
  const [interceptedIntent, setInterceptedIntent] = useState<{
    url: string;
    caller: string;
  } | null>(null);

  const vault = useMemo(
    () => new EncryptedPreferencesVault(new BrowserLocalStorageAdapter()),
    []
  );

  const refreshVaultEntries = useCallback(() => {
    setEncryptedEntries(vault.inspectEncryptedEntries());
  }, [vault]);

  const appendIntrusionEvent = useCallback(
    async (event: IntrusionEvent) => {
      setShieldEvents((prev) => {
        if (prev.some((existing) => existing.id === event.id)) {
          return prev;
        }
        const next = [event, ...prev].slice(0, 50);
        void vault.putEncrypted(VAULT_KEYS.SHIELD_EVENTS, next).then(refreshVaultEntries);
        return next;
      });
    },
    [vault, refreshVaultEntries]
  );

  const runShieldIntegritySweep = useCallback(
    async (armedOverride?: boolean) => {
      setIsSweepingShield(true);
      try {
        if (isRunningOnAndroidNative()) {
          const snapshot = await AegisSecurityNative.getLiveShieldSnapshot();
          setShieldTelemetry(mapNativeSnapshotToTelemetry(snapshot));
          setVpnLoopbackActive(snapshot.vpnTunnelActive);
          if (snapshot.recentEvents?.length) {
            setShieldEvents((prev) => {
              const seen = new Set(prev.map((e) => e.id));
              const merged = [
                ...snapshot.recentEvents.filter((e) => !seen.has(e.id)),
                ...prev,
              ].slice(0, 50);
              void vault.putEncrypted(VAULT_KEYS.SHIELD_EVENTS, merged).then(refreshVaultEntries);
              return merged;
            });
          }
        } else {
          let dnsReachable: boolean | null = null;
          let dnsLatencyMs: number | null = null;

          try {
            const resp = await fetch('/api/shield-probe', {
              headers: { Accept: 'application/json' },
            });
            if (resp.ok) {
              const data = (await resp.json()) as {
                reachable?: boolean;
                latencyMs?: number;
              };
              dnsReachable = Boolean(data.reachable);
              dnsLatencyMs = typeof data.latencyMs === 'number' ? data.latencyMs : null;
            } else {
              dnsReachable = false;
            }
          } catch {
            dnsReachable = false;
          }

          const secureTls =
            typeof window !== 'undefined' ? Boolean(window.isSecureContext) : true;
          const nowIso = new Date().toISOString();

          setShieldTelemetry((prev) => ({
            ...prev,
            shieldArmed: armedOverride ?? prev.shieldArmed,
            secureTransportTls: secureTls,
            malwareDnsReachable: dnsReachable,
            malwareDnsLatencyMs: dnsLatencyMs,
            lastSweepIso: nowIso,
          }));
        }
      } catch {
        // Keep current telemetry on transient error
      } finally {
        setIsSweepingShield(false);
      }
    },
    [vault, refreshVaultEntries]
  );

  // Hydrate AES-256-GCM Vault (purging any legacy _v1 demo keys) and connect Android native listeners
  useEffect(() => {
    let cancelled = false;
    let alertListenerPromise: ReturnType<typeof AegisSecurityNative.addListener> | null = null;

    (async () => {
      try {
        // Purge legacy v1 seed keys so zero demo artifacts remain in storage
        vault.removeKeys(LEGACY_DEMO_KEYS);

        const [
          storedBaselines,
          storedLinks,
          storedPolicy,
          storedBlocklist,
          storedEvents,
        ] = await Promise.all([
          vault.getDecrypted<BssidBaseline[]>(VAULT_KEYS.WIFI_BASELINES).catch(() => null),
          vault.getDecrypted<UrlAnalysisResult[]>(VAULT_KEYS.URL_HISTORY).catch(() => null),
          vault.getDecrypted<LiveShieldPolicy>(VAULT_KEYS.SHIELD_POLICY).catch(() => null),
          vault.getDecrypted<string[]>(VAULT_KEYS.SHIELD_BLOCKLIST).catch(() => null),
          vault.getDecrypted<IntrusionEvent[]>(VAULT_KEYS.SHIELD_EVENTS).catch(() => null),
        ]);

        const effectivePolicy = storedPolicy ?? DEFAULT_LIVE_SHIELD_POLICY;
        const effectiveBlocklist = storedBlocklist ?? [];

        if (!cancelled) {
          if (storedBaselines) setBaselines(storedBaselines);
          if (storedLinks) setRecentUrlAnalyses(storedLinks);
          if (storedPolicy) setShieldPolicy(storedPolicy);
          if (storedBlocklist) setCustomBlockedDomains(storedBlocklist);
          if (storedEvents) setShieldEvents(storedEvents);
          refreshVaultEntries();
        }

        if (isRunningOnAndroidNative()) {
          alertListenerPromise = AegisSecurityNative.addListener('shieldAlert', (event) => {
            if (!cancelled && event) {
              void appendIntrusionEvent(event);
              void AegisSecurityNative.getLiveShieldSnapshot()
                .then((snap) => {
                  if (!cancelled) {
                    setShieldTelemetry(mapNativeSnapshotToTelemetry(snap));
                    setVpnLoopbackActive(snap.vpnTunnelActive);
                  }
                })
                .catch(() => null);
            }
          });

          const pending = await AegisSecurityNative.consumePendingInterceptUrl().catch(() => null);
          if (!cancelled && pending?.interceptedUrl) {
            setInterceptedIntent({
              url: pending.interceptedUrl,
              caller: pending.callerPackage ?? 'Android Intent',
            });
            setActiveTab('links');
          }

          const encBaselines = await AegisSecurityNative.getEncryptedString({
            key: VAULT_KEYS.WIFI_BASELINES,
          }).catch(() => ({ value: null }));
          if (!cancelled && encBaselines.value) {
            try {
              setBaselines(JSON.parse(encBaselines.value) as BssidBaseline[]);
            } catch {
              // Ignore malformed stored JSON
            }
          }

          const [pkgRes, healthRes] = await Promise.all([
            AegisSecurityNative.scanInstalledPackages().catch(() => ({ packages: [] })),
            AegisSecurityNative.getDeviceHealthState().catch(() => null),
          ]);

          if (!cancelled) {
            setPackages(pkgRes.packages);
            if (healthRes) setDeviceHealth(healthRes);
          }

          if (effectivePolicy.enabled) {
            const snap = await AegisSecurityNative.setLiveShieldArmed({
              armed: true,
              policy: effectivePolicy,
              blockedDomains: effectiveBlocklist,
            }).catch(() => null);
            if (!cancelled && snap) {
              setShieldTelemetry(mapNativeSnapshotToTelemetry(snap));
              setVpnLoopbackActive(snap.vpnTunnelActive);
            }
          } else {
            const snap = await AegisSecurityNative.getLiveShieldSnapshot().catch(() => null);
            if (!cancelled && snap) {
              setShieldTelemetry(mapNativeSnapshotToTelemetry(snap));
              setVpnLoopbackActive(snap.vpnTunnelActive);
            }
          }

          const wifiRes = await AegisSecurityNative.scanWifiNetworks().catch(() => ({
            permissionGranted: false,
            accessPoints: [],
          }));
          if (!cancelled && wifiRes.permissionGranted) {
            setAccessPoints(
              wifiRes.accessPoints.map((ap) => ({
                ...ap,
                protocol: mapSecurityStringToEnum(String(ap.protocol)),
              }))
            );
          }
        } else if (effectivePolicy.enabled && !cancelled) {
          setShieldTelemetry((prev) => ({ ...prev, shieldArmed: true }));
          await runShieldIntegritySweep(true);
        }
      } catch {
        if (!cancelled) {
          refreshVaultEntries();
        }
      }
    })();

    return () => {
      cancelled = true;
      if (alertListenerPromise) {
        void alertListenerPromise.then((handle) => handle.remove()).catch(() => null);
      }
    };
  }, [vault, refreshVaultEntries, appendIntrusionEvent, runShieldIntegritySweep]);

  // Real-time Web DOM MutationObserver for unauthorized cross-origin script/iframe injection when armed
  useEffect(() => {
    if (isRunningOnAndroidNative() || !shieldPolicy.enabled || typeof MutationObserver === 'undefined') {
      return;
    }

    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        mutation.addedNodes.forEach((node) => {
          if (!(node instanceof HTMLElement)) return;
          const tag = node.tagName.toLowerCase();
          if (tag !== 'script' && tag !== 'iframe') return;

          const src = node.getAttribute('src') ?? '';
          if (!src) return;

          try {
            const resolved = new URL(src, window.location.origin);
            if (resolved.origin !== window.location.origin) {
              setShieldTelemetry((prev) => ({
                ...prev,
                domInjectionCount: prev.domInjectionCount + 1,
              }));
              void appendIntrusionEvent({
                id: `dom-inj-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
                timestampIso: new Date().toISOString(),
                surface: 'RASP_INTEGRITY',
                severity: ThreatSeverity.CRITICAL,
                title: `Untrusted <${tag}> injection detected`,
                detail: `Runtime DOM MutationObserver caught an external ${tag.toUpperCase()} element pointing to ${resolved.origin}.`,
                indicator: resolved.href,
              });
            }
          } catch {
            // Ignore relative non-URL attributes
          }
        });
      }
    });

    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
    });

    return () => observer.disconnect();
  }, [shieldPolicy.enabled, appendIntrusionEvent]);

  const handleToggleShieldArmed = async () => {
    const nextArmed = !shieldPolicy.enabled;
    const nextPolicy: LiveShieldPolicy = {
      ...shieldPolicy,
      enabled: nextArmed,
    };
    setShieldPolicy(nextPolicy);
    await vault.putEncrypted(VAULT_KEYS.SHIELD_POLICY, nextPolicy);
    refreshVaultEntries();

    if (isRunningOnAndroidNative()) {
      await AegisSecurityNative.putEncryptedString({
        key: VAULT_KEYS.SHIELD_POLICY,
        value: JSON.stringify(nextPolicy),
      }).catch(() => null);

      const snap = await AegisSecurityNative.setLiveShieldArmed({
        armed: nextArmed,
        policy: nextPolicy,
        blockedDomains: customBlockedDomains,
      }).catch(() => null);

      if (snap) {
        setShieldTelemetry(mapNativeSnapshotToTelemetry(snap));
        setVpnLoopbackActive(snap.vpnTunnelActive);
      }
    } else {
      setShieldTelemetry((prev) => ({
        ...prev,
        shieldArmed: nextArmed,
      }));
      setVpnLoopbackActive(nextArmed && nextPolicy.dnsSinkholeEnabled);
      if (nextArmed) {
        await runShieldIntegritySweep(true);
      }
    }
  };

  const handleUpdateShieldPolicy = async (nextPolicy: LiveShieldPolicy) => {
    setShieldPolicy(nextPolicy);
    await vault.putEncrypted(VAULT_KEYS.SHIELD_POLICY, nextPolicy);
    refreshVaultEntries();

    if (isRunningOnAndroidNative()) {
      await AegisSecurityNative.putEncryptedString({
        key: VAULT_KEYS.SHIELD_POLICY,
        value: JSON.stringify(nextPolicy),
      }).catch(() => null);

      if (nextPolicy.enabled) {
        const snap = await AegisSecurityNative.setLiveShieldArmed({
          armed: true,
          policy: nextPolicy,
          blockedDomains: customBlockedDomains,
        }).catch(() => null);
        if (snap) {
          setShieldTelemetry(mapNativeSnapshotToTelemetry(snap));
          setVpnLoopbackActive(snap.vpnTunnelActive);
        }
      } else {
        await AegisSecurityNative.syncBlockedDomains({
          policy: nextPolicy,
          blockedDomains: customBlockedDomains,
        }).catch(() => null);
      }
    } else if (nextPolicy.enabled) {
      setVpnLoopbackActive(nextPolicy.dnsSinkholeEnabled);
    }
  };

  const handleAddBlockedDomain = async (rawDomain: string) => {
    const normalized = normalizeDomainInput(rawDomain);
    if (!normalized) return;

    const nextList = Array.from(new Set([normalized, ...customBlockedDomains]));
    setCustomBlockedDomains(nextList);
    await vault.putEncrypted(VAULT_KEYS.SHIELD_BLOCKLIST, nextList);
    refreshVaultEntries();

    if (isRunningOnAndroidNative()) {
      await AegisSecurityNative.putEncryptedString({
        key: VAULT_KEYS.SHIELD_BLOCKLIST,
        value: JSON.stringify(nextList),
      }).catch(() => null);
      await AegisSecurityNative.syncBlockedDomains({
        policy: shieldPolicy,
        blockedDomains: nextList,
      }).catch(() => null);
    }
  };

  const handleRemoveBlockedDomain = async (domainToRemove: string) => {
    const nextList = customBlockedDomains.filter((d) => d !== domainToRemove);
    if (nextList.length > 0) {
      await vault.putEncrypted(VAULT_KEYS.SHIELD_BLOCKLIST, nextList);
    } else {
      vault.removeEntry(VAULT_KEYS.SHIELD_BLOCKLIST);
    }
    setCustomBlockedDomains(nextList);
    refreshVaultEntries();

    if (isRunningOnAndroidNative()) {
      await AegisSecurityNative.putEncryptedString({
        key: VAULT_KEYS.SHIELD_BLOCKLIST,
        value: JSON.stringify(nextList),
      }).catch(() => null);
      await AegisSecurityNative.syncBlockedDomains({
        policy: shieldPolicy,
        blockedDomains: nextList,
      }).catch(() => null);
    }
  };

  const handleRecordEvaluatedBlock = (verdict: DnsSinkholeVerdict) => {
    setShieldTelemetry((prev) => ({
      ...prev,
      inspectedDnsQueries: prev.inspectedDnsQueries + 1,
      blockedDnsQueries: prev.blockedDnsQueries + (verdict.blocked ? 1 : 0),
    }));

    void appendIntrusionEvent({
      id: `dns-eval-${Date.now()}-${verdict.domain}`,
      timestampIso: new Date().toISOString(),
      surface: 'DNS_SINKHOLE',
      severity: verdict.severity,
      title: `DNS Sinkhole blocked ${verdict.domain}`,
      detail: verdict.reasons[0] ?? `Matched rule ${verdict.matchedRule}.`,
      indicator: `${verdict.matchedRule} · H=${verdict.shannonEntropy.toFixed(2)}`,
    });
  };

  const handleClearShieldEvents = () => {
    setShieldEvents([]);
    vault.removeEntry(VAULT_KEYS.SHIELD_EVENTS);
    refreshVaultEntries();
  };

  const handleToggleVpnLoopback = async () => {
    const nextState = !vpnLoopbackActive;
    if (isRunningOnAndroidNative()) {
      try {
        const res = await AegisSecurityNative.toggleLocalVpn({ enable: nextState });
        setVpnLoopbackActive(res.active);
        return;
      } catch {
        setWifiScanMessage('Android VpnService consent was cancelled or unavailable.');
        return;
      }
    }
    setVpnLoopbackActive(nextState);
  };

  const handleScanWifi = async () => {
    setIsScanningWifi(true);
    setWifiScanMessage(null);
    try {
      if (isRunningOnAndroidNative()) {
        const wifiRes = await AegisSecurityNative.scanWifiNetworks({ forcePrompt: true });
        if (!wifiRes.permissionGranted) {
          setWifiScanMessage(
            'Location permission is required by Android OS to read Wi-Fi BSSID hardware addresses.'
          );
          return;
        }
        const mapped = wifiRes.accessPoints.map((ap) => ({
          ...ap,
          protocol: mapSecurityStringToEnum(String(ap.protocol)),
        }));
        setAccessPoints(mapped);
        setWifiScanMessage(
          mapped.length > 0
            ? `Scanned ${mapped.length} nearby 802.11 access point(s) via Android WifiManager.`
            : 'WifiManager scan completed: 0 nearby access points returned by OS.'
        );
      } else {
        setWifiScanMessage(
          'Browser sandboxes cannot read raw 802.11 BSSID frames. Install the Android APK to scan live nearby Wi-Fi radios via WifiManager.'
        );
      }
    } catch {
      setWifiScanMessage('Wi-Fi radio scan could not complete on this device.');
    } finally {
      setIsScanningWifi(false);
    }
  };

  const handlePinBaseline = async (ap: WifiAccessPoint) => {
    const upperBssid = ap.bssid.toUpperCase();
    const nextBaselines = [...baselines];
    const existingIdx = nextBaselines.findIndex((b) => b.ssid === ap.ssid);

    if (existingIdx >= 0) {
      const current = nextBaselines[existingIdx];
      const merged = Array.from(new Set([...current.trustedBssids, upperBssid]));
      nextBaselines[existingIdx] = { ...current, trustedBssids: merged };
    } else {
      nextBaselines.push({
        ssid: ap.ssid,
        trustedBssids: [upperBssid],
        expectedProtocol: ap.protocol,
        pinnedGatewayMac: ap.gatewayMac,
        pinnedAtIso: new Date().toISOString(),
      });
    }

    setBaselines(nextBaselines);
    if (isRunningOnAndroidNative()) {
      await AegisSecurityNative.putEncryptedString({
        key: VAULT_KEYS.WIFI_BASELINES,
        value: JSON.stringify(nextBaselines),
      }).catch(() => null);
    }
    await vault.putEncrypted(VAULT_KEYS.WIFI_BASELINES, nextBaselines);
    refreshVaultEntries();
  };

  const handleClearBaselines = async () => {
    setBaselines([]);
    vault.removeEntry(VAULT_KEYS.WIFI_BASELINES);
    if (isRunningOnAndroidNative()) {
      await AegisSecurityNative.putEncryptedString({
        key: VAULT_KEYS.WIFI_BASELINES,
        value: '[]',
      }).catch(() => null);
    }
    refreshVaultEntries();
  };

  const handleRecordUrlAnalysis = async (result: UrlAnalysisResult) => {
    const next = [result, ...recentUrlAnalyses.filter((r) => r.inputUrl !== result.inputUrl)].slice(
      0,
      12
    );
    setRecentUrlAnalyses(next);
    await vault.putEncrypted(VAULT_KEYS.URL_HISTORY, next);
    refreshVaultEntries();
  };

  const handleClearUrlHistory = () => {
    setRecentUrlAnalyses([]);
    vault.removeEntry(VAULT_KEYS.URL_HISTORY);
    refreshVaultEntries();
  };

  const handleRefreshDeviceAudit = async () => {
    setIsAuditingDevice(true);
    setDeviceAuditMessage(null);
    try {
      if (isRunningOnAndroidNative()) {
        const [pkgRes, healthRes] = await Promise.all([
          AegisSecurityNative.scanInstalledPackages().catch(() => ({ packages: [] })),
          AegisSecurityNative.getDeviceHealthState().catch(() => null),
        ]);
        setPackages(pkgRes.packages);
        if (healthRes) setDeviceHealth(healthRes);
        setDeviceAuditMessage(
          `Audited ${pkgRes.packages.length} installed user package(s) and hardware Keyguard posture.`
        );
      } else {
        setDeviceAuditMessage(
          'Browser sandboxes cannot enumerate installed Android APKs or hardware Keyguard state. Install the Android APK to run live PackageManager and OS posture audits.'
        );
      }
    } finally {
      setIsAuditingDevice(false);
    }
  };

  const handleOpenAppSettings = async (packageName: string) => {
    if (isRunningOnAndroidNative()) {
      await AegisSecurityNative.openAppSettings({ packageName }).catch(() => null);
    }
  };

  const handleExportBundle = () => {
    const lines: string[] = [
      '# AegisLocal — Local Android Cybersecurity Architecture & Kotlin Implementation',
      '',
      '## 1. Architecture Overview',
      ...ARCHITECTURE_LAYERS.flatMap((l) => [
        `### ${l.number}. ${l.title}`,
        l.summary,
        ...l.details.map((d) => `- ${d}`),
        '',
      ]),
      '## 2. Source Files & Manifests',
      ...BLUEPRINT_FILES.flatMap((f) => [
        `### ${f.path}`,
        f.summary,
        '',
        '**Security Edge Cases:**',
        ...f.edgeCases.map((e) => `- ${e}`),
        '',
        '**Performance Implications:**',
        ...f.performanceNotes.map((p) => `- ${p}`),
        '',
        `\`\`\`${f.language}`,
        f.code,
        '```',
        '',
      ]),
    ];

    const blob = new Blob([lines.join('\n')], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'AegisLocal-Android-Security-Blueprint.md';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div id="top" className="min-h-screen flex flex-col bg-slate-50 text-slate-900 pb-20 md:pb-10">
      <TopNav
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        onExportBundle={handleExportBundle}
      />

      <main className="flex-1 w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8">
        {activeTab === 'shield' && (
          <LiveShieldView
            policy={shieldPolicy}
            telemetry={shieldTelemetry}
            events={shieldEvents}
            customBlockedDomains={customBlockedDomains}
            isSweeping={isSweepingShield}
            onToggleShieldArmed={() => void handleToggleShieldArmed()}
            onUpdatePolicy={(next) => void handleUpdateShieldPolicy(next)}
            onRunIntegritySweep={() => void runShieldIntegritySweep()}
            onAddBlockedDomain={(domain) => void handleAddBlockedDomain(domain)}
            onRemoveBlockedDomain={(domain) => void handleRemoveBlockedDomain(domain)}
            onRecordEvaluatedBlock={handleRecordEvaluatedBlock}
            onClearEvents={handleClearShieldEvents}
          />
        )}

        {activeTab === 'wifi' && (
          <WifiInspectorView
            accessPoints={accessPoints}
            baselines={baselines}
            vpnLoopbackActive={vpnLoopbackActive}
            encryptedEntries={encryptedEntries}
            isScanningWifi={isScanningWifi}
            wifiScanMessage={wifiScanMessage}
            onToggleVpnLoopback={() => void handleToggleVpnLoopback()}
            onPinBaseline={(ap) => void handlePinBaseline(ap)}
            onScanWifi={() => void handleScanWifi()}
            onClearBaselines={() => void handleClearBaselines()}
          />
        )}

        {activeTab === 'links' && (
          <LinkAnalyzerView
            recentAnalyses={recentUrlAnalyses}
            onRecordAnalysis={(res) => void handleRecordUrlAnalysis(res)}
            onClearHistory={handleClearUrlHistory}
            interceptedIntent={interceptedIntent}
          />
        )}

        {activeTab === 'device' && (
          <DeviceAuditorView
            packages={packages}
            deviceHealth={deviceHealth}
            isAuditing={isAuditingDevice}
            auditMessage={deviceAuditMessage}
            onRefreshAudit={() => void handleRefreshDeviceAudit()}
            onOpenAppSettings={(pkg) => void handleOpenAppSettings(pkg)}
          />
        )}

        {activeTab === 'blueprint' && (
          <AndroidBlueprintView onExportBundle={handleExportBundle} />
        )}
      </main>

      <footer className="max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 border-t border-slate-200 flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-slate-500">
        <span>AegisLocal Android Security Architecture · Non-Root Real-Time Defense</span>
        <span>Persistence encrypted locally via AES-256-GCM</span>
      </footer>
    </div>
  );
}
