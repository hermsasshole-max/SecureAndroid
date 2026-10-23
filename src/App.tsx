/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useEffect, useMemo, useState } from 'react';
import { TopNav, WorkspaceTab } from './components/TopNav';
import { WifiInspectorView } from './components/WifiInspectorView';
import { LinkAnalyzerView } from './components/LinkAnalyzerView';
import { DeviceAuditorView } from './components/DeviceAuditorView';
import { AndroidBlueprintView } from './components/AndroidBlueprintView';
import {
  BssidBaseline,
  DeviceHealthState,
  EncryptedVaultEntry,
  InstalledAppPackage,
  UrlAnalysisResult,
  WifiAccessPoint,
} from './security/types';
import {
  BrowserLocalStorageAdapter,
  EncryptedPreferencesVault,
} from './security/encryptedVault';
import {
  INITIAL_BSSID_BASELINES,
  INITIAL_DEVICE_HEALTH,
  INITIAL_INSTALLED_PACKAGES,
  INITIAL_WIFI_SCAN,
} from './data/seedData';
import { ARCHITECTURE_LAYERS, BLUEPRINT_FILES } from './data/androidBlueprints';
import {
  AegisSecurityNative,
  isRunningOnAndroidNative,
  mapSecurityStringToEnum,
} from './native/aegisBridge';

function getInitialTabFromQuery(): WorkspaceTab {
  if (typeof window === 'undefined') return 'wifi';
  const params = new URLSearchParams(window.location.search);
  const tab = params.get('tab');
  if (tab === 'links' || tab === 'device' || tab === 'blueprint' || tab === 'wifi') {
    return tab;
  }
  return 'wifi';
}

export default function App() {
  const [activeTab, setActiveTab] = useState<WorkspaceTab>(getInitialTabFromQuery);
  const [accessPoints, setAccessPoints] = useState<WifiAccessPoint[]>(INITIAL_WIFI_SCAN);
  const [baselines, setBaselines] = useState<BssidBaseline[]>(INITIAL_BSSID_BASELINES);
  const [vpnLoopbackActive, setVpnLoopbackActive] = useState<boolean>(true);
  const [recentUrlAnalyses, setRecentUrlAnalyses] = useState<UrlAnalysisResult[]>([]);
  const [packages, setPackages] = useState<InstalledAppPackage[]>(INITIAL_INSTALLED_PACKAGES);
  const [deviceHealth, setDeviceHealth] = useState<DeviceHealthState>(INITIAL_DEVICE_HEALTH);
  const [encryptedEntries, setEncryptedEntries] = useState<EncryptedVaultEntry[]>([]);
  const [interceptedIntent, setInterceptedIntent] = useState<{
    url: string;
    caller: string;
  } | null>(null);

  const vault = useMemo(
    () => new EncryptedPreferencesVault(new BrowserLocalStorageAdapter()),
    []
  );

  // Hydrate AES-256-GCM EncryptedPreferencesVault + Android Capacitor Native APIs on mount
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        if (isRunningOnAndroidNative()) {
          // 1. Check if launched via Android Browser Picker ACTION_VIEW intent
          const pending = await AegisSecurityNative.consumePendingInterceptUrl();
          if (!cancelled && pending.interceptedUrl) {
            setInterceptedIntent({
              url: pending.interceptedUrl,
              caller: pending.callerPackage ?? 'Android Intent',
            });
            setActiveTab('links');
          }

          // 2. Load hardware-backed EncryptedSharedPreferences baselines
          const encBaselines = await AegisSecurityNative.getEncryptedString({
            key: 'wifi_bssid_baselines_v1',
          });
          if (!cancelled && encBaselines.value) {
            setBaselines(JSON.parse(encBaselines.value) as BssidBaseline[]);
          }

          // 3. Scan real device Wi-Fi ScanResults, Installed Packages, and OS Posture
          const [wifiRes, pkgRes, healthRes] = await Promise.all([
            AegisSecurityNative.scanWifiNetworks(),
            AegisSecurityNative.scanInstalledPackages(),
            AegisSecurityNative.getDeviceHealthState(),
          ]);

          if (!cancelled) {
            if (wifiRes.permissionGranted && wifiRes.accessPoints.length > 0) {
              setAccessPoints(
                wifiRes.accessPoints.map((ap) => ({
                  ...ap,
                  protocol: mapSecurityStringToEnum(String(ap.protocol)),
                }))
              );
            }
            if (pkgRes.packages.length > 0) {
              setPackages(pkgRes.packages);
            }
            setDeviceHealth(healthRes);
          }
        }

        const storedBaselines = await vault.getDecrypted<BssidBaseline[]>('wifi_bssid_baselines_v1');
        if (!cancelled && storedBaselines && storedBaselines.length > 0 && !isRunningOnAndroidNative()) {
          setBaselines(storedBaselines);
        } else if (!isRunningOnAndroidNative()) {
          await vault.putEncrypted('wifi_bssid_baselines_v1', INITIAL_BSSID_BASELINES);
        }

        const storedHealth = await vault.getDecrypted<DeviceHealthState>('device_posture_state_v1');
        if (!cancelled && storedHealth && !isRunningOnAndroidNative()) {
          setDeviceHealth(storedHealth);
        } else {
          await vault.putEncrypted('device_posture_state_v1', INITIAL_DEVICE_HEALTH);
        }

        const storedLinks = await vault.getDecrypted<UrlAnalysisResult[]>('url_audit_history_v1');
        if (!cancelled && storedLinks) {
          setRecentUrlAnalyses(storedLinks);
        }

        if (!cancelled) {
          setEncryptedEntries(vault.inspectEncryptedEntries());
        }
      } catch {
        await vault.putEncrypted('wifi_bssid_baselines_v1', INITIAL_BSSID_BASELINES);
        if (!cancelled) {
          setEncryptedEntries(vault.inspectEncryptedEntries());
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [vault]);

  const handleToggleVpnLoopback = async () => {
    const nextState = !vpnLoopbackActive;
    if (isRunningOnAndroidNative()) {
      try {
        const res = await AegisSecurityNative.toggleLocalVpn({ enable: nextState });
        setVpnLoopbackActive(res.active);
        return;
      } catch {
        // Fallback to local UI state
      }
    }
    setVpnLoopbackActive(nextState);
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
        key: 'wifi_bssid_baselines_v1',
        value: JSON.stringify(nextBaselines),
      });
    }
    await vault.putEncrypted('wifi_bssid_baselines_v1', nextBaselines);
    setEncryptedEntries(vault.inspectEncryptedEntries());
  };

  const handleAddAccessPoint = (ap: WifiAccessPoint) => {
    setAccessPoints((prev) => [ap, ...prev]);
  };

  const handleSimulateGatewaySpoof = () => {
    setAccessPoints((prev) =>
      prev.map((ap) =>
        ap.isConnected
          ? {
              ...ap,
              gatewayMac: 'DE:AD:BE:EF:44:19',
              dnsServers: ['185.199.108.153'],
            }
          : ap
      )
    );
  };

  const handleResetScan = async () => {
    setAccessPoints(INITIAL_WIFI_SCAN);
    setBaselines(INITIAL_BSSID_BASELINES);
    setVpnLoopbackActive(true);
    await vault.putEncrypted('wifi_bssid_baselines_v1', INITIAL_BSSID_BASELINES);
    setEncryptedEntries(vault.inspectEncryptedEntries());
  };

  const handleRecordUrlAnalysis = async (result: UrlAnalysisResult) => {
    const next = [result, ...recentUrlAnalyses.filter((r) => r.inputUrl !== result.inputUrl)].slice(
      0,
      8
    );
    setRecentUrlAnalyses(next);
    await vault.putEncrypted('url_audit_history_v1', next);
    setEncryptedEntries(vault.inspectEncryptedEntries());
  };

  const handleUpdateDeviceHealth = async (next: DeviceHealthState) => {
    setDeviceHealth(next);
    await vault.putEncrypted('device_posture_state_v1', next);
    setEncryptedEntries(vault.inspectEncryptedEntries());
  };

  const handleAddPackage = (pkg: InstalledAppPackage) => {
    setPackages((prev) => [pkg, ...prev.filter((p) => p.packageName !== pkg.packageName)]);
  };

  const handleUninstallPackage = (packageName: string) => {
    setPackages((prev) => prev.filter((p) => p.packageName !== packageName));
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
        {activeTab === 'wifi' && (
          <WifiInspectorView
            accessPoints={accessPoints}
            baselines={baselines}
            vpnLoopbackActive={vpnLoopbackActive}
            encryptedEntries={encryptedEntries}
            onToggleVpnLoopback={() => void handleToggleVpnLoopback()}
            onPinBaseline={handlePinBaseline}
            onAddAccessPoint={handleAddAccessPoint}
            onSimulateGatewaySpoof={handleSimulateGatewaySpoof}
            onResetScan={handleResetScan}
          />
        )}

        {activeTab === 'links' && (
          <LinkAnalyzerView
            recentAnalyses={recentUrlAnalyses}
            onRecordAnalysis={handleRecordUrlAnalysis}
            interceptedIntent={interceptedIntent}
          />
        )}

        {activeTab === 'device' && (
          <DeviceAuditorView
            packages={packages}
            deviceHealth={deviceHealth}
            onUpdateDeviceHealth={handleUpdateDeviceHealth}
            onAddPackage={handleAddPackage}
            onUninstallPackage={handleUninstallPackage}
          />
        )}

        {activeTab === 'blueprint' && (
          <AndroidBlueprintView onExportBundle={handleExportBundle} />
        )}
      </main>

      <footer className="max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 border-t border-slate-200 flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-slate-500">
        <span>AegisLocal Android Security Architecture · Non-Root On-Device Inspection</span>
        <span>Persistence encrypted locally via AES-256-GCM</span>
      </footer>
    </div>
  );
}
