import { useMemo, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Loader2,
  Lock,
  RefreshCw,
  ShieldCheck,
  ShieldOff,
  Trash2,
  Wifi,
} from 'lucide-react';
import {
  BssidBaseline,
  EncryptedVaultEntry,
  ThreatSeverity,
  WifiAccessPoint,
} from '../security/types';
import {
  auditWifiEnvironment,
  validateLocalGatewayAndTunnel,
} from '../security/wifiInspector';
import { isRunningOnAndroidNative } from '../native/aegisBridge';

interface WifiInspectorViewProps {
  accessPoints: WifiAccessPoint[];
  baselines: BssidBaseline[];
  vpnLoopbackActive: boolean;
  encryptedEntries: EncryptedVaultEntry[];
  isScanningWifi: boolean;
  wifiScanMessage: string | null;
  onToggleVpnLoopback: () => void;
  onPinBaseline: (ap: WifiAccessPoint) => void;
  onScanWifi: () => void;
  onClearBaselines: () => void;
}

type RiskFilter = 'all' | 'flagged' | 'pinned';

export function WifiInspectorView({
  accessPoints,
  baselines,
  vpnLoopbackActive,
  encryptedEntries,
  isScanningWifi,
  wifiScanMessage,
  onToggleVpnLoopback,
  onPinBaseline,
  onScanWifi,
  onClearBaselines,
}: WifiInspectorViewProps) {
  const [filter, setFilter] = useState<RiskFilter>('all');
  const [searchQuery, setSearchQuery] = useState('');

  const findings = useMemo(
    () => auditWifiEnvironment(accessPoints, baselines),
    [accessPoints, baselines]
  );

  const connectedAp = useMemo(
    () => accessPoints.find((ap) => ap.isConnected) ?? accessPoints[0],
    [accessPoints]
  );

  const gatewayReport = useMemo(
    () => validateLocalGatewayAndTunnel(connectedAp, vpnLoopbackActive, baselines),
    [connectedAp, vpnLoopbackActive, baselines]
  );

  const filteredFindings = useMemo(() => {
    return findings.filter((item) => {
      if (filter === 'flagged' && item.severity === ThreatSeverity.NOMINAL) return false;
      if (filter === 'pinned' && !item.isPinnedTrusted) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.trim().toLowerCase();
        return (
          item.ap.ssid.toLowerCase().includes(q) ||
          item.ap.bssid.toLowerCase().includes(q) ||
          item.ap.protocol.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [findings, filter, searchQuery]);

  const criticalCount = findings.filter((f) => f.severity === ThreatSeverity.CRITICAL).length;
  const evilTwinCount = findings.filter((f) => f.isEvilTwinSuspect).length;

  const renderSeverityLabel = (severity: ThreatSeverity) => {
    if (severity === ThreatSeverity.CRITICAL) {
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-red-700 whitespace-nowrap">
          <AlertTriangle className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
          <span>Critical</span>
        </span>
      );
    }
    if (severity === ThreatSeverity.WARNING) {
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-amber-700 whitespace-nowrap">
          <AlertTriangle className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
          <span>Warning</span>
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
      {/* Header & Live Scan Actions */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
        <div className="space-y-1.5 max-w-2xl">
          <p className="text-xs font-medium text-slate-500">
            Non-Root Android Network Monitor · WifiManager + Local VpnService
          </p>
          <h1
            className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-950"
            style={{ textWrap: 'balance' }}
          >
            Wi-Fi Access Point &amp; Evil Twin Inspector
          </h1>
          <p className="text-sm text-slate-600 leading-relaxed">
            Audits live 802.11 radio beacons for unencrypted or deprecated ciphers, cross-checks hardware BSSIDs against encrypted baselines, and validates local gateway ARP consistency.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          {baselines.length > 0 && (
            <button
              type="button"
              onClick={onClearBaselines}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 min-h-[42px] text-xs font-medium text-slate-700 bg-white border border-slate-300 rounded-lg hover:bg-slate-50 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Trash2 className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
              <span>Clear Pinned Baselines ({baselines.length})</span>
            </button>
          )}

          <button
            type="button"
            onClick={onScanWifi}
            disabled={isScanningWifi}
            className="inline-flex items-center gap-2 px-4 py-2 min-h-[42px] text-xs font-semibold text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-60 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            {isScanningWifi ? (
              <Loader2 className="w-4 h-4 animate-spin shrink-0" aria-hidden="true" />
            ) : (
              <RefreshCw className="w-4 h-4 shrink-0" aria-hidden="true" />
            )}
            <span>{isScanningWifi ? 'Scanning Radios…' : 'Scan Nearby Wi-Fi'}</span>
          </button>
        </div>
      </div>

      {/* Summary Strip + Local Loopback VpnService Controller */}
      <section
        aria-label="Local Loopback Interface and Gateway Status"
        className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-200"
      >
        <div className="grid grid-cols-2 lg:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-slate-200">
          <div className="p-5">
            <p className="text-xs text-slate-500">Scanned 802.11 Radios</p>
            <p className="mt-1 text-2xl font-bold text-slate-950 font-mono tabular-nums">
              {accessPoints.length}
            </p>
            <p className="mt-1 text-xs text-slate-500">
              {criticalCount} critical · {baselines.length} pinned SSIDs
            </p>
          </div>

          <div className="p-5">
            <p className="text-xs text-slate-500">Evil Twin Impersonations</p>
            <p
              className={`mt-1 text-2xl font-bold font-mono tabular-nums ${
                evilTwinCount > 0 ? 'text-red-700' : 'text-slate-950'
              }`}
            >
              {evilTwinCount}
            </p>
            <p className="mt-1 text-xs text-slate-500">
              BSSID / OUI &amp; downgrade checks
            </p>
          </div>

          <div className="p-5">
            <p className="text-xs text-slate-500">Active Interface &amp; Tunnel</p>
            <p className="mt-1 text-lg font-bold text-slate-950 font-mono tabular-nums">
              {gatewayReport.activeInterface}
            </p>
            <p className="mt-1 text-xs text-slate-500 font-mono tabular-nums">
              {gatewayReport.localTunnelCidr}
            </p>
          </div>

          <div className="p-5">
            <p className="text-xs text-slate-500">Local Gateway Validation</p>
            <div className="mt-1.5">{renderSeverityLabel(gatewayReport.severity)}</div>
            <p className="mt-1.5 text-xs text-slate-500 font-mono tabular-nums truncate">
              {gatewayReport.gatewayIp} · {gatewayReport.gatewayMac}
            </p>
          </div>
        </div>

        <div className="p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-900">
              {vpnLoopbackActive ? (
                <ShieldCheck className="w-4 h-4 text-emerald-700 shrink-0" aria-hidden="true" />
              ) : (
                <ShieldOff className="w-4 h-4 text-amber-700 shrink-0" aria-hidden="true" />
              )}
              <span>
                On-Device VpnService Loopback Guard ({vpnLoopbackActive ? 'Active on tun0' : 'Inactive'})
              </span>
            </div>
            <ul className="space-y-0.5 text-xs text-slate-600">
              {gatewayReport.findings.map((note, idx) => (
                <li key={idx}>{note}</li>
              ))}
            </ul>
          </div>

          <button
            type="button"
            onClick={onToggleVpnLoopback}
            aria-pressed={vpnLoopbackActive}
            className={`px-4 py-2 min-h-[42px] text-xs font-semibold rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              vpnLoopbackActive
                ? 'bg-slate-100 text-slate-900 hover:bg-slate-200'
                : 'bg-slate-900 text-white hover:bg-slate-800'
            }`}
          >
            {vpnLoopbackActive ? 'Pause Local VpnService' : 'Enable Local VpnService'}
          </button>
        </div>
      </section>

      {/* Scanned Access Points Table + Toolbar */}
      <section
        aria-label="Scanned Wi-Fi Access Points"
        className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-200"
      >
        <div className="p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-3">
            <div
              role="group"
              aria-label="Filter access points"
              className="inline-flex items-center gap-1 p-1 bg-slate-100 rounded-lg"
            >
              {(['all', 'flagged', 'pinned'] as const).map((mode) => (
                <button
                  key={mode}
                  type="button"
                  onClick={() => setFilter(mode)}
                  className={`px-3 py-1.5 min-h-[34px] text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    filter === mode
                      ? 'bg-white text-slate-950 shadow-xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {mode === 'all'
                    ? 'All Radios'
                    : mode === 'flagged'
                    ? 'Flagged Only'
                    : 'Pinned Baselines'}
                </button>
              ))}
            </div>

            <div>
              <label htmlFor="wifi-search" className="sr-only">
                Search SSID or BSSID
              </label>
              <input
                id="wifi-search"
                type="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter SSID or BSSID…"
                className="h-9 px-3 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-blue-600"
              />
            </div>
          </div>

          {wifiScanMessage && (
            <span role="status" className="text-xs text-slate-500">
              {wifiScanMessage}
            </span>
          )}
        </div>

        {accessPoints.length === 0 ? (
          <div className="p-10 text-center space-y-3">
            <Wifi className="w-6 h-6 text-slate-400 mx-auto" aria-hidden="true" />
            <p className="text-sm font-medium text-slate-900">
              No live Wi-Fi scan results loaded
            </p>
            <p className="text-xs text-slate-500 max-w-md mx-auto">
              {isRunningOnAndroidNative()
                ? 'Ensure Location Services and Wi-Fi are turned on, then run a live scan to inspect nearby 802.11 BSSIDs and encryption ciphers.'
                : 'Web browsers sandbox hardware 802.11 BSSID radio scans. Install and open the Android APK to inspect live nearby Wi-Fi access points.'}
            </p>
            <button
              type="button"
              onClick={onScanWifi}
              disabled={isScanningWifi}
              className="px-4 py-2 min-h-[40px] text-xs font-semibold text-white bg-slate-900 rounded-lg hover:bg-slate-800 disabled:opacity-60 cursor-pointer"
            >
              {isScanningWifi ? 'Scanning…' : 'Scan Nearby Wi-Fi'}
            </button>
          </div>
        ) : filteredFindings.length === 0 ? (
          <div className="p-10 text-center space-y-3">
            <Wifi className="w-6 h-6 text-slate-400 mx-auto" aria-hidden="true" />
            <p className="text-sm font-medium text-slate-900">
              No access points match the active filter
            </p>
            <button
              type="button"
              onClick={() => {
                setFilter('all');
                setSearchQuery('');
              }}
              className="px-4 py-2 min-h-[40px] text-xs font-semibold text-white bg-slate-900 rounded-lg hover:bg-slate-800 cursor-pointer"
            >
              Show All Radios
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 text-xs font-semibold text-slate-500 bg-slate-50/70">
                  <th className="py-3 px-5">SSID &amp; Radio Metadata</th>
                  <th className="py-3 px-4">Hardware BSSID</th>
                  <th className="py-3 px-4">Protocol</th>
                  <th className="py-3 px-4 text-right">RSSI</th>
                  <th className="py-3 px-4">Verdict</th>
                  <th className="py-3 px-5">Diagnostic Analysis &amp; Baseline</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 text-sm">
                {filteredFindings.map((finding) => {
                  const { ap } = finding;
                  return (
                    <tr key={ap.id} className="hover:bg-slate-50/80 transition-colors align-top">
                      <td className="py-3.5 px-5">
                        <div className="font-semibold text-slate-950">
                          {ap.ssid}
                          {ap.isConnected ? (
                            <span className="ml-2 text-xs font-normal text-blue-700">
                              · Associated
                            </span>
                          ) : null}
                        </div>
                        <div className="mt-0.5 text-xs text-slate-500 font-mono tabular-nums">
                          {ap.frequencyMhz} MHz · Ch {ap.channel}
                          {ap.captivePortal ? ' · Captive Portal' : ''}
                        </div>
                      </td>

                      <td className="py-3.5 px-4 font-mono text-xs text-slate-800 tabular-nums whitespace-nowrap">
                        {ap.bssid}
                      </td>

                      <td className="py-3.5 px-4 font-mono text-xs text-slate-700 whitespace-nowrap">
                        {ap.protocol}
                      </td>

                      <td className="py-3.5 px-4 text-right font-mono text-xs text-slate-700 tabular-nums whitespace-nowrap">
                        {ap.rssiDbm} dBm
                      </td>

                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <div>{renderSeverityLabel(finding.severity)}</div>
                        {finding.isEvilTwinSuspect && (
                          <div className="mt-0.5 text-xs font-medium text-red-700">
                            Evil Twin Suspect
                          </div>
                        )}
                      </td>

                      <td className="py-3.5 px-5 max-w-md">
                        <ul className="space-y-1 text-xs text-slate-700 leading-relaxed">
                          {finding.reasons.map((r, i) => (
                            <li key={i}>{r}</li>
                          ))}
                        </ul>
                        <div className="mt-2 flex items-center justify-between gap-3">
                          <span className="text-xs text-slate-500">{finding.recommendedAction}</span>
                          {finding.isPinnedTrusted ? (
                            <span className="text-xs font-medium text-slate-600 whitespace-nowrap shrink-0">
                              Pinned in Vault
                            </span>
                          ) : (
                            <button
                              type="button"
                              onClick={() => onPinBaseline(ap)}
                              aria-label={`Pin BSSID ${ap.bssid} for ${ap.ssid}`}
                              className="px-2.5 py-1 min-h-[34px] text-xs font-semibold text-slate-800 bg-slate-100 rounded-md hover:bg-slate-200 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                            >
                              Trust BSSID
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* EncryptedSharedPreferences Live Ciphertext Inspector */}
      <section
        aria-label="EncryptedSharedPreferences Vault Inspector"
        className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-200"
      >
        <div className="p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h2 className="text-base font-bold text-slate-950 flex items-center gap-2">
              <Lock className="w-4 h-4 text-slate-700 shrink-0" aria-hidden="true" />
              <span>EncryptedSharedPreferences Persistence Vault (AES-256-GCM)</span>
            </h2>
            <p className="mt-0.5 text-xs text-slate-600">
              Trusted BSSID baselines, custom DNS blocklists, and URL audit history are persisted strictly as authenticated AES-256-GCM ciphertexts.
            </p>
          </div>
          <span className="text-xs font-mono text-slate-500 tabular-nums shrink-0">
            {encryptedEntries.length} encrypted keyset record(s)
          </span>
        </div>

        <div className="divide-y divide-slate-200">
          {encryptedEntries.length === 0 ? (
            <p className="p-5 text-xs text-slate-500">
              Vault is empty. Records are encrypted and written here when you pin a trusted BSSID, block a domain, or audit a link.
            </p>
          ) : (
            encryptedEntries.map((entry) => (
              <div
                key={entry.key}
                className="p-4 px-5 flex flex-col lg:flex-row lg:items-center justify-between gap-2 text-xs"
              >
                <div className="font-mono font-medium text-slate-900 shrink-0">{entry.key}</div>
                <div className="font-mono text-slate-500 truncate max-w-2xl">
                  IV: {entry.ivBase64} · Ciphertext: {entry.ciphertextBase64}
                </div>
                <div className="font-mono text-slate-400 tabular-nums shrink-0">
                  {entry.updatedAtIso.slice(0, 19).replace('T', ' ')}Z
                </div>
              </div>
            ))
          )}
        </div>
      </section>
    </div>
  );
}
