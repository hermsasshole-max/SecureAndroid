import React, { useMemo, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ShieldCheck,
  ShieldOff,
  Plus,
  RotateCcw,
  Lock,
  Wifi,
} from 'lucide-react';
import {
  BssidBaseline,
  EncryptedVaultEntry,
  EncryptionProtocol,
  ThreatSeverity,
  WifiAccessPoint,
} from '../security/types';
import {
  auditWifiEnvironment,
  isValidBssidFormat,
  normalizeBssid,
  validateLocalGatewayAndTunnel,
} from '../security/wifiInspector';

interface WifiInspectorViewProps {
  accessPoints: WifiAccessPoint[];
  baselines: BssidBaseline[];
  vpnLoopbackActive: boolean;
  encryptedEntries: EncryptedVaultEntry[];
  onToggleVpnLoopback: () => void;
  onPinBaseline: (ap: WifiAccessPoint) => void;
  onAddAccessPoint: (ap: WifiAccessPoint) => void;
  onSimulateGatewaySpoof: () => void;
  onResetScan: () => void;
}

type RiskFilter = 'all' | 'flagged' | 'pinned';

export function WifiInspectorView({
  accessPoints,
  baselines,
  vpnLoopbackActive,
  encryptedEntries,
  onToggleVpnLoopback,
  onPinBaseline,
  onAddAccessPoint,
  onSimulateGatewaySpoof,
  onResetScan,
}: WifiInspectorViewProps) {
  const [filter, setFilter] = useState<RiskFilter>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [showCustomForm, setShowCustomForm] = useState(false);

  // Custom AP Scan Entry Form state
  const [ssidInput, setSsidInput] = useState('');
  const [bssidInput, setBssidInput] = useState('');
  const [protocolInput, setProtocolInput] = useState<EncryptionProtocol>(EncryptionProtocol.OPEN);
  const [rssiInput, setRssiInput] = useState('-34');
  const [formError, setFormError] = useState<string | null>(null);

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

  const handleInjectEvilTwin = () => {
    const rogueId = `ap-rogue-${Date.now()}`;
    onAddAccessPoint({
      id: rogueId,
      ssid: 'StudioFiber-Home',
      bssid: '00:C0:CA:88:21:09', // Alfa AWUS wireless adapter OUI
      protocol: EncryptionProtocol.OPEN,
      frequencyMhz: 2437,
      rssiDbm: -29,
      channel: 6,
      captivePortal: true,
    });
  };

  const handleCustomSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const cleanSsid = ssidInput.trim();
    const cleanBssid = normalizeBssid(bssidInput);
    const parsedRssi = Number(rssiInput);

    if (!cleanSsid) {
      setFormError('SSID name is required.');
      return;
    }
    if (!isValidBssidFormat(cleanBssid)) {
      setFormError('Enter a valid 6-octet hex BSSID (for example, DE:AD:BE:EF:10:20).');
      return;
    }
    if (Number.isNaN(parsedRssi) || parsedRssi > -10 || parsedRssi < -100) {
      setFormError('Signal RSSI must be between -100 dBm and -10 dBm.');
      return;
    }

    setFormError(null);
    onAddAccessPoint({
      id: `ap-custom-${Date.now()}`,
      ssid: cleanSsid,
      bssid: cleanBssid,
      protocol: protocolInput,
      frequencyMhz: protocolInput === EncryptionProtocol.WPA3_SAE ? 5180 : 2437,
      rssiDbm: parsedRssi,
      channel: protocolInput === EncryptionProtocol.WPA3_SAE ? 36 : 6,
    });
    setSsidInput('');
    setBssidInput('');
    setShowCustomForm(false);
  };

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
      {/* Header & Primary Simulation Actions */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
        <div className="space-y-1.5 max-w-2xl">
          <p className="text-xs font-medium text-slate-500">
            Non-Root Android 14 Network Monitor · WifiManager + Local VpnService
          </p>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-950">
            Wi-Fi Access Point &amp; Evil Twin Inspector
          </h1>
          <p className="text-sm text-slate-600 leading-relaxed">
            Audits nearby 802.11 beacons for unencrypted or deprecated ciphers, cross-checks hardware BSSIDs against hardware-encrypted baselines, and validates local gateway ARP consistency.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <button
            type="button"
            onClick={handleInjectEvilTwin}
            className="px-3.5 py-2 min-h-[40px] text-xs font-semibold text-white bg-blue-600 rounded-lg hover:bg-blue-700 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            Simulate Evil Twin AP
          </button>
          <button
            type="button"
            onClick={onSimulateGatewaySpoof}
            className="px-3.5 py-2 min-h-[40px] text-xs font-medium text-slate-800 bg-white border border-slate-300 rounded-lg hover:bg-slate-50 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            Simulate Gateway ARP Spoof
          </button>
          <button
            type="button"
            onClick={onResetScan}
            aria-label="Reset Wi-Fi environment to baseline"
            className="inline-flex items-center gap-1.5 px-3 py-2 min-h-[40px] text-xs font-medium text-slate-600 bg-white border border-slate-200 rounded-lg hover:text-slate-900 hover:bg-slate-50 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <RotateCcw className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
            <span>Reset</span>
          </button>
        </div>
      </div>

      {/* Summary Strip + Local Loopback VpnService Controller (Single-Elevation Container) */}
      <section
        aria-label="Local Loopback Interface and Gateway Status"
        className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-200"
      >
        <div className="grid grid-cols-2 lg:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-slate-200">
          <div className="p-5">
            <p className="text-xs text-slate-500">Visible 802.11 Radios</p>
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
                On-Device VpnService Loopback Guard ({vpnLoopbackActive ? 'Active on tun0' : 'Paused'})
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
            className={`px-4 py-2 min-h-[40px] text-xs font-semibold rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
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
            {/* Functional Filter Segmented Control */}
            <div role="group" aria-label="Filter access points" className="inline-flex items-center gap-1 p-1 bg-slate-100 rounded-lg">
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
                  {mode === 'all' ? 'All Radios' : mode === 'flagged' ? 'Flagged Only' : 'Pinned Baselines'}
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

          <button
            type="button"
            onClick={() => setShowCustomForm((prev) => !prev)}
            aria-expanded={showCustomForm}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 min-h-[38px] text-xs font-medium text-slate-800 bg-slate-100 rounded-lg hover:bg-slate-200 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
            <span>{showCustomForm ? 'Close Custom Beacon' : 'Add Test Beacon'}</span>
          </button>
        </div>

        {/* Collapsible Custom Beacon Form */}
        {showCustomForm && (
          <form onSubmit={handleCustomSubmit} className="p-5 bg-slate-50 space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div>
                <label htmlFor="ap-ssid" className="block text-xs font-medium text-slate-700 mb-1">
                  Broadcast SSID
                </label>
                <input
                  id="ap-ssid"
                  type="text"
                  value={ssidInput}
                  onChange={(e) => setSsidInput(e.target.value)}
                  placeholder="CorpNet-5G"
                  className="w-full h-10 px-3 text-sm bg-white border border-slate-300 rounded-lg focus:outline-none focus:border-blue-600"
                />
              </div>

              <div>
                <label htmlFor="ap-bssid" className="block text-xs font-medium text-slate-700 mb-1">
                  Hardware BSSID (MAC)
                </label>
                <input
                  id="ap-bssid"
                  type="text"
                  value={bssidInput}
                  onChange={(e) => setBssidInput(e.target.value)}
                  placeholder="DE:AD:BE:EF:10:20"
                  className="w-full h-10 px-3 text-sm font-mono bg-white border border-slate-300 rounded-lg focus:outline-none focus:border-blue-600"
                />
              </div>

              <div>
                <label htmlFor="ap-proto" className="block text-xs font-medium text-slate-700 mb-1">
                  Security Protocol
                </label>
                <select
                  id="ap-proto"
                  value={protocolInput}
                  onChange={(e) => setProtocolInput(e.target.value as EncryptionProtocol)}
                  className="w-full h-10 px-3 text-sm bg-white border border-slate-300 rounded-lg focus:outline-none focus:border-blue-600"
                >
                  {Object.values(EncryptionProtocol).map((proto) => (
                    <option key={proto} value={proto}>
                      {proto}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label htmlFor="ap-rssi" className="block text-xs font-medium text-slate-700 mb-1">
                  Signal RSSI (dBm)
                </label>
                <input
                  id="ap-rssi"
                  type="number"
                  value={rssiInput}
                  onChange={(e) => setRssiInput(e.target.value)}
                  min={-100}
                  max={-10}
                  className="w-full h-10 px-3 text-sm font-mono tabular-nums bg-white border border-slate-300 rounded-lg focus:outline-none focus:border-blue-600"
                />
              </div>
            </div>

            {formError && (
              <p role="alert" className="text-xs font-medium text-red-700">
                {formError}
              </p>
            )}

            <div className="flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={() => {
                  setShowCustomForm(false);
                  setFormError(null);
                }}
                className="px-3.5 py-2 text-xs font-medium text-slate-700 hover:text-slate-950 cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-2 min-h-[38px] text-xs font-semibold text-white bg-slate-900 rounded-lg hover:bg-slate-800 cursor-pointer"
              >
                Inject Beacon into Scan
              </button>
            </div>
          </form>
        )}

        {/* High-Density Data Table */}
        {filteredFindings.length === 0 ? (
          <div className="p-10 text-center space-y-3">
            <Wifi className="w-6 h-6 text-slate-400 mx-auto" aria-hidden="true" />
            <p className="text-sm font-medium text-slate-900">No access points match the active filter</p>
            <p className="text-xs text-slate-500">
              Clear your search query or switch back to All Radios to inspect the full spectrum scan.
            </p>
            <button
              type="button"
              onClick={() => {
                setFilter('all');
                setSearchQuery('');
              }}
              className="px-4 py-2 text-xs font-semibold text-white bg-slate-900 rounded-lg hover:bg-slate-800 cursor-pointer"
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
                            <span className="ml-2 text-xs font-normal text-blue-700">· Associated</span>
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
                          <div className="mt-0.5 text-xs font-medium text-red-700">Evil Twin Suspect</div>
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
                              className="px-2.5 py-1 min-h-[32px] text-xs font-semibold text-slate-800 bg-slate-100 rounded-md hover:bg-slate-200 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
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
              Pinned BSSID baselines and link audit records are persisted strictly as authenticated AES-256-GCM ciphertexts with key-bound AAD—mirroring Android Keystore MasterKey storage.
            </p>
          </div>
          <span className="text-xs font-mono text-slate-500 tabular-nums shrink-0">
            {encryptedEntries.length} encrypted keyset record(s)
          </span>
        </div>

        <div className="divide-y divide-slate-200">
          {encryptedEntries.length === 0 ? (
            <p className="p-5 text-xs text-slate-500">Initializing AES-256-GCM MasterKey vault…</p>
          ) : (
            encryptedEntries.map((entry) => (
              <div key={entry.key} className="p-4 px-5 flex flex-col lg:flex-row lg:items-center justify-between gap-2 text-xs">
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
