import React, { useMemo, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Smartphone,
  Plus,
} from 'lucide-react';
import {
  DeviceHealthState,
  InstalledAppPackage,
  ThreatSeverity,
} from '../security/types';
import {
  auditInstalledPackages,
  evaluateDevicePosture,
  HIGH_RISK_PERMISSIONS,
} from '../security/deviceAuditor';

interface DeviceAuditorViewProps {
  packages: InstalledAppPackage[];
  deviceHealth: DeviceHealthState;
  onUpdateDeviceHealth: (next: DeviceHealthState) => void;
  onAddPackage: (pkg: InstalledAppPackage) => void;
  onUninstallPackage: (packageName: string) => void;
}

type PackageRiskFilter = 'all' | 'critical' | 'warning' | 'nominal';

export function DeviceAuditorView({
  packages,
  deviceHealth,
  onUpdateDeviceHealth,
  onAddPackage,
  onUninstallPackage,
}: DeviceAuditorViewProps) {
  const [riskFilter, setRiskFilter] = useState<PackageRiskFilter>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedPkg, setExpandedPkg] = useState<string | null>('com.fin.invoiceviewer.helper');
  const [showAddForm, setShowAddForm] = useState(false);

  // Custom package simulator state
  const [customAppName, setCustomAppName] = useState('');
  const [customPkgName, setCustomPkgName] = useState('');
  const [customSideloaded, setCustomSideloaded] = useState(true);
  const [customA11y, setCustomA11y] = useState(true);
  const [customOverlay, setCustomOverlay] = useState(true);
  const [customSms, setCustomSms] = useState(true);
  const [pkgFormError, setPkgFormError] = useState<string | null>(null);

  const posture = useMemo(() => evaluateDevicePosture(deviceHealth), [deviceHealth]);
  const packageAudits = useMemo(() => auditInstalledPackages(packages), [packages]);

  const filteredPackages = useMemo(() => {
    return packageAudits.filter((item) => {
      if (riskFilter === 'critical' && item.severity !== ThreatSeverity.CRITICAL) return false;
      if (riskFilter === 'warning' && item.severity !== ThreatSeverity.WARNING) return false;
      if (riskFilter === 'nominal' && item.severity !== ThreatSeverity.NOMINAL) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.trim().toLowerCase();
        return (
          item.pkg.appName.toLowerCase().includes(q) ||
          item.pkg.packageName.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [packageAudits, riskFilter, searchQuery]);

  const criticalPkgCount = packageAudits.filter((a) => a.severity === ThreatSeverity.CRITICAL).length;

  const handleCreateCustomPackage = (e: React.FormEvent) => {
    e.preventDefault();
    const cleanName = customAppName.trim();
    const cleanPkg = customPkgName.trim().toLowerCase();
    if (!cleanName) {
      setPkgFormError('Application label is required.');
      return;
    }
    if (!/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/.test(cleanPkg)) {
      setPkgFormError('Enter a valid Java/Android package identifier (for example, com.spy.clipper).');
      return;
    }

    const perms: string[] = ['android.permission.INTERNET'];
    if (customA11y) perms.push('android.permission.BIND_ACCESSIBILITY_SERVICE');
    if (customOverlay) perms.push('android.permission.SYSTEM_ALERT_WINDOW');
    if (customSms) perms.push('android.permission.RECEIVE_SMS', 'android.permission.READ_SMS');

    setPkgFormError(null);
    onAddPackage({
      packageName: cleanPkg,
      appName: cleanName,
      installerSource: customSideloaded ? 'com.chrome.downloader' : 'com.android.vending',
      versionName: '1.0.0',
      targetSdk: customSideloaded ? 29 : 34,
      hasLauncherIcon: true,
      enabledAccessibilityService: customA11y,
      canDrawOverlays: customOverlay,
      permissions: perms,
    });
    setCustomAppName('');
    setCustomPkgName('');
    setShowAddForm(false);
    setExpandedPkg(cleanPkg);
  };

  const renderStatus = (sev: ThreatSeverity) => {
    if (sev === ThreatSeverity.CRITICAL) {
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-red-700 whitespace-nowrap">
          <AlertTriangle className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
          <span>Critical</span>
        </span>
      );
    }
    if (sev === ThreatSeverity.WARNING) {
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
      {/* Header */}
      <div className="space-y-1.5 max-w-3xl">
        <p className="text-xs font-medium text-slate-500">
          PackageManager + AccessibilityManager + Keyguard Posture Auditor
        </p>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-950">
          Permission &amp; Device Health Checklist
        </h1>
        <p className="text-sm text-slate-600 leading-relaxed">
          Audits installed user-space APKs for spyware and banking-trojan permission combinations (Accessibility control, Draw-Over-Apps tapjacking, SMS OTP interception) alongside OS security patch and hardware lock state.
        </p>
      </div>

      {/* Section 1: Interactive Android Device Health Checklist */}
      <section
        aria-label="Android OS and Hardware Posture Checklist"
        className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-200"
      >
        <div className="p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-base font-bold text-slate-950">
              OS Security Patch, Lock Screen &amp; Play Protect State
            </h2>
            <p className="text-xs text-slate-600 mt-0.5">
              Toggle hardware/OS states below to test real-time Android posture evaluation (Patch Age: {posture.patchAgeDays}d).
            </p>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs text-slate-500">Overall Device Posture:</span>
            {renderStatus(posture.overallSeverity)}
          </div>
        </div>

        {/* Interactive Posture Controls (Single-Elevation Hairline Grid) */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 divide-y sm:divide-y-0 sm:divide-x divide-slate-200 bg-slate-50/60 text-xs">
          <button
            type="button"
            onClick={() =>
              onUpdateDeviceHealth({
                ...deviceHealth,
                deviceLockSecure: !deviceHealth.deviceLockSecure,
                lockMethod: !deviceHealth.deviceLockSecure ? 'Biometric + PIN' : 'Swipe Only',
              })
            }
            aria-pressed={deviceHealth.deviceLockSecure}
            className="p-4 text-left hover:bg-slate-100/80 transition-colors cursor-pointer"
          >
            <div className="font-semibold text-slate-900">Toggle Screen Lock</div>
            <div className="mt-1 text-slate-600">{deviceHealth.lockMethod}</div>
          </button>

          <button
            type="button"
            onClick={() =>
              onUpdateDeviceHealth({
                ...deviceHealth,
                securityPatchDate:
                  deviceHealth.securityPatchDate === '2026-10-05' ? '2026-04-01' : '2026-10-05',
              })
            }
            className="p-4 text-left hover:bg-slate-100/80 transition-colors cursor-pointer"
          >
            <div className="font-semibold text-slate-900">Cycle OS Patch Age</div>
            <div className="mt-1 font-mono tabular-nums text-slate-600">
              {deviceHealth.securityPatchDate} ({posture.patchAgeDays}d)
            </div>
          </button>

          <button
            type="button"
            onClick={() =>
              onUpdateDeviceHealth({
                ...deviceHealth,
                playProtectEnabled: !deviceHealth.playProtectEnabled,
              })
            }
            aria-pressed={deviceHealth.playProtectEnabled}
            className="p-4 text-left hover:bg-slate-100/80 transition-colors cursor-pointer"
          >
            <div className="font-semibold text-slate-900">Toggle Play Protect</div>
            <div className="mt-1 text-slate-600">
              {deviceHealth.playProtectEnabled ? 'Enabled (VerifyApps)' : 'Disabled'}
            </div>
          </button>

          <button
            type="button"
            onClick={() =>
              onUpdateDeviceHealth({
                ...deviceHealth,
                adbDebuggingEnabled: !deviceHealth.adbDebuggingEnabled,
              })
            }
            aria-pressed={deviceHealth.adbDebuggingEnabled}
            className="p-4 text-left hover:bg-slate-100/80 transition-colors cursor-pointer"
          >
            <div className="font-semibold text-slate-900">Toggle USB / Wi-Fi ADB</div>
            <div className="mt-1 text-slate-600">
              {deviceHealth.adbDebuggingEnabled ? 'Enabled (Exposed)' : 'Disabled'}
            </div>
          </button>

          <button
            type="button"
            onClick={() =>
              onUpdateDeviceHealth({
                ...deviceHealth,
                unknownSourcesAllowed: !deviceHealth.unknownSourcesAllowed,
              })
            }
            aria-pressed={deviceHealth.unknownSourcesAllowed}
            className="p-4 text-left hover:bg-slate-100/80 transition-colors cursor-pointer"
          >
            <div className="font-semibold text-slate-900">Toggle Unknown Sources</div>
            <div className="mt-1 text-slate-600">
              {deviceHealth.unknownSourcesAllowed ? '1 Browser Permitted' : 'Blocked'}
            </div>
          </button>
        </div>

        {/* Checklist Verification Rows */}
        <div className="divide-y divide-slate-200">
          {posture.checks.map((check) => (
            <div
              key={check.id}
              className="p-4 px-5 flex flex-col md:flex-row md:items-center justify-between gap-2 text-sm"
            >
              <div className="space-y-0.5">
                <div className="font-semibold text-slate-950">{check.label}</div>
                <p className="text-xs text-slate-600">{check.detail}</p>
              </div>
              <div className="flex items-center gap-4 shrink-0">
                <span className="text-xs font-mono text-slate-400">{check.androidApiSource}</span>
                {renderStatus(check.status)}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Section 2: Installed App Permission & Spyware Scanner */}
      <section
        aria-label="Installed Package Permission Scanner"
        className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-200"
      >
        <div className="p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-3">
            <div
              role="group"
              aria-label="Filter installed packages by risk"
              className="inline-flex items-center gap-1 p-1 bg-slate-100 rounded-lg"
            >
              {(['all', 'critical', 'warning', 'nominal'] as const).map((tier) => (
                <button
                  key={tier}
                  type="button"
                  onClick={() => setRiskFilter(tier)}
                  className={`px-3 py-1.5 min-h-[34px] text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    riskFilter === tier
                      ? 'bg-white text-slate-950 shadow-xs'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {tier === 'all'
                    ? `All (${packages.length})`
                    : tier === 'critical'
                    ? `Critical (${criticalPkgCount})`
                    : tier === 'warning'
                    ? 'Warning'
                    : 'Nominal'}
                </button>
              ))}
            </div>

            <div>
              <label htmlFor="pkg-search" className="sr-only">
                Search package name or app label
              </label>
              <input
                id="pkg-search"
                type="search"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search app or package…"
                className="h-9 px-3 text-xs bg-slate-50 border border-slate-200 rounded-lg text-slate-900 placeholder:text-slate-400 focus:outline-none focus:border-blue-600"
              />
            </div>
          </div>

          <button
            type="button"
            onClick={() => setShowAddForm((prev) => !prev)}
            aria-expanded={showAddForm}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 min-h-[38px] text-xs font-medium text-slate-800 bg-slate-100 rounded-lg hover:bg-slate-200 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
            <span>{showAddForm ? 'Close Simulator' : 'Simulate Sideloaded APK'}</span>
          </button>
        </div>

        {/* Custom Package Simulator Form */}
        {showAddForm && (
          <form onSubmit={handleCreateCustomPackage} className="p-5 bg-slate-50 space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label htmlFor="custom-app-label" className="block text-xs font-medium text-slate-700 mb-1">
                  Application Label
                </label>
                <input
                  id="custom-app-label"
                  type="text"
                  value={customAppName}
                  onChange={(e) => setCustomAppName(e.target.value)}
                  placeholder="Crypto Clipboard Guard"
                  className="w-full h-10 px-3 text-sm bg-white border border-slate-300 rounded-lg focus:outline-none focus:border-blue-600"
                />
              </div>

              <div>
                <label htmlFor="custom-pkg-id" className="block text-xs font-medium text-slate-700 mb-1">
                  Android Package Name
                </label>
                <input
                  id="custom-pkg-id"
                  type="text"
                  value={customPkgName}
                  onChange={(e) => setCustomPkgName(e.target.value)}
                  placeholder="com.clipper.wallet.overlay"
                  className="w-full h-10 px-3 text-sm font-mono bg-white border border-slate-300 rounded-lg focus:outline-none focus:border-blue-600"
                />
              </div>
            </div>

            <div className="flex flex-wrap gap-5 text-xs text-slate-800">
              <label className="inline-flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={customSideloaded}
                  onChange={(e) => setCustomSideloaded(e.target.checked)}
                />
                <span>Sideloaded via Browser APK</span>
              </label>
              <label className="inline-flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={customA11y}
                  onChange={(e) => setCustomA11y(e.target.checked)}
                />
                <span>BIND_ACCESSIBILITY_SERVICE</span>
              </label>
              <label className="inline-flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={customOverlay}
                  onChange={(e) => setCustomOverlay(e.target.checked)}
                />
                <span>SYSTEM_ALERT_WINDOW (Overlay)</span>
              </label>
              <label className="inline-flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={customSms}
                  onChange={(e) => setCustomSms(e.target.checked)}
                />
                <span>RECEIVE_SMS / READ_SMS</span>
              </label>
            </div>

            {pkgFormError && (
              <p role="alert" className="text-xs font-medium text-red-700">
                {pkgFormError}
              </p>
            )}

            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowAddForm(false)}
                className="px-3.5 py-2 text-xs font-medium text-slate-600 hover:text-slate-900 cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-2 min-h-[38px] text-xs font-semibold text-white bg-slate-900 rounded-lg hover:bg-slate-800 cursor-pointer"
              >
                Audit Simulated Package
              </button>
            </div>
          </form>
        )}

        {/* Package Rows */}
        {filteredPackages.length === 0 ? (
          <div className="p-10 text-center space-y-3">
            <Smartphone className="w-6 h-6 text-slate-400 mx-auto" aria-hidden="true" />
            <p className="text-sm font-medium text-slate-900">No installed packages match this filter</p>
            <button
              type="button"
              onClick={() => {
                setRiskFilter('all');
                setSearchQuery('');
              }}
              className="px-4 py-2 text-xs font-semibold text-white bg-slate-900 rounded-lg hover:bg-slate-800 cursor-pointer"
            >
              Show All Packages
            </button>
          </div>
        ) : (
          <div className="divide-y divide-slate-200">
            {filteredPackages.map(({ pkg, severity, flaggedPermissions, threatPatterns, remediation }) => {
              const isExpanded = expandedPkg === pkg.packageName;
              return (
                <div key={pkg.packageName} className="p-5 space-y-3">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div className="space-y-0.5">
                      <div className="flex items-center gap-2.5">
                        <span className="font-bold text-slate-950 text-sm">{pkg.appName}</span>
                        {renderStatus(severity)}
                      </div>
                      <div className="text-xs text-slate-500 font-mono tabular-nums">
                        {pkg.packageName} · v{pkg.versionName} · targetSdk {pkg.targetSdk} · Installer:{' '}
                        {pkg.installerSource}
                        {!pkg.hasLauncherIcon ? ' · Hidden Launcher Icon' : ''}
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      {severity !== ThreatSeverity.NOMINAL && pkg.installerSource !== 'system-preload' && (
                        <button
                          type="button"
                          onClick={() => onUninstallPackage(pkg.packageName)}
                          aria-label={`Quarantine and remove ${pkg.appName}`}
                          className="px-3 py-1.5 min-h-[34px] text-xs font-semibold text-red-700 bg-red-50 hover:bg-red-100 rounded-lg transition-colors whitespace-nowrap cursor-pointer"
                        >
                          Remove Package
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={() => setExpandedPkg(isExpanded ? null : pkg.packageName)}
                        aria-expanded={isExpanded}
                        aria-label={`${isExpanded ? 'Collapse' : 'Inspect'} permissions for ${pkg.appName}`}
                        className="inline-flex items-center gap-1 px-3 py-1.5 min-h-[34px] text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors whitespace-nowrap cursor-pointer"
                      >
                        <span>{isExpanded ? 'Hide Manifest' : 'Inspect Manifest'}</span>
                        {isExpanded ? (
                          <ChevronUp className="w-3.5 h-3.5" aria-hidden="true" />
                        ) : (
                          <ChevronDown className="w-3.5 h-3.5" aria-hidden="true" />
                        )}
                      </button>
                    </div>
                  </div>

                  <ul className="space-y-1 text-xs text-slate-700">
                    {threatPatterns.map((pt, i) => (
                      <li key={i}>{pt}</li>
                    ))}
                  </ul>

                  {isExpanded && (
                    <div className="pt-2 space-y-2.5 text-xs bg-slate-50 rounded-lg p-4">
                      <div className="font-semibold text-slate-900">
                        Granted Sensitive Capabilities ({flaggedPermissions.length})
                      </div>
                      {flaggedPermissions.length === 0 ? (
                        <p className="text-slate-600">No high-risk spyware permissions granted.</p>
                      ) : (
                        <ul className="space-y-1.5">
                          {flaggedPermissions.map((perm) => (
                            <li key={perm} className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                              <span className="font-mono text-slate-900">{perm}</span>
                              <span className="text-slate-600">
                                {HIGH_RISK_PERMISSIONS[perm]?.label ?? 'Sensitive OS Permission'}
                              </span>
                            </li>
                          ))}
                        </ul>
                      )}
                      <p className="pt-1 text-slate-700 font-medium">
                        Recommended Action: <span className="font-normal">{remediation}</span>
                      </p>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}
