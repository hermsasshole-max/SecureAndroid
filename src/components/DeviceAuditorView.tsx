import { useMemo, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Loader2,
  RefreshCw,
  Smartphone,
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
import { isRunningOnAndroidNative } from '../native/aegisBridge';

interface DeviceAuditorViewProps {
  packages: InstalledAppPackage[];
  deviceHealth: DeviceHealthState | null;
  isAuditing: boolean;
  auditMessage?: string | null;
  onRefreshAudit: () => void;
  onOpenAppSettings: (packageName: string) => void;
}

type PackageRiskFilter = 'all' | 'critical' | 'warning' | 'nominal';

export function DeviceAuditorView({
  packages,
  deviceHealth,
  isAuditing,
  auditMessage,
  onRefreshAudit,
  onOpenAppSettings,
}: DeviceAuditorViewProps) {
  const [riskFilter, setRiskFilter] = useState<PackageRiskFilter>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedPkg, setExpandedPkg] = useState<string | null>(null);

  const posture = useMemo(
    () => (deviceHealth ? evaluateDevicePosture(deviceHealth) : null),
    [deviceHealth]
  );
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

  const criticalPkgCount = packageAudits.filter(
    (a) => a.severity === ThreatSeverity.CRITICAL
  ).length;

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
      {/* Header & Live Scan CTA */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
        <div className="space-y-1.5 max-w-2xl">
          <p className="text-xs font-medium text-slate-500">
            PackageManager + AccessibilityManager + Keyguard Posture Auditor
          </p>
          <h1
            className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-950"
            style={{ textWrap: 'balance' }}
          >
            Permission &amp; Device Health Auditor
          </h1>
          <p className="text-sm text-slate-600 leading-relaxed">
            Scans installed user-space APKs for spyware and banking-trojan permission combinations (Accessibility control, Draw-Over-Apps tapjacking, SMS OTP access) alongside OS security patch and hardware lock state.
          </p>
        </div>

        <button
          type="button"
          onClick={onRefreshAudit}
          disabled={isAuditing}
          className="inline-flex items-center gap-2 px-4 py-2 min-h-[42px] text-xs font-semibold text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-60 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
        >
          {isAuditing ? (
            <Loader2 className="w-4 h-4 animate-spin shrink-0" aria-hidden="true" />
          ) : (
            <RefreshCw className="w-4 h-4 shrink-0" aria-hidden="true" />
          )}
          <span>{isAuditing ? 'Auditing Device…' : 'Run Device Audit'}</span>
        </button>
      </div>

      {auditMessage && (
        <p role="status" className="text-xs font-medium text-slate-700 bg-white border border-slate-200 rounded-lg px-4 py-2.5">
          {auditMessage}
        </p>
      )}

      {/* Section 1: Android Device Health Checklist */}
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
              Live hardware Keyguard, SELinux, ADB debugging, and OS security patch verification.
            </p>
          </div>
          {posture && (
            <div className="flex items-center gap-3">
              <span className="text-xs text-slate-500">Overall Device Posture:</span>
              {renderStatus(posture.overallSeverity)}
            </div>
          )}
        </div>

        {!posture ? (
          <div className="p-8 text-center space-y-2.5">
            <Smartphone className="w-6 h-6 text-slate-400 mx-auto" aria-hidden="true" />
            <p className="text-sm font-medium text-slate-900">
              No Android OS posture telemetry captured yet
            </p>
            <p className="text-xs text-slate-500 max-w-md mx-auto">
              {isRunningOnAndroidNative()
                ? 'Tap Run Device Audit to read Keyguard lock state, OS security patch date, Play Protect, and ADB status.'
                : 'Hardware Keyguard, SELinux, and Settings.Global ADB queries require the native Android APK runtime.'}
            </p>
          </div>
        ) : (
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
        )}
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
        </div>

        {packages.length === 0 ? (
          <div className="p-10 text-center space-y-3">
            <Smartphone className="w-6 h-6 text-slate-400 mx-auto" aria-hidden="true" />
            <p className="text-sm font-medium text-slate-900">
              No installed user packages scanned
            </p>
            <p className="text-xs text-slate-500 max-w-md mx-auto">
              {isRunningOnAndroidNative()
                ? 'Tap Run Device Audit to inspect installed applications for Accessibility, Overlay, and SMS spyware permissions.'
                : 'PackageManager enumeration runs exclusively on Android devices inside the compiled APK.'}
            </p>
            <button
              type="button"
              onClick={onRefreshAudit}
              disabled={isAuditing}
              className="px-4 py-2 min-h-[40px] text-xs font-semibold text-white bg-slate-900 rounded-lg hover:bg-slate-800 disabled:opacity-60 cursor-pointer"
            >
              {isAuditing ? 'Scanning…' : 'Scan Installed Apps'}
            </button>
          </div>
        ) : filteredPackages.length === 0 ? (
          <div className="p-10 text-center space-y-3">
            <Smartphone className="w-6 h-6 text-slate-400 mx-auto" aria-hidden="true" />
            <p className="text-sm font-medium text-slate-900">
              No installed packages match this filter
            </p>
            <button
              type="button"
              onClick={() => {
                setRiskFilter('all');
                setSearchQuery('');
              }}
              className="px-4 py-2 min-h-[40px] text-xs font-semibold text-white bg-slate-900 rounded-lg hover:bg-slate-800 cursor-pointer"
            >
              Show All Packages
            </button>
          </div>
        ) : (
          <div className="divide-y divide-slate-200">
            {filteredPackages.map(
              ({ pkg, severity, flaggedPermissions, threatPatterns, remediation }) => {
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
                        {isRunningOnAndroidNative() && (
                          <button
                            type="button"
                            onClick={() => onOpenAppSettings(pkg.packageName)}
                            aria-label={`Open Android App Settings for ${pkg.appName}`}
                            className="inline-flex items-center gap-1 px-3 py-1.5 min-h-[36px] text-xs font-semibold text-slate-800 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors whitespace-nowrap cursor-pointer"
                          >
                            <span>App Settings</span>
                            <ExternalLink className="w-3.5 h-3.5" aria-hidden="true" />
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => setExpandedPkg(isExpanded ? null : pkg.packageName)}
                          aria-expanded={isExpanded}
                          aria-label={`${isExpanded ? 'Collapse' : 'Inspect'} permissions for ${pkg.appName}`}
                          className="inline-flex items-center gap-1 px-3 py-1.5 min-h-[36px] text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors whitespace-nowrap cursor-pointer"
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
                              <li
                                key={perm}
                                className="flex flex-col sm:flex-row sm:items-center justify-between gap-1"
                              >
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
              }
            )}
          </div>
        )}
      </section>
    </div>
  );
}
