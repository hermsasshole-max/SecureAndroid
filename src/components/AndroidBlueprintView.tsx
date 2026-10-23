import { useState } from 'react';
import { Check, Copy, Download } from 'lucide-react';
import { ARCHITECTURE_LAYERS, BLUEPRINT_FILES } from '../data/androidBlueprints';

interface AndroidBlueprintViewProps {
  onExportBundle: () => void;
}

type BlueprintSection = 'overview' | 'manifest' | 'kotlin' | 'ui' | 'cicd';

export function AndroidBlueprintView({ onExportBundle }: AndroidBlueprintViewProps) {
  const [section, setSection] = useState<BlueprintSection>('overview');
  const [selectedKotlinId, setSelectedKotlinId] = useState<string>('vpn-service');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const manifestFiles = BLUEPRINT_FILES.filter((f) => f.id === 'manifest' || f.id === 'gradle');
  const coreKotlinFiles = BLUEPRINT_FILES.filter((f) =>
    ['encrypted-store', 'wifi-inspector', 'vpn-service', 'url-analyzer', 'device-auditor'].includes(f.id)
  );
  const uiIntegrationFile = BLUEPRINT_FILES.find((f) => f.id === 'ui-interceptor')!;
  const cicdFiles = BLUEPRINT_FILES.filter(
    (f) => f.id === 'github-actions-apk' || f.id === 'capacitor-plugin'
  );
  const activeKotlinFile =
    coreKotlinFiles.find((f) => f.id === selectedKotlinId) ?? coreKotlinFiles[0];

  const handleCopy = async (id: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId((prev) => (prev === id ? null : prev)), 1800);
    } catch {
      setCopiedId(null);
    }
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-4">
        <div className="space-y-1.5 max-w-3xl">
          <p className="text-xs font-medium text-slate-500">
            Capacitor 8 + Android SDK 36 · Kotlin 2.2 + GitHub Actions APK Pipeline
          </p>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-950">
            Android Security Architecture &amp; Source Code
          </h1>
          <p className="text-sm text-slate-600 leading-relaxed">
            Modular, non-root Android implementation structured into Architecture Overview, Manifest Permissions, Core Kotlin Modules (VpnService, EncryptedSharedPreferences, SpoofChecker), Compose Interceptor UI, and GitHub Actions Capacitor APK CI.
          </p>
        </div>

        <button
          type="button"
          onClick={onExportBundle}
          className="inline-flex items-center gap-2 px-4 py-2.5 min-h-[40px] text-xs font-semibold text-white bg-blue-600 rounded-lg hover:bg-blue-700 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
        >
          <Download className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
          <span>Download Complete Markdown Spec</span>
        </button>
      </div>

      {/* Section Selector */}
      <div
        role="group"
        aria-label="Blueprint Architecture Sections"
        className="inline-flex flex-wrap items-center gap-1 p-1 bg-slate-200/70 rounded-xl"
      >
        {(
          [
            { id: 'overview', label: '01. Architecture Overview' },
            { id: 'manifest', label: '02. AndroidManifest & Gradle' },
            { id: 'kotlin', label: '03. Core Implementation (Kotlin)' },
            { id: 'ui', label: '04. UI Integration' },
            { id: 'cicd', label: '05. GitHub CI & Capacitor APK' },
          ] as const
        ).map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setSection(tab.id)}
            className={`px-3.5 py-2 min-h-[38px] text-xs font-semibold rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
              section === tab.id
                ? 'bg-white text-slate-950 shadow-xs'
                : 'text-slate-600 hover:text-slate-950'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* 01. Architecture Overview */}
      {section === 'overview' && (
        <div className="space-y-6">
          {/* Dataflow Topology Diagram */}
          <section className="bg-white border border-slate-200 rounded-xl p-6 space-y-4">
            <h2 className="text-base font-bold text-slate-950">
              On-Device Privacy-First Execution Pipeline
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pt-1 text-xs">
              <div className="bg-slate-50 rounded-lg p-4 space-y-2">
                <div className="font-mono text-blue-700 font-semibold">
                  Layer A · Radio &amp; Loopback Plane
                </div>
                <div className="font-semibold text-slate-900 text-sm">
                  WifiManager + Local VpnService (tun0)
                </div>
                <p className="text-slate-600 leading-relaxed">
                  Reads 802.11 ScanResults &amp; LinkProperties locally. Routes DNS/53 packets into an in-memory <code className="font-mono text-slate-800">ParcelFileDescriptor</code> (<code className="font-mono text-slate-800">10.215.173.1/30</code>) using <code className="font-mono text-slate-800">protect(DatagramSocket)</code> so zero traffic is sent to third-party VPN servers.
                </p>
              </div>

              <div className="bg-slate-50 rounded-lg p-4 space-y-2">
                <div className="font-mono text-blue-700 font-semibold">
                  Layer B · Intent Interceptor Plane
                </div>
                <div className="font-semibold text-slate-900 text-sm">
                  ACTION_VIEW Picker + ICU SpoofChecker
                </div>
                <p className="text-slate-600 leading-relaxed">
                  Intercepts external clicks prior to browser engine startup. Resolves <code className="font-mono text-slate-800">bit.ly</code> / <code className="font-mono text-slate-800">tinyurl</code> 30x hops via <code className="font-mono text-slate-800">HttpURLConnection</code> (<code className="font-mono text-slate-800">instanceFollowRedirects = false</code>) and evaluates Punycode confusables &amp; Safe Browsing hashes.
                </p>
              </div>

              <div className="bg-slate-50 rounded-lg p-4 space-y-2">
                <div className="font-mono text-blue-700 font-semibold">
                  Layer C · Hardware Keystore Plane
                </div>
                <div className="font-semibold text-slate-900 text-sm">
                  EncryptedSharedPreferences (TEE/StrongBox)
                </div>
                <p className="text-slate-600 leading-relaxed">
                  Persists trusted BSSID baselines, gateway MAC pins, and audit verdicts using <code className="font-mono text-slate-800">AES256_SIV</code> deterministic key encryption and <code className="font-mono text-slate-800">AES256_GCM</code> authenticated value ciphertexts backed by Android Keystore.
                </p>
              </div>
            </div>
          </section>

          {/* Editorial Numbered Architectural Deep-Dive */}
          <section className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-200">
            {ARCHITECTURE_LAYERS.map((layer) => (
              <div key={layer.number} className="p-6 space-y-2.5">
                <h3 className="text-base font-bold text-slate-950">
                  {layer.number}. {layer.title}
                </h3>
                <p className="text-sm text-slate-700">{layer.summary}</p>
                <ul className="space-y-1.5 text-xs text-slate-600 list-disc pl-4 pt-1">
                  {layer.details.map((d, idx) => (
                    <li key={idx}>{d}</li>
                  ))}
                </ul>
              </div>
            ))}
          </section>
        </div>
      )}

      {/* 02. Required Permissions (AndroidManifest.xml & build.gradle.kts) */}
      {section === 'manifest' && (
        <div className="space-y-6">
          {manifestFiles.map((file) => (
            <section
              key={file.id}
              className="bg-white border border-slate-200 rounded-xl overflow-hidden divide-y divide-slate-200"
            >
              <div className="p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <h2 className="text-base font-bold text-slate-950 font-mono">{file.path}</h2>
                  <p className="text-xs text-slate-600 mt-0.5">{file.summary}</p>
                </div>
                <button
                  type="button"
                  onClick={() => void handleCopy(file.id, file.code)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 min-h-[36px] text-xs font-semibold text-slate-800 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  {copiedId === file.id ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-700" aria-hidden="true" />
                      <span>Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                      <span>Copy {file.filename}</span>
                    </>
                  )}
                </button>
              </div>

              <div className="p-5 bg-slate-50 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div className="space-y-1">
                  <div className="font-semibold text-slate-900">Security Edge Cases</div>
                  <ul className="space-y-1 text-slate-600 list-disc pl-4">
                    {file.edgeCases.map((ec, i) => (
                      <li key={i}>{ec}</li>
                    ))}
                  </ul>
                </div>
                <div className="space-y-1">
                  <div className="font-semibold text-slate-900">Performance &amp; OS Limits</div>
                  <ul className="space-y-1 text-slate-600 list-disc pl-4">
                    {file.performanceNotes.map((pn, i) => (
                      <li key={i}>{pn}</li>
                    ))}
                  </ul>
                </div>
              </div>

              <pre className="p-5 bg-slate-950 text-slate-100 text-xs font-mono leading-relaxed overflow-x-auto">
                <code>{file.code}</code>
              </pre>
            </section>
          ))}
        </div>
      )}

      {/* 03. Core Implementation Code (Kotlin) */}
      {section === 'kotlin' && (
        <section className="bg-white border border-slate-200 rounded-xl overflow-hidden divide-y divide-slate-200">
          {/* Module Selector Bar */}
          <div className="p-4 bg-slate-50 flex flex-wrap items-center gap-1.5">
            {coreKotlinFiles.map((file) => {
              const isSelected = file.id === activeKotlinFile.id;
              return (
                <button
                  key={file.id}
                  type="button"
                  onClick={() => setSelectedKotlinId(file.id)}
                  className={`px-3 py-1.5 min-h-[36px] text-xs font-mono font-medium rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                    isSelected
                      ? 'bg-slate-900 text-white'
                      : 'text-slate-700 hover:bg-slate-200/70 hover:text-slate-950'
                  }`}
                >
                  {file.filename}
                </button>
              );
            })}
          </div>

          <div className="p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h2 className="text-base font-bold text-slate-950 font-mono">
                {activeKotlinFile.path}
              </h2>
              <p className="text-xs text-slate-600 mt-0.5">{activeKotlinFile.summary}</p>
            </div>
            <button
              type="button"
              onClick={() => void handleCopy(activeKotlinFile.id, activeKotlinFile.code)}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 min-h-[36px] text-xs font-semibold text-slate-800 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              {copiedId === activeKotlinFile.id ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-700" aria-hidden="true" />
                  <span>Copied Kotlin</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>Copy Code</span>
                </>
              )}
            </button>
          </div>

          <div className="p-5 bg-slate-50/70 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="space-y-1">
              <div className="font-semibold text-slate-900">Android Security Edge Cases</div>
              <ul className="space-y-1 text-slate-600 list-disc pl-4">
                {activeKotlinFile.edgeCases.map((ec, i) => (
                  <li key={i}>{ec}</li>
                ))}
              </ul>
            </div>
            <div className="space-y-1">
              <div className="font-semibold text-slate-900">Battery &amp; Throughput Implications</div>
              <ul className="space-y-1 text-slate-600 list-disc pl-4">
                {activeKotlinFile.performanceNotes.map((pn, i) => (
                  <li key={i}>{pn}</li>
                ))}
              </ul>
            </div>
          </div>

          <pre className="p-5 bg-slate-950 text-slate-100 text-xs font-mono leading-relaxed overflow-x-auto">
            <code>{activeKotlinFile.code}</code>
          </pre>
        </section>
      )}

      {/* 04. UI Integration (Jetpack Compose LinkInterceptorActivity) */}
      {section === 'ui' && (
        <section className="bg-white border border-slate-200 rounded-xl overflow-hidden divide-y divide-slate-200">
          <div className="p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h2 className="text-base font-bold text-slate-950 font-mono">
                {uiIntegrationFile.path}
              </h2>
              <p className="text-xs text-slate-600 mt-0.5">{uiIntegrationFile.summary}</p>
            </div>
            <button
              type="button"
              onClick={() => void handleCopy(uiIntegrationFile.id, uiIntegrationFile.code)}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 min-h-[36px] text-xs font-semibold text-slate-800 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              {copiedId === uiIntegrationFile.id ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-700" aria-hidden="true" />
                  <span>Copied</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                  <span>Copy Compose Activity</span>
                </>
              )}
            </button>
          </div>

          <div className="p-5 bg-slate-50 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            <div className="space-y-1">
              <div className="font-semibold text-slate-900">Intent Routing Edge Cases</div>
              <ul className="space-y-1 text-slate-600 list-disc pl-4">
                {uiIntegrationFile.edgeCases.map((ec, i) => (
                  <li key={i}>{ec}</li>
                ))}
              </ul>
            </div>
            <div className="space-y-1">
              <div className="font-semibold text-slate-900">UI Latency &amp; Lifecycle</div>
              <ul className="space-y-1 text-slate-600 list-disc pl-4">
                {uiIntegrationFile.performanceNotes.map((pn, i) => (
                  <li key={i}>{pn}</li>
                ))}
              </ul>
            </div>
          </div>

          <pre className="p-5 bg-slate-950 text-slate-100 text-xs font-mono leading-relaxed overflow-x-auto">
            <code>{uiIntegrationFile.code}</code>
          </pre>
        </section>
      )}

      {/* 05. GitHub Actions CI & Capacitor Native Bridge */}
      {section === 'cicd' && (
        <div className="space-y-6">
          {cicdFiles.map((file) => (
            <section
              key={file.id}
              className="bg-white border border-slate-200 rounded-xl overflow-hidden divide-y divide-slate-200"
            >
              <div className="p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <h2 className="text-base font-bold text-slate-950 font-mono">{file.path}</h2>
                  <p className="text-xs text-slate-600 mt-0.5">{file.summary}</p>
                </div>
                <button
                  type="button"
                  onClick={() => void handleCopy(file.id, file.code)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 min-h-[36px] text-xs font-semibold text-slate-800 bg-slate-100 hover:bg-slate-200 rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                >
                  {copiedId === file.id ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-700" aria-hidden="true" />
                      <span>Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" aria-hidden="true" />
                      <span>Copy {file.filename}</span>
                    </>
                  )}
                </button>
              </div>

              <div className="p-5 bg-slate-50 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div className="space-y-1">
                  <div className="font-semibold text-slate-900">Build &amp; Signing Notes</div>
                  <ul className="space-y-1 text-slate-600 list-disc pl-4">
                    {file.edgeCases.map((ec, i) => (
                      <li key={i}>{ec}</li>
                    ))}
                  </ul>
                </div>
                <div className="space-y-1">
                  <div className="font-semibold text-slate-900">CI Caching &amp; Runtime Throughput</div>
                  <ul className="space-y-1 text-slate-600 list-disc pl-4">
                    {file.performanceNotes.map((pn, i) => (
                      <li key={i}>{pn}</li>
                    ))}
                  </ul>
                </div>
              </div>

              <pre className="p-5 bg-slate-950 text-slate-100 text-xs font-mono leading-relaxed overflow-x-auto">
                <code>{file.code}</code>
              </pre>
            </section>
          ))}
        </div>
      )}
    </div>
  );
}
