import React, { useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  ShieldBan,
  ArrowRight,
  Loader2,
} from 'lucide-react';
import { RedirectHop, ThreatSeverity, UrlAnalysisResult } from '../security/types';
import { analyzeUrlSafety } from '../security/urlAnalyzer';
import { URL_TEST_VECTORS } from '../data/seedData';
import { AegisSecurityNative, isRunningOnAndroidNative } from '../native/aegisBridge';

interface LinkAnalyzerViewProps {
  recentAnalyses: UrlAnalysisResult[];
  onRecordAnalysis: (result: UrlAnalysisResult) => void;
  interceptedIntent?: { url: string; caller: string } | null;
}

export function LinkAnalyzerView({
  recentAnalyses,
  onRecordAnalysis,
  interceptedIntent,
}: LinkAnalyzerViewProps) {
  const [urlInput, setUrlInput] = useState(interceptedIntent?.url ?? URL_TEST_VECTORS[0].url);
  const [sourceCaller, setSourceCaller] = useState(
    interceptedIntent?.caller ?? URL_TEST_VECTORS[0].sourceApp
  );
  const [isExpanding, setIsExpanding] = useState(false);
  const [activeResult, setActiveResult] = useState<UrlAnalysisResult>(() =>
    interceptedIntent
      ? analyzeUrlSafety(interceptedIntent.url)
      : analyzeUrlSafety(
          URL_TEST_VECTORS[0].url,
          [
            {
              step: 1,
              url: 'https://bit.ly/3xCorpAuth',
              statusCode: 301,
              location: 'https://t.co/redirect-gateway-99',
              latencyMs: 42,
            },
            {
              step: 2,
              url: 'https://t.co/redirect-gateway-99',
              statusCode: 302,
              location: 'https://xn--pypal-4ve.com/signin/session-verify',
              latencyMs: 68,
            },
            {
              step: 3,
              url: 'https://xn--pypal-4ve.com/signin/session-verify',
              statusCode: 200,
              contentType: 'text/html; charset=utf-8',
              latencyMs: 95,
            },
          ],
          'https://xn--pypal-4ve.com/signin/session-verify',
          'deterministic-vector'
        )
  );
  const [interceptorFeedback, setInterceptorFeedback] = useState<string | null>(null);

  const runFullAnalysis = async (targetUrl: string) => {
    setInterceptorFeedback(null);
    const trimmed = targetUrl.trim();

    // Validate locally first before making network hop request
    const preliminary = analyzeUrlSafety(trimmed);
    if (!preliminary.validSyntax) {
      setActiveResult(preliminary);
      return;
    }

    setIsExpanding(true);
    try {
      if (isRunningOnAndroidNative()) {
        const nativeRes = await AegisSecurityNative.expandUrlNative({ url: trimmed });
        const fullResult = analyzeUrlSafety(
          trimmed,
          nativeRes.hops ?? [],
          nativeRes.finalUrl ?? trimmed,
          nativeRes.mode
        );
        setActiveResult(fullResult);
        onRecordAnalysis(fullResult);
      } else {
        const resp = await fetch('/api/expand-url', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: trimmed }),
        });

        if (resp.ok) {
          const data = (await resp.json()) as {
            mode?: string;
            finalUrl?: string;
            hops?: RedirectHop[];
          };
          const fullResult = analyzeUrlSafety(
            trimmed,
            data.hops ?? [],
            data.finalUrl ?? trimmed,
            data.mode
          );
          setActiveResult(fullResult);
          onRecordAnalysis(fullResult);
        } else {
          setActiveResult(preliminary);
          onRecordAnalysis(preliminary);
        }
      }
    } catch {
      setActiveResult(preliminary);
      onRecordAnalysis(preliminary);
    } finally {
      setIsExpanding(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    void runFullAnalysis(urlInput);
  };

  const handleSelectPreset = (url: string, caller: string) => {
    setUrlInput(url);
    setSourceCaller(caller);
    void runFullAnalysis(url);
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="space-y-1.5 max-w-3xl">
        <p className="text-xs font-medium text-slate-500">
          Android ACTION_VIEW Browser Picker Interceptor · Non-WebView Preflight
        </p>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-950">
          Link Safe-Guard &amp; Homograph URL Analyzer
        </h1>
        <p className="text-sm text-slate-600 leading-relaxed">
          Intercepts external links before launching the system browser, unrolls shortened redirect chains via non-rendering HTTP HEAD hops, and detects IDN Punycode homographs, typosquatting, and drive-by APK payloads.
        </p>
      </div>

      {/* URL Input & Preset Test Vectors */}
      <section
        aria-label="URL Verification Input"
        className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-200"
      >
        <form onSubmit={handleSubmit} className="p-5 sm:p-6 space-y-4">
          <div>
            <label htmlFor="url-analyzer-input" className="block text-xs font-semibold text-slate-700 mb-1.5">
              Incoming External Intent URI (Intent.ACTION_VIEW)
            </label>
            <div className="flex flex-col sm:flex-row gap-3">
              <input
                id="url-analyzer-input"
                type="text"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="https://bit.ly/... or https://example.com"
                className="flex-1 h-11 px-3.5 text-sm font-mono bg-slate-50 border border-slate-300 rounded-lg text-slate-950 placeholder:text-slate-400 focus:outline-none focus:bg-white focus:border-blue-600"
              />
              <button
                type="submit"
                disabled={isExpanding}
                className="inline-flex items-center justify-center gap-2 px-5 h-11 text-xs font-semibold text-white bg-blue-600 rounded-lg hover:bg-blue-700 disabled:opacity-60 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                {isExpanding ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin shrink-0" aria-hidden="true" />
                    <span>Tracing Hops…</span>
                  </>
                ) : (
                  <span>Analyze Link</span>
                )}
              </button>
            </div>
            {!activeResult.validSyntax && activeResult.errorMessage && (
              <p role="alert" className="mt-2 text-xs font-medium text-red-700">
                {activeResult.errorMessage}
              </p>
            )}
          </div>

          {/* Preset Threat & Clean Test Vectors */}
          <div className="space-y-2">
            <span className="block text-xs text-slate-500">
              Load threat vector or benign sample:
            </span>
            <div className="flex flex-wrap gap-2">
              {URL_TEST_VECTORS.map((vec) => {
                const isSelected = urlInput === vec.url;
                return (
                  <button
                    key={vec.label}
                    type="button"
                    onClick={() => handleSelectPreset(vec.url, vec.sourceApp)}
                    className={`px-3 py-1.5 min-h-[34px] text-xs font-medium rounded-lg transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      isSelected
                        ? 'bg-slate-900 text-white'
                        : 'bg-slate-100 text-slate-700 hover:bg-slate-200 hover:text-slate-950'
                    }`}
                  >
                    {vec.label}
                  </button>
                );
              })}
            </div>
          </div>
        </form>

        {/* Detailed Analysis Grid */}
        {activeResult.validSyntax && (
          <div className="grid grid-cols-1 lg:grid-cols-12 divide-y lg:divide-y-0 lg:divide-x divide-slate-200">
            {/* Left 7 cols: Redirect Chain, Homograph Character Breakdown & Heuristics */}
            <div className="lg:col-span-7 divide-y divide-slate-200">
              {/* Verdict Header */}
              <div className="p-5 sm:p-6 space-y-2">
                <div className="flex items-center justify-between gap-4">
                  <div className="text-xs text-slate-500">
                    Scheme: <span className="font-mono text-slate-800">{activeResult.scheme}</span> · Registrable Domain:{' '}
                    <span className="font-mono text-slate-800">{activeResult.registrableDomain}</span>
                  </div>
                  {activeResult.severity === ThreatSeverity.CRITICAL ? (
                    <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-red-700">
                      <ShieldBan className="w-4 h-4 shrink-0" aria-hidden="true" />
                      <span>Critical Threat — Block Launch</span>
                    </span>
                  ) : activeResult.severity === ThreatSeverity.WARNING ? (
                    <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-amber-700">
                      <AlertTriangle className="w-4 h-4 shrink-0" aria-hidden="true" />
                      <span>Caution — Quarantine Prompt</span>
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-700">
                      <CheckCircle2 className="w-4 h-4 shrink-0" aria-hidden="true" />
                      <span>Verified Clean Destination</span>
                    </span>
                  )}
                </div>

                <div className="text-sm font-mono break-all text-slate-950 pt-1">
                  {activeResult.finalUrl}
                </div>

                {activeResult.impersonatedBrand && (
                  <p className="text-xs font-medium text-red-700 pt-1">
                    Impersonation Target: {activeResult.impersonatedBrand.brandDomain} · Technique:{' '}
                    {activeResult.impersonatedBrand.technique}
                  </p>
                )}

                {activeResult.safeBrowsingCategory && (
                  <p className="text-xs font-mono text-red-700">
                    Safe Browsing Classification: {activeResult.safeBrowsingCategory}
                  </p>
                )}
              </div>

              {/* Character-Level IDN Homograph / Confusable Inspector */}
              <div className="p-5 sm:p-6 space-y-3">
                <h2 className="text-sm font-bold text-slate-950">
                  Hostname &amp; Unicode Confusable Inspection
                </h2>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                  <div>
                    <span className="text-slate-500 block">Wire ASCII / Punycode Host</span>
                    <span className="font-mono font-medium text-slate-900 break-all">
                      {activeResult.rawHostname}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Rendered Unicode Display Host</span>
                    <span className="font-mono font-medium text-slate-900 break-all">
                      {activeResult.unicodeHostname}
                    </span>
                  </div>
                </div>

                {activeResult.confusableChars.length > 0 ? (
                  <div className="pt-2 space-y-2">
                    <p className="text-xs font-medium text-red-700">
                      Detected {activeResult.confusableChars.length} deceptive homoglyph code point(s):
                    </p>
                    <div className="space-y-1.5">
                      {activeResult.confusableChars.map((c) => (
                        <div
                          key={`${c.index}-${c.codePointHex}`}
                          className="text-xs font-mono text-slate-800 bg-slate-50 p-2.5 rounded-lg flex flex-wrap items-center justify-between gap-2"
                        >
                          <span>
                            Char index {c.index}: &ldquo;{c.char}&rdquo; ({c.codePointHex})
                          </span>
                          <span className="text-red-700">
                            {c.script} script spoofing Latin &ldquo;{c.latinLookalike}&rdquo;
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <p className="text-xs text-slate-600">
                    All hostname labels use single-script standard ASCII code points (U+002D–U+007A).
                  </p>
                )}
              </div>

              {/* Redirect Expansion Timeline */}
              <div className="p-5 sm:p-6 space-y-3">
                <div className="flex items-center justify-between">
                  <h2 className="text-sm font-bold text-slate-950">
                    Non-Rendering HTTP HEAD Redirect Chain
                  </h2>
                  <span className="text-xs text-slate-500 font-mono tabular-nums">
                    {activeResult.hops.length > 0 ? `${activeResult.hops.length} hop(s)` : 'Direct URI'}
                  </span>
                </div>

                {activeResult.hops.length === 0 ? (
                  <p className="text-xs text-slate-600">
                    Evaluated directly without intermediate HTTP 30x redirects.
                  </p>
                ) : (
                  <ol className="space-y-2.5 text-xs">
                    {activeResult.hops.map((hop) => (
                      <li key={hop.step} className="bg-slate-50 rounded-lg p-3 space-y-1">
                        <div className="flex items-center justify-between font-mono tabular-nums text-slate-600">
                          <span>
                            Hop {hop.step} · HTTP {hop.statusCode}
                          </span>
                          <span>{hop.latencyMs} ms</span>
                        </div>
                        <div className="font-mono text-slate-900 break-all">{hop.url}</div>
                        {hop.location && (
                          <div className="flex items-center gap-1.5 font-mono text-blue-700 break-all">
                            <ArrowRight className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
                            <span>{hop.location}</span>
                          </div>
                        )}
                        {hop.contentType && (
                          <div className="text-slate-500 font-mono">Content-Type: {hop.contentType}</div>
                        )}
                      </li>
                    ))}
                  </ol>
                )}
              </div>

              {/* Heuristic Findings List */}
              <div className="p-5 sm:p-6 space-y-2.5">
                <h2 className="text-sm font-bold text-slate-950">Heuristic &amp; Threat Feed Signals</h2>
                <ul className="space-y-1.5 text-xs text-slate-700 leading-relaxed list-disc pl-4">
                  {activeResult.findings.map((f, idx) => (
                    <li key={idx}>{f}</li>
                  ))}
                </ul>
              </div>
            </div>

            {/* Right 5 cols: Android LinkInterceptorActivity BottomSheet Simulation */}
            <div className="lg:col-span-5 p-5 sm:p-6 bg-slate-50/60 flex flex-col justify-between space-y-6">
              <div className="space-y-4">
                <div>
                  <h2 className="text-sm font-bold text-slate-950">
                    Android Intent Filter Overlay Simulation
                  </h2>
                  <p className="mt-0.5 text-xs text-slate-600">
                    Preview of LinkInterceptorActivity intercepting ACTION_VIEW from{' '}
                    <span className="font-medium text-slate-900">{sourceCaller}</span> before Chrome or WebView initializes.
                  </p>
                </div>

                {/* Simulated Android Handset BottomSheet Frame (flat clean elevation) */}
                <div className="bg-slate-900 text-white rounded-2xl p-5 space-y-4">
                  <div className="w-10 h-1 bg-slate-700 rounded-full mx-auto" aria-hidden="true" />

                  <div className="space-y-1">
                    <p className="text-[11px] text-slate-400">
                      Intercepted from {sourceCaller} · AegisLocal Browser Guard
                    </p>
                    <h3 className="text-base font-bold text-white">
                      {activeResult.verdictAction === 'BLOCK_INTENT'
                        ? 'Deceptive or Malicious Link Blocked'
                        : activeResult.verdictAction === 'QUARANTINE_WARNING'
                        ? 'Unverified Transport — Proceed with Caution'
                        : 'Destination Verified Safe'}
                    </h3>
                  </div>

                  <div className="bg-slate-800/90 rounded-xl p-3.5 space-y-1.5 text-xs">
                    <div className="text-slate-400">True Final Destination:</div>
                    <div className="font-mono text-slate-100 break-all">{activeResult.finalUrl}</div>
                    {activeResult.dangerousPayloadExtension && (
                      <div className="text-red-300 font-medium pt-1">
                        Binary Payload Alert: {activeResult.dangerousPayloadExtension} package download blocked
                      </div>
                    )}
                  </div>

                  <div className="space-y-1.5 text-xs text-slate-300">
                    {activeResult.findings.slice(0, 2).map((item, i) => (
                      <p key={i}>• {item}</p>
                    ))}
                  </div>

                  <div className="grid grid-cols-2 gap-2.5 pt-2">
                    <button
                      type="button"
                      onClick={() =>
                        setInterceptorFeedback(
                          'Intent terminated via finish(). Default browser was never spawned.'
                        )
                      }
                      className="min-h-[42px] px-3 py-2 text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-white rounded-xl transition-colors cursor-pointer"
                    >
                      Close &amp; Block
                    </button>

                    <button
                      type="button"
                      onClick={() => {
                        if (isRunningOnAndroidNative()) {
                          void AegisSecurityNative.openVerifiedExternalBrowser({
                            url: activeResult.finalUrl,
                          });
                        }
                        setInterceptorFeedback(
                          activeResult.verdictAction === 'ALLOW_BROWSER_LAUNCH'
                            ? 'Explicit Intent(ACTION_VIEW) dispatched to external browser.'
                            : 'User override logged to EncryptedSharedPreferences; explicit browser intent isolated.'
                        );
                      }}
                      className={`min-h-[42px] px-3 py-2 text-xs font-semibold rounded-xl inline-flex items-center justify-center gap-1.5 transition-colors cursor-pointer ${
                        activeResult.verdictAction === 'ALLOW_BROWSER_LAUNCH'
                          ? 'bg-blue-600 hover:bg-blue-500 text-white'
                          : 'bg-red-700 hover:bg-red-600 text-white'
                      }`}
                    >
                      <span>
                        {activeResult.verdictAction === 'ALLOW_BROWSER_LAUNCH'
                          ? 'Open Browser'
                          : 'Override Block'}
                      </span>
                      <ExternalLink className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
                    </button>
                  </div>

                  {interceptorFeedback && (
                    <p role="status" className="text-xs font-mono text-blue-300 pt-1">
                      {interceptorFeedback}
                    </p>
                  )}
                </div>
              </div>

              {/* Encrypted Audit History */}
              {recentAnalyses.length > 0 && (
                <div className="space-y-2 pt-2 border-t border-slate-200">
                  <h3 className="text-xs font-semibold text-slate-700">
                    Recent Vault-Logged URL Inspections ({recentAnalyses.length})
                  </h3>
                  <ul className="space-y-1.5 text-xs">
                    {recentAnalyses.slice(0, 4).map((item, idx) => (
                      <li key={`${item.inputUrl}-${idx}`} className="flex items-center justify-between gap-2">
                        <button
                          type="button"
                          onClick={() => {
                            setUrlInput(item.inputUrl);
                            setActiveResult(item);
                          }}
                          className="font-mono text-slate-700 hover:text-blue-700 truncate text-left cursor-pointer"
                        >
                          {item.inputUrl}
                        </button>
                        <span className="text-slate-500 shrink-0">{item.severity}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
