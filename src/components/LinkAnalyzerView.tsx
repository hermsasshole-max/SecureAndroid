import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  ClipboardPaste,
  ExternalLink,
  Link2,
  Loader2,
  ShieldBan,
  Trash2,
} from 'lucide-react';
import { RedirectHop, ThreatSeverity, UrlAnalysisResult } from '../security/types';
import { analyzeUrlSafety } from '../security/urlAnalyzer';
import { AegisSecurityNative, isRunningOnAndroidNative } from '../native/aegisBridge';

interface LinkAnalyzerViewProps {
  recentAnalyses: UrlAnalysisResult[];
  onRecordAnalysis: (result: UrlAnalysisResult) => void;
  onClearHistory: () => void;
  interceptedIntent?: { url: string; caller: string } | null;
}

export function LinkAnalyzerView({
  recentAnalyses,
  onRecordAnalysis,
  onClearHistory,
  interceptedIntent,
}: LinkAnalyzerViewProps) {
  const [urlInput, setUrlInput] = useState(interceptedIntent?.url ?? '');
  const [sourceCaller, setSourceCaller] = useState(
    interceptedIntent?.caller ?? 'Manual Inspection'
  );
  const [isExpanding, setIsExpanding] = useState(false);
  const [activeResult, setActiveResult] = useState<UrlAnalysisResult | null>(() =>
    interceptedIntent ? analyzeUrlSafety(interceptedIntent.url) : null
  );
  const [validationError, setValidationError] = useState<string | null>(null);
  const [interceptorFeedback, setInterceptorFeedback] = useState<string | null>(null);

  useEffect(() => {
    if (interceptedIntent?.url) {
      setUrlInput(interceptedIntent.url);
      setSourceCaller(interceptedIntent.caller);
      void runFullAnalysis(interceptedIntent.url);
    }
  }, [interceptedIntent]);

  const runFullAnalysis = async (targetUrl: string) => {
    setInterceptorFeedback(null);
    const trimmed = targetUrl.trim();

    const preliminary = analyzeUrlSafety(trimmed);
    if (!preliminary.validSyntax) {
      setValidationError(
        preliminary.errorMessage ?? 'Enter a valid URL including http:// or https://.'
      );
      setActiveResult(null);
      return;
    }

    setValidationError(null);
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

  const handlePasteClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text.trim()) {
        setUrlInput(text.trim());
        setSourceCaller('Clipboard');
        void runFullAnalysis(text.trim());
      } else {
        setValidationError('Clipboard does not contain text to analyze.');
      }
    } catch {
      setValidationError('Clipboard read permission was declined; paste the URL directly into the field.');
    }
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="space-y-1.5 max-w-3xl">
        <p className="text-xs font-medium text-slate-500">
          Android ACTION_VIEW Browser Picker Interceptor · Non-WebView Preflight
        </p>
        <h1
          className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-950"
          style={{ textWrap: 'balance' }}
        >
          Link Safe-Guard &amp; Homograph URL Analyzer
        </h1>
        <p className="text-sm text-slate-600 leading-relaxed">
          Intercepts external links before launching the system browser, unrolls shortened redirect chains via non-rendering HTTP HEAD hops, and detects IDN Punycode homographs, typosquatting, and drive-by APK payloads.
        </p>
      </div>

      {/* URL Input & Live Inspection */}
      <section
        aria-label="URL Verification Input"
        className="bg-white border border-slate-200 rounded-xl divide-y divide-slate-200"
      >
        <form onSubmit={handleSubmit} className="p-5 sm:p-6 space-y-3">
          <label
            htmlFor="url-analyzer-input"
            className="block text-xs font-semibold text-slate-700"
          >
            External Link or Intent URI (http:// or https://)
          </label>
          <div className="flex flex-col sm:flex-row gap-2.5">
            <input
              id="url-analyzer-input"
              type="text"
              value={urlInput}
              onChange={(e) => {
                setUrlInput(e.target.value);
                if (validationError) setValidationError(null);
              }}
              placeholder="https://example.com or shortened link"
              className="flex-1 h-11 px-3.5 text-sm font-mono bg-slate-50 border border-slate-300 rounded-lg text-slate-950 placeholder:text-slate-400 focus:outline-none focus:bg-white focus:border-blue-600"
            />
            <div className="flex items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={() => void handlePasteClipboard()}
                className="inline-flex items-center justify-center gap-1.5 px-3.5 h-11 text-xs font-medium text-slate-700 bg-slate-100 rounded-lg hover:bg-slate-200 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
              >
                <ClipboardPaste className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
                <span>Paste</span>
              </button>

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
          </div>

          {validationError && (
            <p role="alert" className="text-xs font-medium text-red-700">
              {validationError}
            </p>
          )}
        </form>

        {/* Empty State vs Detailed Analysis Grid */}
        {!activeResult ? (
          <div className="p-10 text-center space-y-2.5">
            <Link2 className="w-6 h-6 text-slate-400 mx-auto" aria-hidden="true" />
            <p className="text-sm font-medium text-slate-900">Ready to inspect external links</p>
            <p className="text-xs text-slate-500 max-w-lg mx-auto">
              Paste any URL above or select AegisLocal from Android&apos;s browser chooser when tapping links in SMS, email, or messaging apps to verify redirects and domain authenticity before loading a browser.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-12 divide-y lg:divide-y-0 lg:divide-x divide-slate-200">
            {/* Left 7 cols: Redirect Chain, Homograph Character Breakdown & Heuristics */}
            <div className="lg:col-span-7 divide-y divide-slate-200">
              <div className="p-5 sm:p-6 space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-4">
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
                    Threat Signature Classification: {activeResult.safeBrowsingCategory}
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
                    Evaluated without intermediate HTTP 30x redirects.
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
                          <div className="text-slate-500 font-mono">
                            Content-Type: {hop.contentType}
                          </div>
                        )}
                      </li>
                    ))}
                  </ol>
                )}
              </div>

              {/* Heuristic Findings List */}
              <div className="p-5 sm:p-6 space-y-2.5">
                <h2 className="text-sm font-bold text-slate-950">Heuristic &amp; Threat Signals</h2>
                <ul className="space-y-1.5 text-xs text-slate-700 leading-relaxed list-disc pl-4">
                  {activeResult.findings.map((f, idx) => (
                    <li key={idx}>{f}</li>
                  ))}
                </ul>
              </div>
            </div>

            {/* Right 5 cols: Browser Launch Gate & Encrypted History */}
            <div className="lg:col-span-5 p-5 sm:p-6 bg-slate-50/60 flex flex-col justify-between space-y-6">
              <div className="space-y-4">
                <div>
                  <h2 className="text-sm font-bold text-slate-950">
                    Browser Launch Gate
                  </h2>
                  <p className="mt-0.5 text-xs text-slate-600">
                    Source: <span className="font-medium text-slate-900">{sourceCaller}</span> · Holds navigation until destination passes local verification.
                  </p>
                </div>

                <div className="bg-slate-900 text-white rounded-2xl p-5 space-y-4">
                  <div className="space-y-1">
                    <p className="text-[11px] text-slate-400">
                      Source: {sourceCaller} · AegisLocal Browser Guard
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
                    <div className="text-slate-400">Resolved Final Destination:</div>
                    <div className="font-mono text-slate-100 break-all">{activeResult.finalUrl}</div>
                    {activeResult.dangerousPayloadExtension && (
                      <div className="text-red-300 font-medium pt-1">
                        Binary Payload Alert: {activeResult.dangerousPayloadExtension} package download blocked
                      </div>
                    )}
                  </div>

                  <div className="grid grid-cols-2 gap-2.5 pt-2">
                    <button
                      type="button"
                      onClick={() => {
                        setUrlInput('');
                        setActiveResult(null);
                        setInterceptorFeedback(null);
                      }}
                      className="min-h-[42px] px-3 py-2 text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-white rounded-xl transition-colors cursor-pointer"
                    >
                      Block &amp; Clear
                    </button>

                    <button
                      type="button"
                      onClick={() => {
                        if (isRunningOnAndroidNative()) {
                          void AegisSecurityNative.openVerifiedExternalBrowser({
                            url: activeResult.finalUrl,
                          }).catch(() => null);
                          setInterceptorFeedback('Dispatched verified URL to external Android browser.');
                        } else {
                          setInterceptorFeedback(
                            activeResult.verdictAction === 'ALLOW_BROWSER_LAUNCH'
                              ? 'Destination verified safe for browser navigation.'
                              : 'Warning: Link flagged as high risk — external auto-open suppressed.'
                          );
                        }
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

              {recentAnalyses.length > 0 && (
                <div className="space-y-2 pt-2 border-t border-slate-200">
                  <div className="flex items-center justify-between gap-2">
                    <h3 className="text-xs font-semibold text-slate-700">
                      Vault-Logged URL Inspections ({recentAnalyses.length})
                    </h3>
                    <button
                      type="button"
                      onClick={onClearHistory}
                      className="inline-flex items-center gap-1 text-xs text-slate-500 hover:text-red-700 cursor-pointer"
                    >
                      <Trash2 className="w-3 h-3" aria-hidden="true" />
                      <span>Clear</span>
                    </button>
                  </div>
                  <ul className="space-y-1.5 text-xs">
                    {recentAnalyses.slice(0, 5).map((item, idx) => (
                      <li
                        key={`${item.inputUrl}-${idx}`}
                        className="flex items-center justify-between gap-2"
                      >
                        <button
                          type="button"
                          onClick={() => {
                            setUrlInput(item.inputUrl);
                            setActiveResult(item);
                            setValidationError(null);
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
