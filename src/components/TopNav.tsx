import { ShieldCheck, Wifi, Link2, Smartphone, FileCode2, Download } from 'lucide-react';

export type WorkspaceTab = 'shield' | 'wifi' | 'links' | 'device' | 'blueprint';

interface TopNavProps {
  activeTab: WorkspaceTab;
  onSelectTab: (tab: WorkspaceTab) => void;
  onExportBundle: () => void;
}

const NAV_ITEMS: Array<{
  id: WorkspaceTab;
  label: string;
  shortLabel: string;
  Icon: typeof ShieldCheck;
}> = [
  { id: 'shield', label: 'Live Shield', shortLabel: 'Shield', Icon: ShieldCheck },
  { id: 'wifi', label: 'Wi-Fi Inspector', shortLabel: 'Wi-Fi', Icon: Wifi },
  { id: 'links', label: 'Link Analyzer', shortLabel: 'Links', Icon: Link2 },
  { id: 'device', label: 'Device Audit', shortLabel: 'Device', Icon: Smartphone },
  { id: 'blueprint', label: 'Kotlin Spec', shortLabel: 'Kotlin', Icon: FileCode2 },
];

export function TopNav({ activeTab, onSelectTab, onExportBundle }: TopNavProps) {
  return (
    <>
      {/* Strict 3-Zone Top Bar Contract (h-12 on mobile, h-16 on desktop) */}
      <header className="sticky top-0 z-30 h-12 md:h-16 bg-white/95 backdrop-blur-sm border-b border-slate-200 px-4 sm:px-6 lg:px-8 flex items-center justify-between gap-8">
        {/* Zone 1: Single text element wordmark */}
        <a
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            onSelectTab('shield');
          }}
          className="text-base md:text-lg font-bold tracking-tight text-slate-900 whitespace-nowrap shrink-0 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600"
          style={{ fontFamily: 'var(--font-display)' }}
        >
          AegisLocal
        </a>

        {/* Zone 2: 5 concise single-line text navigation links */}
        <nav aria-label="Primary Workspace" className="hidden md:flex items-center gap-6 lg:gap-7 text-sm font-medium">
          {NAV_ITEMS.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => onSelectTab(item.id)}
                aria-current={isActive ? 'page' : undefined}
                className={`py-5 border-b-2 transition-colors whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 ${
                  isActive
                    ? 'border-blue-600 text-slate-950 font-semibold'
                    : 'border-transparent text-slate-600 hover:text-slate-900 hover:border-slate-300'
                }`}
              >
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* Zone 3: 1 primary action */}
        <div className="flex items-center shrink-0">
          <button
            type="button"
            onClick={onExportBundle}
            className="inline-flex items-center gap-2 px-3.5 py-2 min-h-[36px] md:min-h-[40px] text-xs font-semibold text-white bg-slate-900 rounded-lg hover:bg-slate-800 transition-colors whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600"
          >
            <Download className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
            <span>Export Spec</span>
          </button>
        </div>
      </header>

      {/* Mobile Bottom Tab Bar (h-14 = 56px; combined sticky height 48+56 = 104px = 12.3% of 844px <= 15% cap) */}
      <nav
        aria-label="Mobile Workspace"
        className="md:hidden fixed bottom-0 left-0 right-0 z-30 h-14 bg-white/95 backdrop-blur-md border-t border-slate-200 grid grid-cols-5 items-center px-1"
      >
        {NAV_ITEMS.map(({ id, shortLabel, Icon }) => {
          const isActive = activeTab === id;
          return (
            <button
              key={id}
              type="button"
              onClick={() => onSelectTab(id)}
              aria-current={isActive ? 'page' : undefined}
              className={`min-h-[44px] flex flex-col items-center justify-center transition-colors whitespace-nowrap shrink-0 ${
                isActive ? 'text-blue-600 font-semibold' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <Icon className="w-5 h-5 shrink-0" aria-hidden="true" />
              <span className="text-[10px] leading-tight mt-0.5">{shortLabel}</span>
            </button>
          );
        })}
      </nav>
    </>
  );
}
