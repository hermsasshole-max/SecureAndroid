export enum EncryptionProtocol {
  OPEN = 'OPEN',
  WEP = 'WEP',
  WPA_TKIP = 'WPA-TKIP',
  WPA2_PSK = 'WPA2-PSK',
  WPA2_ENTERPRISE = 'WPA2-EAP',
  WPA3_SAE = 'WPA3-SAE',
}

export enum ThreatSeverity {
  NOMINAL = 'Nominal',
  WARNING = 'Warning',
  CRITICAL = 'Critical',
}

export interface WifiAccessPoint {
  id: string;
  ssid: string;
  bssid: string;
  protocol: EncryptionProtocol;
  frequencyMhz: number;
  rssiDbm: number;
  channel: number;
  gatewayIp?: string;
  gatewayMac?: string;
  dnsServers?: string[];
  captivePortal?: boolean;
  isConnected?: boolean;
}

export interface BssidBaseline {
  ssid: string;
  trustedBssids: string[];
  expectedProtocol: EncryptionProtocol;
  pinnedGatewayMac?: string;
  pinnedAtIso: string;
}

export interface WifiAuditFinding {
  ap: WifiAccessPoint;
  severity: ThreatSeverity;
  isEvilTwinSuspect: boolean;
  isPinnedTrusted: boolean;
  reasons: string[];
  recommendedAction: string;
}

export interface NetworkInterfaceValidation {
  activeInterface: 'wlan0' | 'tun0';
  vpnLoopbackActive: boolean;
  localTunnelCidr: string;
  gatewayIp: string;
  gatewayMac: string;
  gatewayArpValid: boolean;
  dnsIntegrityValid: boolean;
  findings: string[];
  severity: ThreatSeverity;
}

export interface RedirectHop {
  step: number;
  url: string;
  statusCode: number;
  location?: string;
  contentType?: string;
  latencyMs: number;
}

export interface ConfusableChar {
  index: number;
  char: string;
  codePointHex: string;
  script: 'Cyrillic' | 'Greek' | 'Latin' | 'Digit/Symbol';
  latinLookalike: string;
}

export interface UrlAnalysisResult {
  inputUrl: string;
  finalUrl: string;
  validSyntax: boolean;
  errorMessage?: string;
  scheme: string;
  rawHostname: string;
  unicodeHostname: string;
  registrableDomain: string;
  isShortenedUrl: boolean;
  isPunycodeHomograph: boolean;
  confusableChars: ConfusableChar[];
  impersonatedBrand?: {
    brandDomain: string;
    editDistance: number;
    technique: 'IDN Homograph' | 'Typosquatting' | 'Userinfo Credential Spoof' | 'Subdomain Masquerade';
  };
  dangerousPayloadExtension?: string;
  safeBrowsingCategory?: 'SOCIAL_ENGINEERING' | 'MALWARE' | 'UNWANTED_SOFTWARE';
  severity: ThreatSeverity;
  verdictAction: 'ALLOW_BROWSER_LAUNCH' | 'QUARANTINE_WARNING' | 'BLOCK_INTENT';
  findings: string[];
  hops: RedirectHop[];
  expansionMode?: string;
}

export interface InstalledAppPackage {
  packageName: string;
  appName: string;
  installerSource: 'com.android.vending' | 'adb-sideload' | 'com.chrome.downloader' | 'system-preload';
  versionName: string;
  targetSdk: number;
  hasLauncherIcon: boolean;
  enabledAccessibilityService: boolean;
  canDrawOverlays: boolean;
  permissions: string[];
}

export interface PackageAuditFinding {
  pkg: InstalledAppPackage;
  severity: ThreatSeverity;
  flaggedPermissions: string[];
  threatPatterns: string[];
  remediation: string;
}

export interface DeviceHealthState {
  deviceLockSecure: boolean;
  lockMethod: 'Biometric + PIN' | 'Swipe Only' | 'None';
  securityPatchDate: string; // YYYY-MM-DD
  playProtectEnabled: boolean;
  adbDebuggingEnabled: boolean;
  unknownSourcesAllowed: boolean;
  selinuxEnforcing: boolean;
}

export interface PostureCheckItem {
  id: string;
  label: string;
  status: ThreatSeverity;
  detail: string;
  androidApiSource: string;
}

export interface DevicePostureReport {
  overallSeverity: ThreatSeverity;
  patchAgeDays: number;
  checks: PostureCheckItem[];
}

export interface EncryptedVaultEntry {
  key: string;
  ivBase64: string;
  ciphertextBase64: string;
  updatedAtIso: string;
}

export interface LiveShieldPolicy {
  enabled: boolean;
  dnsSinkholeEnabled: boolean;
  dgaEntropyGuard: boolean;
  punycodeHomographBlock: boolean;
  dynamicDnsC2Block: boolean;
  overlayTapjackShield: boolean;
  usbAdbWatchdog: boolean;
}

export type IntrusionSurface =
  | 'DNS_SINKHOLE'
  | 'PACKAGE_GUARD'
  | 'NETWORK_MITM'
  | 'ACCESSIBILITY_WATCH'
  | 'USB_ADB_GUARD'
  | 'RASP_INTEGRITY';

export interface IntrusionEvent {
  id: string;
  timestampIso: string;
  surface: IntrusionSurface;
  severity: ThreatSeverity;
  title: string;
  detail: string;
  indicator?: string;
}

export interface RawShieldTelemetry {
  platform: 'android-native' | 'web-browser';
  shieldArmed: boolean;
  vpnTunnelActive: boolean;
  overlayShieldActive: boolean;
  secureTransportTls: boolean;
  malwareDnsReachable: boolean | null;
  malwareDnsLatencyMs: number | null;
  userRootCaCount: number | null;
  userRootCaSubjects: string[];
  fridaOrXposedDetected: boolean | null;
  debuggerAttached: boolean | null;
  rootIndicatorsFound: boolean | null;
  usbAdbEnabled: boolean | null;
  wirelessAdbEnabled: boolean | null;
  httpProxyHost: string | null;
  enabledAccessibilityPackages: string[];
  domInjectionCount: number;
  inspectedDnsQueries: number;
  blockedDnsQueries: number;
  lastSweepIso: string | null;
}

export interface ShieldIntegrityCheck {
  id: string;
  label: string;
  status: ThreatSeverity | 'Pending' | 'NativeOnly';
  detail: string;
  method: string;
}

export interface DnsSinkholeVerdict {
  domain: string;
  blocked: boolean;
  severity: ThreatSeverity;
  shannonEntropy: number;
  matchedRule: string;
  reasons: string[];
}
