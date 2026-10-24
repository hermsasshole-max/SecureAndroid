import { Capacitor, PluginListenerHandle, registerPlugin } from '@capacitor/core';
import {
  DeviceHealthState,
  EncryptionProtocol,
  InstalledAppPackage,
  IntrusionEvent,
  LiveShieldPolicy,
  RedirectHop,
  WifiAccessPoint,
} from '../security/types';

export interface NativeWifiScanResponse {
  permissionGranted: boolean;
  accessPoints: WifiAccessPoint[];
}

export interface NativeUrlExpansionResponse {
  mode: string;
  initialUrl: string;
  finalUrl: string;
  hops: RedirectHop[];
}

export interface NativeVpnStatusResponse {
  active: boolean;
  interfaceName: string;
}

export interface NativePendingIntentResponse {
  interceptedUrl: string | null;
  callerPackage: string | null;
}

export interface NativeLiveShieldSnapshot {
  shieldArmed: boolean;
  vpnTunnelActive: boolean;
  overlayShieldActive: boolean;
  userRootCaCount: number;
  userRootCaSubjects: string[];
  fridaOrXposedDetected: boolean;
  debuggerAttached: boolean;
  rootIndicatorsFound: boolean;
  usbAdbEnabled: boolean;
  wirelessAdbEnabled: boolean;
  httpProxyHost: string | null;
  enabledAccessibilityPackages: string[];
  inspectedDnsQueries: number;
  blockedDnsQueries: number;
  recentEvents: IntrusionEvent[];
  checkedAtIso: string;
}

export interface AegisSecurityPluginContract {
  scanWifiNetworks(options?: { forcePrompt?: boolean }): Promise<NativeWifiScanResponse>;
  toggleLocalVpn(options: { enable: boolean }): Promise<NativeVpnStatusResponse>;
  expandUrlNative(options: { url: string }): Promise<NativeUrlExpansionResponse>;
  openVerifiedExternalBrowser(options: { url: string }): Promise<{ launched: boolean }>;
  openAppSettings(options: { packageName: string }): Promise<{ opened: boolean }>;
  scanInstalledPackages(): Promise<{ packages: InstalledAppPackage[] }>;
  getDeviceHealthState(): Promise<DeviceHealthState>;
  setLiveShieldArmed(options: {
    armed: boolean;
    policy: LiveShieldPolicy;
    blockedDomains: string[];
  }): Promise<NativeLiveShieldSnapshot>;
  getLiveShieldSnapshot(): Promise<NativeLiveShieldSnapshot>;
  syncBlockedDomains(options: {
    policy: LiveShieldPolicy;
    blockedDomains: string[];
  }): Promise<{ syncedCount: number }>;
  putEncryptedString(options: { key: string; value: string }): Promise<{ saved: boolean }>;
  getEncryptedString(options: { key: string }): Promise<{ value: string | null }>;
  consumePendingInterceptUrl(): Promise<NativePendingIntentResponse>;
  addListener(
    eventName: 'shieldAlert',
    listenerFunc: (event: IntrusionEvent) => void
  ): Promise<PluginListenerHandle>;
}

export const AegisSecurityNative = registerPlugin<AegisSecurityPluginContract>('AegisSecurity');

export function isRunningOnAndroidNative(): boolean {
  return Capacitor.isNativePlatform() && Capacitor.getPlatform() === 'android';
}

export function mapSecurityStringToEnum(label: string): EncryptionProtocol {
  const upper = label.toUpperCase();
  if (upper.includes('WPA3') || upper.includes('SAE')) return EncryptionProtocol.WPA3_SAE;
  if (upper.includes('EAP') || upper.includes('ENTERPRISE')) return EncryptionProtocol.WPA2_ENTERPRISE;
  if (upper.includes('WPA2')) return EncryptionProtocol.WPA2_PSK;
  if (upper.includes('TKIP') || upper.includes('WPA-TKIP')) return EncryptionProtocol.WPA_TKIP;
  if (upper.includes('WEP')) return EncryptionProtocol.WEP;
  return EncryptionProtocol.OPEN;
}
