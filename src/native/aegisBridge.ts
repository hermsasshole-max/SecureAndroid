import { Capacitor, registerPlugin } from '@capacitor/core';
import {
  DeviceHealthState,
  EncryptionProtocol,
  InstalledAppPackage,
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

export interface AegisSecurityPluginContract {
  scanWifiNetworks(options?: { forcePrompt?: boolean }): Promise<NativeWifiScanResponse>;
  toggleLocalVpn(options: { enable: boolean }): Promise<NativeVpnStatusResponse>;
  expandUrlNative(options: { url: string }): Promise<NativeUrlExpansionResponse>;
  openVerifiedExternalBrowser(options: { url: string }): Promise<{ launched: boolean }>;
  scanInstalledPackages(): Promise<{ packages: InstalledAppPackage[] }>;
  getDeviceHealthState(): Promise<DeviceHealthState>;
  putEncryptedString(options: { key: string; value: string }): Promise<{ saved: boolean }>;
  getEncryptedString(options: { key: string }): Promise<{ value: string | null }>;
  consumePendingInterceptUrl(): Promise<NativePendingIntentResponse>;
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
