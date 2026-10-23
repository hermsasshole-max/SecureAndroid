import {
  BssidBaseline,
  DeviceHealthState,
  EncryptionProtocol,
  InstalledAppPackage,
  WifiAccessPoint,
} from '../security/types';

export const INITIAL_BSSID_BASELINES: BssidBaseline[] = [
  {
    ssid: 'CorpNet-5G',
    trustedBssids: ['A4:83:E7:4B:12:90', 'A4:83:E7:4B:12:91'],
    expectedProtocol: EncryptionProtocol.WPA3_SAE,
    pinnedGatewayMac: 'A4:83:E7:4B:12:01',
    pinnedAtIso: '2026-10-12T09:15:00Z',
  },
  {
    ssid: 'StudioFiber-Home',
    trustedBssids: ['3C:84:6A:99:04:1B'],
    expectedProtocol: EncryptionProtocol.WPA2_PSK,
    pinnedGatewayMac: '3C:84:6A:99:04:1A',
    pinnedAtIso: '2026-09-28T18:40:00Z',
  },
];

export const INITIAL_WIFI_SCAN: WifiAccessPoint[] = [
  {
    id: 'ap-corp-legit',
    ssid: 'CorpNet-5G',
    bssid: 'A4:83:E7:4B:12:90',
    protocol: EncryptionProtocol.WPA3_SAE,
    frequencyMhz: 5220,
    rssiDbm: -56,
    channel: 44,
    gatewayIp: '10.24.0.1',
    gatewayMac: 'A4:83:E7:4B:12:01',
    dnsServers: ['1.1.1.1', '1.0.0.1'],
    isConnected: true,
  },
  {
    id: 'ap-corp-eviltwin',
    ssid: 'CorpNet-5G',
    bssid: '00:13:37:A9:F2:0C',
    protocol: EncryptionProtocol.OPEN,
    frequencyMhz: 2437,
    rssiDbm: -32,
    channel: 6,
    gatewayIp: '192.168.4.1',
    gatewayMac: '00:13:37:A9:F2:0C',
    dnsServers: ['192.168.4.1'],
    captivePortal: true,
  },
  {
    id: 'ap-airport-open',
    ssid: 'Terminal_Free_WiFi',
    bssid: '58:EF:68:21:88:30',
    protocol: EncryptionProtocol.OPEN,
    frequencyMhz: 2412,
    rssiDbm: -64,
    channel: 1,
    captivePortal: true,
  },
  {
    id: 'ap-legacy-cafe',
    ssid: 'Roastery_Guest_Legacy',
    bssid: '18:D6:C7:50:19:44',
    protocol: EncryptionProtocol.WEP,
    frequencyMhz: 2462,
    rssiDbm: -71,
    channel: 11,
  },
  {
    id: 'ap-home-pinned',
    ssid: 'StudioFiber-Home',
    bssid: '3C:84:6A:99:04:1B',
    protocol: EncryptionProtocol.WPA2_PSK,
    frequencyMhz: 5180,
    rssiDbm: -61,
    channel: 36,
    gatewayIp: '192.168.1.1',
    gatewayMac: '3C:84:6A:99:04:1A',
    dnsServers: ['192.168.1.1', '9.9.9.9'],
  },
];

export interface UrlSampleVector {
  label: string;
  description: string;
  url: string;
  sourceApp: string;
}

export const URL_TEST_VECTORS: UrlSampleVector[] = [
  {
    label: 'Shortened Homograph Phish',
    description: 'bit.ly 2-hop redirect resolving to Cyrillic Punycode paypal.com clone',
    url: 'https://bit.ly/3xCorpAuth',
    sourceApp: 'SMS Messenger',
  },
  {
    label: 'Shortened APK Dropper',
    description: 'tinyurl redirect delivering raw IPv4 Android package binary (.apk)',
    url: 'https://tinyurl.com/android-sec-update',
    sourceApp: 'Telegram External Link',
  },
  {
    label: 'Userinfo @ Authority Trick',
    description: 'Uses accounts.google.com@ userinfo prefix before untrusted host',
    url: 'https://accounts.google.com@auth-verify-node.top/signin/confirm-token',
    sourceApp: 'Email Client',
  },
  {
    label: 'IDN Direct Punycode',
    description: 'Direct xn--pypal-4ve.com link using U+0430 Cyrillic Small Letter A',
    url: 'https://xn--pypal-4ve.com/signin/session-verify',
    sourceApp: 'QR Code Scanner',
  },
  {
    label: 'Verified Android Docs',
    description: 'Clean HTTPS documentation link with standard ASCII hostname',
    url: 'https://developer.android.com/reference/android/net/VpnService',
    sourceApp: 'Slack Workspace',
  },
];

export const INITIAL_INSTALLED_PACKAGES: InstalledAppPackage[] = [
  {
    packageName: 'com.fin.invoiceviewer.helper',
    appName: 'QuickInvoice PDF Helper',
    installerSource: 'com.chrome.downloader',
    versionName: '2.1.0-mod',
    targetSdk: 29,
    hasLauncherIcon: false,
    enabledAccessibilityService: true,
    canDrawOverlays: true,
    permissions: [
      'android.permission.BIND_ACCESSIBILITY_SERVICE',
      'android.permission.SYSTEM_ALERT_WINDOW',
      'android.permission.RECEIVE_SMS',
      'android.permission.READ_SMS',
      'android.permission.INTERNET',
    ],
  },
  {
    packageName: 'com.bright.superflashlight.pro',
    appName: 'Ultra Torch LED',
    installerSource: 'adb-sideload',
    versionName: '4.0.2',
    targetSdk: 30,
    hasLauncherIcon: true,
    enabledAccessibilityService: false,
    canDrawOverlays: false,
    permissions: [
      'android.permission.ACCESS_BACKGROUND_LOCATION',
      'android.permission.RECORD_AUDIO',
      'android.permission.REQUEST_INSTALL_PACKAGES',
      'android.permission.CAMERA',
    ],
  },
  {
    packageName: 'com.screen.dimmer.nightfilter',
    appName: 'Night Filter Dimmer',
    installerSource: 'com.android.vending',
    versionName: '1.8.4',
    targetSdk: 33,
    hasLauncherIcon: true,
    enabledAccessibilityService: false,
    canDrawOverlays: true,
    permissions: [
      'android.permission.SYSTEM_ALERT_WINDOW',
      'android.permission.QUERY_ALL_PACKAGES',
    ],
  },
  {
    packageName: 'org.thoughtcrime.securesms',
    appName: 'Signal Private Messenger',
    installerSource: 'com.android.vending',
    versionName: '7.22.1',
    targetSdk: 34,
    hasLauncherIcon: true,
    enabledAccessibilityService: false,
    canDrawOverlays: false,
    permissions: [
      'android.permission.CAMERA',
      'android.permission.RECORD_AUDIO',
      'android.permission.INTERNET',
    ],
  },
  {
    packageName: 'com.android.chrome',
    appName: 'Google Chrome',
    installerSource: 'system-preload',
    versionName: '130.0.6723.58',
    targetSdk: 34,
    hasLauncherIcon: true,
    enabledAccessibilityService: false,
    canDrawOverlays: false,
    permissions: ['android.permission.INTERNET', 'android.permission.CAMERA'],
  },
];

export const INITIAL_DEVICE_HEALTH: DeviceHealthState = {
  deviceLockSecure: true,
  lockMethod: 'Biometric + PIN',
  securityPatchDate: '2026-10-05',
  playProtectEnabled: true,
  adbDebuggingEnabled: false,
  unknownSourcesAllowed: true,
  selinuxEnforcing: true,
};
