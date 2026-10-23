import {
  DeviceHealthState,
  DevicePostureReport,
  InstalledAppPackage,
  PackageAuditFinding,
  PostureCheckItem,
  ThreatSeverity,
} from './types';

export const HIGH_RISK_PERMISSIONS: Record<string, { label: string; weight: number }> = {
  'android.permission.BIND_ACCESSIBILITY_SERVICE': {
    label: 'Accessibility Service Control (Screen Read & Synthetic Tap)',
    weight: 5,
  },
  'android.permission.SYSTEM_ALERT_WINDOW': {
    label: 'Draw Over Other Apps (Tapjacking / Credential Overlay)',
    weight: 4,
  },
  'android.permission.RECEIVE_SMS': {
    label: 'Intercept Incoming SMS (2FA OTP Capture)',
    weight: 4,
  },
  'android.permission.READ_SMS': {
    label: 'Read Stored SMS Messages',
    weight: 4,
  },
  'android.permission.REQUEST_INSTALL_PACKAGES': {
    label: 'Install Unknown APK Packages (Dropper Capability)',
    weight: 4,
  },
  'android.permission.ACCESS_BACKGROUND_LOCATION': {
    label: 'Continuous Background GPS Tracking',
    weight: 3,
  },
  'android.permission.RECORD_AUDIO': {
    label: 'Microphone Audio Capture',
    weight: 2,
  },
  'android.permission.READ_CALL_LOG': {
    label: 'Read Call History Metadata',
    weight: 3,
  },
  'android.permission.QUERY_ALL_PACKAGES': {
    label: 'Enumerate All Installed Apps (Reconnaissance)',
    weight: 2,
  },
};

export function auditInstalledPackages(packages: InstalledAppPackage[]): PackageAuditFinding[] {
  return packages.map((pkg) => {
    const permSet = new Set(pkg.permissions);
    if (pkg.enabledAccessibilityService) {
      permSet.add('android.permission.BIND_ACCESSIBILITY_SERVICE');
    }
    if (pkg.canDrawOverlays) {
      permSet.add('android.permission.SYSTEM_ALERT_WINDOW');
    }

    const flaggedPermissions = Array.from(permSet).filter((p) => Boolean(HIGH_RISK_PERMISSIONS[p]));
    const threatPatterns: string[] = [];
    let severity: ThreatSeverity = ThreatSeverity.NOMINAL;

    const raise = (current: ThreatSeverity, next: ThreatSeverity): ThreatSeverity => {
      if (current === ThreatSeverity.CRITICAL || next === ThreatSeverity.CRITICAL) {
        return ThreatSeverity.CRITICAL;
      }
      if (current === ThreatSeverity.WARNING || next === ThreatSeverity.WARNING) {
        return ThreatSeverity.WARNING;
      }
      return ThreatSeverity.NOMINAL;
    };

    const hasAccessibility =
      pkg.enabledAccessibilityService || permSet.has('android.permission.BIND_ACCESSIBILITY_SERVICE');
    const hasOverlay = pkg.canDrawOverlays || permSet.has('android.permission.SYSTEM_ALERT_WINDOW');
    const hasSms =
      permSet.has('android.permission.READ_SMS') || permSet.has('android.permission.RECEIVE_SMS');
    const hasPackageInstall = permSet.has('android.permission.REQUEST_INSTALL_PACKAGES');
    const hasBgLocation = permSet.has('android.permission.ACCESS_BACKGROUND_LOCATION');
    const hasMic = permSet.has('android.permission.RECORD_AUDIO');
    const isSideloaded =
      pkg.installerSource === 'adb-sideload' || pkg.installerSource === 'com.chrome.downloader';

    // Pattern 1: Banking Trojan / OTP Spyware Triad
    if (hasAccessibility && (hasOverlay || hasSms)) {
      severity = raise(severity, ThreatSeverity.CRITICAL);
      threatPatterns.push(
        'Banking Trojan / Spyware Triad: Active Accessibility Service combined with Screen Overlay or SMS access enables automated UI scraping and 2FA OTP theft.'
      );
    } else if (hasAccessibility && isSideloaded) {
      severity = raise(severity, ThreatSeverity.CRITICAL);
      threatPatterns.push(
        'Sideloaded package holds Accessibility Service privileges outside Android 13+ Restricted Settings.'
      );
    }

    // Pattern 2: Hidden Launcher Stalkerware
    if (!pkg.hasLauncherIcon && pkg.installerSource !== 'system-preload') {
      severity = raise(severity, ThreatSeverity.CRITICAL);
      threatPatterns.push(
        'Stealth Persistence: Package suppresses its Launcher Activity icon while running background components.'
      );
    }

    if (hasBgLocation && hasMic && pkg.installerSource !== 'system-preload') {
      severity = raise(severity, ThreatSeverity.CRITICAL);
      threatPatterns.push(
        'Surveillance / Stalkerware Profile: Continuous background location paired with microphone capture.'
      );
    }

    // Pattern 3: Hostile APK Dropper
    if (hasPackageInstall && isSideloaded) {
      severity = raise(severity, ThreatSeverity.CRITICAL);
      threatPatterns.push(
        'Sideloaded Dropper: Non-store binary holds REQUEST_INSTALL_PACKAGES to stage secondary payloads.'
      );
    }

    // Pattern 4: Target SDK bypass (< API 31 / Android 12)
    if (pkg.targetSdk < 31 && flaggedPermissions.length > 0) {
      severity = raise(severity, ThreatSeverity.WARNING);
      threatPatterns.push(
        `Legacy targetSdk (${pkg.targetSdk}) bypasses modern Android runtime permission auto-reset and stricter background limits.`
      );
    }

    if (severity === ThreatSeverity.NOMINAL && flaggedPermissions.length >= 2) {
      severity = raise(severity, ThreatSeverity.WARNING);
      threatPatterns.push(
        `Requests ${flaggedPermissions.length} sensitive capabilities; verify permissions align with core app utility.`
      );
    }

    if (threatPatterns.length === 0) {
      threatPatterns.push(
        flaggedPermissions.length === 0
          ? 'Zero high-risk spyware permissions requested; standard sandboxed scope.'
          : 'Single sensitive permission scoped within expected Play Store installer provenance.'
      );
    }

    let remediation = 'No action required.';
    if (severity === ThreatSeverity.CRITICAL) {
      remediation =
        'Revoke Accessibility & Overlay access immediately in Settings -> Accessibility, then uninstall package.';
    } else if (severity === ThreatSeverity.WARNING) {
      remediation =
        'Audit runtime grants in Permission Manager and restrict location/microphone to "While in use".';
    }

    return {
      pkg,
      severity,
      flaggedPermissions,
      threatPatterns,
      remediation,
    };
  });
}

export function evaluateDevicePosture(
  state: DeviceHealthState,
  referenceDateIso = '2026-10-23'
): DevicePostureReport {
  const refMs = Date.parse(`${referenceDateIso}T00:00:00Z`);
  const patchMs = Date.parse(`${state.securityPatchDate}T00:00:00Z`);
  const patchAgeDays = Number.isNaN(patchMs)
    ? 999
    : Math.max(0, Math.round((refMs - patchMs) / (1000 * 60 * 60 * 24)));

  const checks: PostureCheckItem[] = [];

  // 1. Keyguard / Device Lock
  if (state.deviceLockSecure && state.lockMethod === 'Biometric + PIN') {
    checks.push({
      id: 'keyguard',
      label: 'Screen Lock & Keystore Auth',
      status: ThreatSeverity.NOMINAL,
      detail: 'Hardware-backed PIN + Biometric lock active; file-based encryption (FBE) keys bound.',
      androidApiSource: 'KeyguardManager.isDeviceSecure()',
    });
  } else {
    checks.push({
      id: 'keyguard',
      label: 'Screen Lock & Keystore Auth',
      status: ThreatSeverity.CRITICAL,
      detail: `Insecure lock state (${state.lockMethod}); physical access exposes unlocked user credential storage.`,
      androidApiSource: 'KeyguardManager.isDeviceSecure()',
    });
  }

  // 2. Android OS Security Patch Age
  if (patchAgeDays <= 60) {
    checks.push({
      id: 'os-patch',
      label: 'Android OS Security Patch Level',
      status: ThreatSeverity.NOMINAL,
      detail: `Patch ${state.securityPatchDate} (${patchAgeDays} days old) mitigates recent N-day kernel/binder CVEs.`,
      androidApiSource: 'Build.VERSION.SECURITY_PATCH',
    });
  } else if (patchAgeDays <= 95) {
    checks.push({
      id: 'os-patch',
      label: 'Android OS Security Patch Level',
      status: ThreatSeverity.WARNING,
      detail: `Patch ${state.securityPatchDate} is ${patchAgeDays} days old; check OEM OTA bulletin updates.`,
      androidApiSource: 'Build.VERSION.SECURITY_PATCH',
    });
  } else {
    checks.push({
      id: 'os-patch',
      label: 'Android OS Security Patch Level',
      status: ThreatSeverity.CRITICAL,
      detail: `Patch ${state.securityPatchDate} is ${patchAgeDays} days overdue; exposed to public privilege-escalation exploits.`,
      androidApiSource: 'Build.VERSION.SECURITY_PATCH',
    });
  }

  // 3. Google Play Protect
  checks.push({
    id: 'play-protect',
    label: 'Google Play Protect PHA Scanner',
    status: state.playProtectEnabled ? ThreatSeverity.NOMINAL : ThreatSeverity.CRITICAL,
    detail: state.playProtectEnabled
      ? 'On-device potentially harmful app (PHA) verification is active.'
      : 'Play Protect verification is disabled; sideloaded trojans will not be flagged at install time.',
    androidApiSource: 'SafetyNetVerifyAppsApi / PlayIntegrity',
  });

  // 4. USB / Wireless ADB Debugging
  checks.push({
    id: 'adb-status',
    label: 'ADB Debugging Interface',
    status: state.adbDebuggingEnabled ? ThreatSeverity.WARNING : ThreatSeverity.NOMINAL,
    detail: state.adbDebuggingEnabled
      ? 'ADB debugging is enabled; malicious charging kiosks (Juice Jacking) can prompt shell pairing.'
      : 'ADB interface disabled in Settings.Global.ADB_ENABLED.',
    androidApiSource: 'Settings.Global.ADB_ENABLED',
  });

  // 5. Unknown Sources Sideloading
  checks.push({
    id: 'sideload-sources',
    label: 'Unknown Package Install Grants',
    status: state.unknownSourcesAllowed ? ThreatSeverity.WARNING : ThreatSeverity.NOMINAL,
    detail: state.unknownSourcesAllowed
      ? 'One or more browsers/file managers hold OP_REQUEST_INSTALL_PACKAGES permission.'
      : 'Zero untrusted apps permitted to stage APK installations.',
    androidApiSource: 'PackageManager.canRequestPackageInstalls()',
  });

  let overallSeverity = ThreatSeverity.NOMINAL;
  for (const c of checks) {
    if (c.status === ThreatSeverity.CRITICAL) {
      overallSeverity = ThreatSeverity.CRITICAL;
      break;
    }
    if (c.status === ThreatSeverity.WARNING) {
      overallSeverity = ThreatSeverity.WARNING;
    }
  }

  return {
    overallSeverity,
    patchAgeDays,
    checks,
  };
}
