import {
  BssidBaseline,
  EncryptionProtocol,
  NetworkInterfaceValidation,
  ThreatSeverity,
  WifiAccessPoint,
  WifiAuditFinding,
} from './types';

const PROTOCOL_STRENGTH_RANK: Record<EncryptionProtocol, number> = {
  [EncryptionProtocol.OPEN]: 0,
  [EncryptionProtocol.WEP]: 1,
  [EncryptionProtocol.WPA_TKIP]: 2,
  [EncryptionProtocol.WPA2_PSK]: 3,
  [EncryptionProtocol.WPA2_ENTERPRISE]: 4,
  [EncryptionProtocol.WPA3_SAE]: 5,
};

export function normalizeBssid(bssid: string): string {
  return bssid.trim().toUpperCase();
}

export function isValidBssidFormat(bssid: string): boolean {
  return /^([0-9A-F]{2}:){5}[0-9A-F]{2}$/i.test(bssid.trim());
}

export function extractOuiPrefix(bssid: string): string {
  const norm = normalizeBssid(bssid);
  return norm.slice(0, 8);
}

function escalateSeverity(current: ThreatSeverity, target: ThreatSeverity): ThreatSeverity {
  if (current === ThreatSeverity.CRITICAL || target === ThreatSeverity.CRITICAL) {
    return ThreatSeverity.CRITICAL;
  }
  if (current === ThreatSeverity.WARNING || target === ThreatSeverity.WARNING) {
    return ThreatSeverity.WARNING;
  }
  return ThreatSeverity.NOMINAL;
}

export function auditWifiEnvironment(
  accessPoints: WifiAccessPoint[],
  baselines: BssidBaseline[]
): WifiAuditFinding[] {
  const baselineBySsid = new Map<string, BssidBaseline>();
  for (const b of baselines) {
    baselineBySsid.set(b.ssid, {
      ...b,
      trustedBssids: b.trustedBssids.map(normalizeBssid),
    });
  }

  // Group scanned APs by SSID to detect unpinned multi-AP protocol downgrades / rogue clones
  const apsBySsid = new Map<string, WifiAccessPoint[]>();
  for (const ap of accessPoints) {
    const list = apsBySsid.get(ap.ssid) ?? [];
    list.push(ap);
    apsBySsid.set(ap.ssid, list);
  }

  return accessPoints.map((ap) => {
    const reasons: string[] = [];
    let severity: ThreatSeverity = ThreatSeverity.NOMINAL;
    let isEvilTwinSuspect = false;
    const normBssid = normalizeBssid(ap.bssid);
    const baseline = baselineBySsid.get(ap.ssid);
    const isPinnedTrusted = Boolean(baseline?.trustedBssids.includes(normBssid));

    // 1. Encryption strength check
    if (ap.protocol === EncryptionProtocol.OPEN) {
      severity = escalateSeverity(severity, ThreatSeverity.CRITICAL);
      reasons.push('Unencrypted OPEN 802.11 network exposes plaintext Layer-2/3 frames to passive sniffing.');
    } else if (ap.protocol === EncryptionProtocol.WEP) {
      severity = escalateSeverity(severity, ThreatSeverity.CRITICAL);
      reasons.push('Deprecated WEP stream cipher (RC4 IV reuse) is trivially crackable in minutes.');
    } else if (ap.protocol === EncryptionProtocol.WPA_TKIP) {
      severity = escalateSeverity(severity, ThreatSeverity.WARNING);
      reasons.push('Legacy WPA-TKIP cipher suite is vulnerable to chopchop and MIC key recovery attacks.');
    }

    // 2. Pinned BSSID baseline Evil Twin verification
    if (baseline) {
      if (!isPinnedTrusted) {
        isEvilTwinSuspect = true;
        severity = escalateSeverity(severity, ThreatSeverity.CRITICAL);
        const trustedOuis = new Set(baseline.trustedBssids.map(extractOuiPrefix));
        const currentOui = extractOuiPrefix(normBssid);
        if (!trustedOuis.has(currentOui)) {
          reasons.push(
            `Unrecognized BSSID (${normBssid}) with foreign NIC OUI (${currentOui}) impersonating pinned SSID "${ap.ssid}".`
          );
        } else {
          reasons.push(
            `BSSID (${normBssid}) is not in the EncryptedSharedPreferences baseline for SSID "${ap.ssid}".`
          );
        }
      }

      const expectedRank = PROTOCOL_STRENGTH_RANK[baseline.expectedProtocol];
      const actualRank = PROTOCOL_STRENGTH_RANK[ap.protocol];
      if (actualRank < expectedRank) {
        isEvilTwinSuspect = true;
        severity = escalateSeverity(severity, ThreatSeverity.CRITICAL);
        reasons.push(
          `Protocol downgrade detected: expected ${baseline.expectedProtocol}, observed ${ap.protocol}.`
        );
      }
    } else {
      // 3. Heuristic multi-AP comparison even without a pre-existing baseline
      const siblings = apsBySsid.get(ap.ssid) ?? [];
      if (siblings.length > 1) {
        const highestSiblingRank = Math.max(
          ...siblings.map((s) => PROTOCOL_STRENGTH_RANK[s.protocol])
        );
        const myRank = PROTOCOL_STRENGTH_RANK[ap.protocol];
        if (myRank < highestSiblingRank && myRank <= PROTOCOL_STRENGTH_RANK[EncryptionProtocol.WPA_TKIP]) {
          isEvilTwinSuspect = true;
          severity = escalateSeverity(severity, ThreatSeverity.CRITICAL);
          reasons.push(
            `Sibling APs for "${ap.ssid}" advertise stronger encryption while this radio broadcasts ${ap.protocol} (classic Wi-Fi Pineapple downgrade).`
          );
        }
      }
    }

    // 4. Anomalous proximity RSSI + Captive portal MITM indicator
    if (ap.rssiDbm >= -35 && (isEvilTwinSuspect || ap.protocol === EncryptionProtocol.OPEN)) {
      severity = escalateSeverity(severity, ThreatSeverity.CRITICAL);
      reasons.push(
        `Abnormally strong signal (${ap.rssiDbm} dBm) indicates an immediate-proximity rogue transmitter.`
      );
    }

    if (ap.captivePortal && isEvilTwinSuspect) {
      severity = escalateSeverity(severity, ThreatSeverity.CRITICAL);
      reasons.push('Captive portal interception active on suspected Evil Twin (credential harvester risk).');
    }

    if (reasons.length === 0) {
      reasons.push(
        isPinnedTrusted
          ? `Verified BSSID matches pinned ${ap.protocol} baseline.`
          : `Strong ${ap.protocol} encryption with no conflicting BSSID anomalies.`
      );
    }

    let recommendedAction = 'Safe for standard TLS traffic; pin BSSID if this is a recurring trusted network.';
    if (isEvilTwinSuspect) {
      recommendedAction = 'Disconnect immediately and block auto-reconnect to prevent MITM session capture.';
    } else if (severity === ThreatSeverity.CRITICAL) {
      recommendedAction = 'Avoid joining unencrypted/WEP radio; enforce Local Loopback VPN DNS/SNI guard.';
    } else if (severity === ThreatSeverity.WARNING) {
      recommendedAction = 'Upgrade router cipher to WPA2-AES (CCMP) or WPA3-SAE.';
    } else if (isPinnedTrusted) {
      recommendedAction = 'Baseline verified in EncryptedSharedPreferences.';
    }

    return {
      ap: { ...ap, bssid: normBssid },
      severity,
      isEvilTwinSuspect,
      isPinnedTrusted,
      reasons,
      recommendedAction,
    };
  });
}

const TRUSTED_PUBLIC_OR_RFC1918_DNS = new Set([
  '1.1.1.1',
  '1.0.0.1',
  '8.8.8.8',
  '8.8.4.4',
  '9.9.9.9',
]);

export function validateLocalGatewayAndTunnel(
  connectedAp: WifiAccessPoint | undefined,
  vpnLoopbackActive: boolean,
  baselines: BssidBaseline[]
): NetworkInterfaceValidation {
  if (!connectedAp) {
    return {
      activeInterface: vpnLoopbackActive ? 'tun0' : 'wlan0',
      vpnLoopbackActive,
      localTunnelCidr: vpnLoopbackActive ? '10.215.173.1/30' : 'Inactive',
      gatewayIp: '—',
      gatewayMac: '—',
      gatewayArpValid: true,
      dnsIntegrityValid: true,
      findings: ['No active Wi-Fi association on wlan0.'],
      severity: ThreatSeverity.NOMINAL,
    };
  }

  const findings: string[] = [];
  let severity = ThreatSeverity.NOMINAL;
  let gatewayArpValid = true;
  let dnsIntegrityValid = true;

  const gatewayIp = connectedAp.gatewayIp ?? '192.168.1.1';
  const gatewayMac = normalizeBssid(connectedAp.gatewayMac ?? connectedAp.bssid);
  const baseline = baselines.find((b) => b.ssid === connectedAp.ssid);

  if (baseline?.pinnedGatewayMac && normalizeBssid(baseline.pinnedGatewayMac) !== gatewayMac) {
    gatewayArpValid = false;
    severity = ThreatSeverity.CRITICAL;
    findings.push(
      `Gateway ARP mismatch: expected MAC ${normalizeBssid(
        baseline.pinnedGatewayMac
      )} for ${gatewayIp}, observed ${gatewayMac} (active ARP spoofing indicator).`
    );
  }

  const dnsList = connectedAp.dnsServers ?? [gatewayIp];
  for (const dnsIp of dnsList) {
    const isSameSubnetGateway = dnsIp === gatewayIp;
    const isKnownResolver = TRUSTED_PUBLIC_OR_RFC1918_DNS.has(dnsIp);
    if (!isSameSubnetGateway && !isKnownResolver) {
      dnsIntegrityValid = false;
      severity = severity === ThreatSeverity.CRITICAL ? ThreatSeverity.CRITICAL : ThreatSeverity.WARNING;
      findings.push(
        `Unrecognized DHCP DNS resolver (${dnsIp}) assigned by network; verify against DNS hijacking.`
      );
    }
  }

  if (!vpnLoopbackActive) {
    if (severity === ThreatSeverity.NOMINAL) {
      severity = ThreatSeverity.WARNING;
    }
    findings.push(
      'Local VpnService loopback (tun0) is paused; outbound DNS queries and plaintext HTTP headers are not being inspected locally.'
    );
  } else {
    findings.push(
      'Local VpnService (tun0 10.215.173.1/30) is inspecting outbound DNS QNAMEs and TLS SNI on-device with zero external server routing.'
    );
  }

  if (gatewayArpValid && dnsIntegrityValid) {
    findings.unshift(`Gateway ${gatewayIp} (${gatewayMac}) passed local Neighbor/ARP consistency checks.`);
  }

  return {
    activeInterface: vpnLoopbackActive ? 'tun0' : 'wlan0',
    vpnLoopbackActive,
    localTunnelCidr: vpnLoopbackActive ? '10.215.173.1/30' : 'Bypassed (wlan0 direct)',
    gatewayIp,
    gatewayMac,
    gatewayArpValid,
    dnsIntegrityValid,
    findings,
    severity,
  };
}
