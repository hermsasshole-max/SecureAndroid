package com.aegislocal.security.network

import android.annotation.SuppressLint
import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.net.wifi.ScanResult
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import com.getcapacitor.JSArray
import com.getcapacitor.JSObject

/**
 * Inspects nearby 802.11 ScanResults and active LinkProperties via standard
 * non-root Android APIs to feed Evil Twin and cipher grading checks.
 * Every system radio call is wrapped in runCatching so approximate-only location
 * grants or disabled GPS toggles never throw SecurityException.
 */
class WifiThreatInspector(context: Context) {

    private val appContext = context.applicationContext
    private val wifiManager =
        appContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager
    private val connectivityManager =
        appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager

    @SuppressLint("MissingPermission")
    fun scanVisibleAccessPoints(): JSArray {
        val out = JSArray()
        val wm = wifiManager ?: return out

        val activeNet = runCatching { connectivityManager?.activeNetwork }.getOrNull()
        val caps = activeNet?.let {
            runCatching { connectivityManager?.getNetworkCapabilities(it) }.getOrNull()
        }
        val linkProps: LinkProperties? = activeNet?.let {
            runCatching { connectivityManager?.getLinkProperties(it) }.getOrNull()
        }

        val activeBssid: String? = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                (caps?.transportInfo as? WifiInfo)?.bssid?.uppercase()
            } else {
                @Suppress("DEPRECATION")
                wm.connectionInfo?.bssid?.uppercase()
            }
        }.getOrNull()

        val captivePortal = runCatching {
            caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL) == true
        }.getOrDefault(false)

        val gatewayIp = runCatching {
            linkProps?.routes
                ?.firstOrNull { it.isDefaultRoute && it.gateway != null }
                ?.gateway?.hostAddress
        }.getOrNull()

        val dnsArray = JSArray()
        runCatching {
            linkProps?.dnsServers?.forEach { addr ->
                addr.hostAddress?.let { dnsArray.put(it) }
            }
        }

        val results: List<ScanResult> = runCatching {
            wm.scanResults.orEmpty()
        }.getOrDefault(emptyList())

        results.forEachIndexed { index, scan ->
            runCatching {
                val ssid = extractSsid(scan).takeIf { it.isNotBlank() } ?: return@forEachIndexed
                val bssid = scan.BSSID?.uppercase()?.takeIf { it.isNotBlank() } ?: return@forEachIndexed
                val isConnected = activeBssid != null && activeBssid == bssid

                val item = JSObject().apply {
                    put("id", "android-ap-$index-${bssid.replace(":", "")}")
                    put("ssid", ssid)
                    put("bssid", bssid)
                    put("protocol", classifySecurityProtocol(scan))
                    put("frequencyMhz", scan.frequency)
                    put("rssiDbm", scan.level)
                    put("channel", frequencyToChannel(scan.frequency))
                    if (isConnected) {
                        put("isConnected", true)
                        if (gatewayIp != null) put("gatewayIp", gatewayIp)
                        put("gatewayMac", bssid)
                        put("dnsServers", dnsArray)
                        put("captivePortal", captivePortal)
                    }
                }
                out.put(item)
            }
        }

        return out
    }

    private fun extractSsid(scan: ScanResult): String {
        return runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                scan.wifiSsid?.toString()?.removeSurrounding("\"") ?: ""
            } else {
                @Suppress("DEPRECATION")
                scan.SSID ?: ""
            }
        }.getOrDefault("")
    }

    private fun classifySecurityProtocol(scan: ScanResult): String {
        val caps = (scan.capabilities ?: "").uppercase()
        return when {
            "SAE" in caps || "WPA3" in caps -> "WPA3-SAE"
            "EAP" in caps -> "WPA2-EAP"
            "WPA2" in caps || "RSN" in caps -> "WPA2-PSK"
            "WPA" in caps && "TKIP" in caps -> "WPA-TKIP"
            "WEP" in caps -> "WEP"
            else -> "OPEN"
        }
    }

    private fun frequencyToChannel(freqMhz: Int): Int {
        return when {
            freqMhz == 2484 -> 14
            freqMhz in 2412..2472 -> (freqMhz - 2407) / 5
            freqMhz in 5170..5825 -> (freqMhz - 5000) / 5
            freqMhz in 5955..7115 -> (freqMhz - 5950) / 5
            else -> 1
        }
    }
}
