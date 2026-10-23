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
 */
class WifiThreatInspector(context: Context) {

    private val appContext = context.applicationContext
    private val wifiManager = appContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
    private val connectivityManager =
        appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    @SuppressLint("MissingPermission")
    fun scanVisibleAccessPoints(): JSArray {
        val activeNet = connectivityManager.activeNetwork
        val caps = activeNet?.let { connectivityManager.getNetworkCapabilities(it) }
        val linkProps: LinkProperties? = activeNet?.let { connectivityManager.getLinkProperties(it) }

        val activeBssid: String? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            (caps?.transportInfo as? WifiInfo)?.bssid?.uppercase()
        } else {
            @Suppress("DEPRECATION")
            wifiManager.connectionInfo?.bssid?.uppercase()
        }

        val captivePortal = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL) == true
        val gatewayIp = linkProps?.routes
            ?.firstOrNull { it.isDefaultRoute && it.gateway != null }
            ?.gateway?.hostAddress

        val dnsArray = JSArray()
        linkProps?.dnsServers?.forEach { addr ->
            addr.hostAddress?.let { dnsArray.put(it) }
        }

        val results: List<ScanResult> = runCatching { wifiManager.scanResults.orEmpty() }.getOrDefault(emptyList())
        val out = JSArray()

        results.forEachIndexed { index, scan ->
            val ssid = extractSsid(scan).takeIf { it.isNotBlank() } ?: return@forEachIndexed
            val bssid = scan.BSSID?.uppercase() ?: return@forEachIndexed
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

        return out
    }

    private fun extractSsid(scan: ScanResult): String {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            scan.wifiSsid?.toString()?.removeSurrounding("\"") ?: ""
        } else {
            @Suppress("DEPRECATION")
            scan.SSID ?: ""
        }
    }

    private fun classifySecurityProtocol(scan: ScanResult): String {
        val caps = scan.capabilities.uppercase()
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
