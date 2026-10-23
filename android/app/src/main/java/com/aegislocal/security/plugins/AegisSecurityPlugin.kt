package com.aegislocal.security.plugins

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import androidx.activity.result.ActivityResult
import androidx.core.content.ContextCompat
import com.aegislocal.security.audit.DeviceHealthAuditor
import com.aegislocal.security.links.UrlThreatAnalyzer
import com.aegislocal.security.network.LocalLoopbackVpnService
import com.aegislocal.security.network.WifiThreatInspector
import com.aegislocal.security.storage.EncryptedSecurityStore
import com.getcapacitor.JSObject
import com.getcapacitor.PermissionState
import com.getcapacitor.Plugin
import com.getcapacitor.PluginCall
import com.getcapacitor.PluginMethod
import com.getcapacitor.annotation.ActivityCallback
import com.getcapacitor.annotation.CapacitorPlugin
import com.getcapacitor.annotation.Permission
import com.getcapacitor.annotation.PermissionCallback
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

@CapacitorPlugin(
    name = "AegisSecurity",
    permissions = [
        Permission(
            alias = "wifiLocation",
            strings = [
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.ACCESS_COARSE_LOCATION
            ]
        )
    ]
)
class AegisSecurityPlugin : Plugin() {

    private val pluginScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private lateinit var encryptedStore: EncryptedSecurityStore
    private lateinit var wifiInspector: WifiThreatInspector
    private lateinit var deviceAuditor: DeviceHealthAuditor
    private val urlAnalyzer = UrlThreatAnalyzer()

    companion object {
        @Volatile
        private var pendingInterceptUrl: String? = null

        @Volatile
        private var pendingCallerPackage: String? = null

        fun recordInterceptedIntent(url: String, caller: String?) {
            pendingInterceptUrl = url
            pendingCallerPackage = caller
        }
    }

    override fun load() {
        super.load()
        encryptedStore = EncryptedSecurityStore(context)
        wifiInspector = WifiThreatInspector(context)
        deviceAuditor = DeviceHealthAuditor(context)
    }

    @PluginMethod
    fun scanWifiNetworks(call: PluginCall) {
        if (getPermissionState("wifiLocation") != PermissionState.GRANTED) {
            requestPermissionForAlias("wifiLocation", call, "onWifiPermissionResult")
            return
        }
        resolveWifiScan(call)
    }

    @PermissionCallback
    fun onWifiPermissionResult(call: PluginCall) {
        if (getPermissionState("wifiLocation") == PermissionState.GRANTED) {
            resolveWifiScan(call)
        } else {
            val res = JSObject().apply {
                put("permissionGranted", false)
                put("accessPoints", com.getcapacitor.JSArray())
            }
            call.resolve(res)
        }
    }

    private fun resolveWifiScan(call: PluginCall) {
        pluginScope.launch(Dispatchers.IO) {
            val scanArray = wifiInspector.scanVisibleAccessPoints()
            val res = JSObject().apply {
                put("permissionGranted", true)
                put("accessPoints", scanArray)
            }
            call.resolve(res)
        }
    }

    @PluginMethod
    fun toggleLocalVpn(call: PluginCall) {
        val enable = call.getBoolean("enable", true) ?: true
        if (!enable) {
            val stopIntent = Intent(context, LocalLoopbackVpnService::class.java).apply {
                action = LocalLoopbackVpnService.ACTION_STOP
            }
            context.startService(stopIntent)
            call.resolve(
                JSObject().apply {
                    put("active", false)
                    put("interfaceName", "wlan0")
                }
            )
            return
        }

        val prepareIntent = VpnService.prepare(context)
        if (prepareIntent != null) {
            startActivityForResult(call, prepareIntent, "onVpnConsentResult")
        } else {
            launchLocalVpnService(call)
        }
    }

    @ActivityCallback
    fun onVpnConsentResult(call: PluginCall?, result: ActivityResult) {
        if (call == null) return
        if (result.resultCode == Activity.RESULT_OK) {
            launchLocalVpnService(call)
        } else {
            call.resolve(
                JSObject().apply {
                    put("active", false)
                    put("interfaceName", "wlan0")
                }
            )
        }
    }

    private fun launchLocalVpnService(call: PluginCall) {
        val startIntent = Intent(context, LocalLoopbackVpnService::class.java).apply {
            action = LocalLoopbackVpnService.ACTION_START
        }
        ContextCompat.startForegroundService(context, startIntent)
        call.resolve(
            JSObject().apply {
                put("active", true)
                put("interfaceName", "tun0")
            }
        )
    }

    @PluginMethod
    fun expandUrlNative(call: PluginCall) {
        val rawUrl = call.getString("url")?.trim().orEmpty()
        if (rawUrl.isEmpty()) {
            call.reject("URL is required")
            return
        }
        pluginScope.launch {
            val result = urlAnalyzer.expandRedirectChain(rawUrl)
            call.resolve(result)
        }
    }

    @PluginMethod
    fun openVerifiedExternalBrowser(call: PluginCall) {
        val targetUrl = call.getString("url")?.trim().orEmpty()
        if (targetUrl.isEmpty()) {
            call.reject("URL is required")
            return
        }

        val viewIntent = Intent(Intent.ACTION_VIEW, Uri.parse(targetUrl)).apply {
            addCategory(Intent.CATEGORY_BROWSABLE)
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
        }

        val browserPkg = context.packageManager.queryIntentActivities(viewIntent, 0)
            .map { it.activityInfo.packageName }
            .firstOrNull { it != context.packageName }

        if (browserPkg != null) {
            viewIntent.setPackage(browserPkg)
            context.startActivity(viewIntent)
            call.resolve(JSObject().apply { put("launched", true) })
        } else {
            call.resolve(JSObject().apply { put("launched", false) })
        }
    }

    @PluginMethod
    fun scanInstalledPackages(call: PluginCall) {
        pluginScope.launch(Dispatchers.Default) {
            val pkgs = deviceAuditor.scanInstalledUserPackages()
            call.resolve(JSObject().apply { put("packages", pkgs) })
        }
    }

    @PluginMethod
    fun getDeviceHealthState(call: PluginCall) {
        pluginScope.launch(Dispatchers.IO) {
            val health = deviceAuditor.evaluateDeviceHealthState()
            call.resolve(health)
        }
    }

    @PluginMethod
    fun putEncryptedString(call: PluginCall) {
        val key = call.getString("key").orEmpty()
        val value = call.getString("value").orEmpty()
        if (key.isEmpty()) {
            call.reject("Key is required")
            return
        }
        pluginScope.launch {
            encryptedStore.putEncryptedString(key, value)
            call.resolve(JSObject().apply { put("saved", true) })
        }
    }

    @PluginMethod
    fun getEncryptedString(call: PluginCall) {
        val key = call.getString("key").orEmpty()
        if (key.isEmpty()) {
            call.reject("Key is required")
            return
        }
        pluginScope.launch {
            val stored = encryptedStore.getEncryptedString(key)
            call.resolve(JSObject().apply { put("value", stored) })
        }
    }

    @PluginMethod
    fun consumePendingInterceptUrl(call: PluginCall) {
        val url = pendingInterceptUrl
        val caller = pendingCallerPackage
        pendingInterceptUrl = null
        pendingCallerPackage = null
        call.resolve(
            JSObject().apply {
                put("interceptedUrl", url)
                put("callerPackage", caller)
            }
        )
    }

    override fun handleOnDestroy() {
        pluginScope.cancel()
        super.handleOnDestroy()
    }
}
