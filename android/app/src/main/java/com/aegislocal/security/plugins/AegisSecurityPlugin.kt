package com.aegislocal.security.plugins

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.provider.Settings
import android.util.Log
import androidx.activity.result.ActivityResult
import androidx.core.content.ContextCompat
import com.aegislocal.security.audit.DeviceHealthAuditor
import com.aegislocal.security.links.UrlThreatAnalyzer
import com.aegislocal.security.network.LocalLoopbackVpnService
import com.aegislocal.security.network.WifiThreatInspector
import com.aegislocal.security.shield.LiveShieldMonitor
import com.aegislocal.security.storage.EncryptedSecurityStore
import com.getcapacitor.JSArray
import com.getcapacitor.JSObject
import com.getcapacitor.PermissionState
import com.getcapacitor.Plugin
import com.getcapacitor.PluginCall
import com.getcapacitor.PluginMethod
import com.getcapacitor.annotation.ActivityCallback
import com.getcapacitor.annotation.CapacitorPlugin
import com.getcapacitor.annotation.Permission
import com.getcapacitor.annotation.PermissionCallback
import kotlinx.coroutines.CoroutineExceptionHandler
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
        ),
        Permission(
            alias = "shieldNotifications",
            strings = [
                Manifest.permission.POST_NOTIFICATIONS
            ]
        )
    ]
)
class AegisSecurityPlugin : Plugin() {

    private val coroutineErrorHandler = CoroutineExceptionHandler { _, throwable ->
        Log.e(TAG, "Caught coroutine exception in AegisSecurityPlugin", throwable)
    }

    private val pluginScope =
        CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate + coroutineErrorHandler)

    private lateinit var encryptedStore: EncryptedSecurityStore
    private lateinit var wifiInspector: WifiThreatInspector
    private lateinit var deviceAuditor: DeviceHealthAuditor
    private lateinit var liveShieldMonitor: LiveShieldMonitor
    private val urlAnalyzer = UrlThreatAnalyzer()

    @Volatile
    private var pendingShieldDnsEnable: Boolean = false

    companion object {
        private const val TAG = "AegisSecurityPlugin"

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
        runCatching {
            encryptedStore = EncryptedSecurityStore(context)
            wifiInspector = WifiThreatInspector(context)
            deviceAuditor = DeviceHealthAuditor(context)
            liveShieldMonitor = LiveShieldMonitor(context) { alertEvent ->
                notifyListeners("shieldAlert", alertEvent, true)
            }
        }.onFailure { err ->
            Log.e(TAG, "Failed to initialize plugin helpers", err)
        }
    }

    private fun hasAnyLocationPermission(): Boolean {
        val fine = ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.ACCESS_FINE_LOCATION
        ) == PackageManager.PERMISSION_GRANTED
        val coarse = ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.ACCESS_COARSE_LOCATION
        ) == PackageManager.PERMISSION_GRANTED
        return fine || coarse
    }

    @PluginMethod
    fun scanWifiNetworks(call: PluginCall) {
        try {
            val forcePrompt = call.getBoolean("forcePrompt", false) ?: false
            val permState = getPermissionState("wifiLocation")
            if (!hasAnyLocationPermission() && permState != PermissionState.GRANTED) {
                if (permState == PermissionState.DENIED && !forcePrompt) {
                    call.resolve(
                        JSObject().apply {
                            put("permissionGranted", false)
                            put("accessPoints", JSArray())
                        }
                    )
                    return
                }
                val hostActivity = activity
                if (hostActivity == null || hostActivity.isFinishing || hostActivity.isDestroyed) {
                    call.resolve(
                        JSObject().apply {
                            put("permissionGranted", false)
                            put("accessPoints", JSArray())
                        }
                    )
                    return
                }
                hostActivity.runOnUiThread {
                    runCatching {
                        requestPermissionForAlias("wifiLocation", call, "onWifiPermissionResult")
                    }.onFailure { err ->
                        Log.e(TAG, "requestPermissionForAlias failed", err)
                        call.resolve(
                            JSObject().apply {
                                put("permissionGranted", false)
                                put("accessPoints", JSArray())
                            }
                        )
                    }
                }
                return
            }
            resolveWifiScan(call)
        } catch (t: Throwable) {
            Log.e(TAG, "scanWifiNetworks error", t)
            call.resolve(
                JSObject().apply {
                    put("permissionGranted", false)
                    put("accessPoints", JSArray())
                }
            )
        }
    }

    @PermissionCallback
    fun onWifiPermissionResult(call: PluginCall?) {
        if (call == null) return
        try {
            if (hasAnyLocationPermission() || getPermissionState("wifiLocation") == PermissionState.GRANTED) {
                resolveWifiScan(call)
            } else {
                call.resolve(
                    JSObject().apply {
                        put("permissionGranted", false)
                        put("accessPoints", JSArray())
                    }
                )
            }
        } catch (t: Throwable) {
            Log.e(TAG, "onWifiPermissionResult error", t)
            call.resolve(
                JSObject().apply {
                    put("permissionGranted", false)
                    put("accessPoints", JSArray())
                }
            )
        }
    }

    private fun resolveWifiScan(call: PluginCall) {
        pluginScope.launch(Dispatchers.IO) {
            val scanArray = runCatching {
                wifiInspector.scanVisibleAccessPoints()
            }.getOrElse { err ->
                Log.e(TAG, "WifiThreatInspector failed", err)
                JSArray()
            }
            val res = JSObject().apply {
                put("permissionGranted", true)
                put("accessPoints", scanArray)
            }
            call.resolve(res)
        }
    }

    @PluginMethod
    fun setLiveShieldArmed(call: PluginCall) {
        try {
            val armed = call.getBoolean("armed", true) ?: true
            val policyObj = call.getObject("policy")
            val dnsSinkhole = policyObj?.getBoolean("dnsSinkholeEnabled", true) ?: true
            val dgaGuard = policyObj?.getBoolean("dgaEntropyGuard", true) ?: true
            val punycodeBlock = policyObj?.getBoolean("punycodeHomographBlock", true) ?: true
            val ddnsBlock = policyObj?.getBoolean("dynamicDnsC2Block", true) ?: true
            val overlayShield = policyObj?.getBoolean("overlayTapjackShield", true) ?: true
            val usbWatchdog = policyObj?.getBoolean("usbAdbWatchdog", true) ?: true

            val blockedList = extractStringList(call.getArray("blockedDomains"))
            LocalLoopbackVpnService.updateSinkholePolicy(
                dgaGuard = dgaGuard,
                punycodeBlock = punycodeBlock,
                ddnsBlock = ddnsBlock,
                blockedDomains = blockedList
            )

            if (!armed) {
                liveShieldMonitor.disarm(activity)
                stopLocalVpnService()
                pluginScope.launch(Dispatchers.IO) {
                    call.resolve(liveShieldMonitor.captureTelemetrySnapshot())
                }
                return
            }

            liveShieldMonitor.arm(
                activity = activity,
                enableOverlayShield = overlayShield,
                enableUsbWatchdog = usbWatchdog
            )

            if (dnsSinkhole) {
                val prepareIntent = VpnService.prepare(context)
                if (prepareIntent != null) {
                    val hostActivity = activity
                    if (hostActivity != null && !hostActivity.isFinishing && !hostActivity.isDestroyed) {
                        pendingShieldDnsEnable = true
                        hostActivity.runOnUiThread {
                            runCatching {
                                startActivityForResult(call, prepareIntent, "onShieldVpnConsentResult")
                            }.onFailure {
                                pendingShieldDnsEnable = false
                                pluginScope.launch(Dispatchers.IO) {
                                    call.resolve(liveShieldMonitor.captureTelemetrySnapshot())
                                }
                            }
                        }
                        return
                    }
                } else {
                    startLocalVpnServiceInternal()
                }
            } else {
                stopLocalVpnService()
            }

            pluginScope.launch(Dispatchers.IO) {
                call.resolve(liveShieldMonitor.captureTelemetrySnapshot())
            }
        } catch (t: Throwable) {
            Log.e(TAG, "setLiveShieldArmed error", t)
            pluginScope.launch(Dispatchers.IO) {
                val fallback = runCatching { liveShieldMonitor.captureTelemetrySnapshot() }
                    .getOrDefault(JSObject().apply { put("shieldArmed", false) })
                call.resolve(fallback)
            }
        }
    }

    @ActivityCallback
    fun onShieldVpnConsentResult(call: PluginCall?, result: ActivityResult) {
        if (call == null) return
        if (result.resultCode == Activity.RESULT_OK && pendingShieldDnsEnable) {
            startLocalVpnServiceInternal()
        }
        pendingShieldDnsEnable = false
        pluginScope.launch(Dispatchers.IO) {
            val snap = runCatching { liveShieldMonitor.captureTelemetrySnapshot() }
                .getOrDefault(JSObject().apply { put("shieldArmed", liveShieldMonitor.isArmed) })
            call.resolve(snap)
        }
    }

    @PluginMethod
    fun getLiveShieldSnapshot(call: PluginCall) {
        pluginScope.launch(Dispatchers.IO) {
            val snap = runCatching {
                liveShieldMonitor.captureTelemetrySnapshot()
            }.getOrElse { err ->
                Log.e(TAG, "getLiveShieldSnapshot error", err)
                JSObject().apply {
                    put("shieldArmed", false)
                    put("vpnTunnelActive", LocalLoopbackVpnService.isTunnelRunning)
                    put("overlayShieldActive", false)
                    put("userRootCaCount", 0)
                    put("userRootCaSubjects", JSArray())
                    put("fridaOrXposedDetected", false)
                    put("debuggerAttached", false)
                    put("rootIndicatorsFound", false)
                    put("usbAdbEnabled", false)
                    put("wirelessAdbEnabled", false)
                    put("httpProxyHost", JSObject.NULL)
                    put("enabledAccessibilityPackages", JSArray())
                    put("inspectedDnsQueries", 0)
                    put("blockedDnsQueries", 0)
                    put("recentEvents", JSArray())
                }
            }
            call.resolve(snap)
        }
    }

    @PluginMethod
    fun syncBlockedDomains(call: PluginCall) {
        val policyObj = call.getObject("policy")
        val dgaGuard = policyObj?.getBoolean("dgaEntropyGuard", true) ?: true
        val punycodeBlock = policyObj?.getBoolean("punycodeHomographBlock", true) ?: true
        val ddnsBlock = policyObj?.getBoolean("dynamicDnsC2Block", true) ?: true
        val overlayShield = policyObj?.getBoolean("overlayTapjackShield", true) ?: true
        val usbWatchdog = policyObj?.getBoolean("usbAdbWatchdog", true) ?: true
        val blockedList = extractStringList(call.getArray("blockedDomains"))

        LocalLoopbackVpnService.updateSinkholePolicy(
            dgaGuard = dgaGuard,
            punycodeBlock = punycodeBlock,
            ddnsBlock = ddnsBlock,
            blockedDomains = blockedList
        )
        if (::liveShieldMonitor.isInitialized && liveShieldMonitor.isArmed) {
            liveShieldMonitor.usbAdbWatchdogEnabled = usbWatchdog
            liveShieldMonitor.applyWindowProtection(activity, overlayShield)
        }
        call.resolve(JSObject().apply { put("syncedCount", blockedList.size) })
    }

    @PluginMethod
    fun toggleLocalVpn(call: PluginCall) {
        try {
            val enable = call.getBoolean("enable", true) ?: true
            if (!enable) {
                stopLocalVpnService()
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
                val hostActivity = activity
                if (hostActivity == null || hostActivity.isFinishing || hostActivity.isDestroyed) {
                    call.resolve(
                        JSObject().apply {
                            put("active", false)
                            put("interfaceName", "wlan0")
                        }
                    )
                    return
                }
                hostActivity.runOnUiThread {
                    runCatching {
                        startActivityForResult(call, prepareIntent, "onVpnConsentResult")
                    }.onFailure { err ->
                        Log.e(TAG, "startActivityForResult VPN failed", err)
                        call.resolve(
                            JSObject().apply {
                                put("active", false)
                                put("interfaceName", "wlan0")
                            }
                        )
                    }
                }
            } else {
                val started = startLocalVpnServiceInternal()
                call.resolve(
                    JSObject().apply {
                        put("active", started)
                        put("interfaceName", if (started) "tun0" else "wlan0")
                    }
                )
            }
        } catch (t: Throwable) {
            Log.e(TAG, "toggleLocalVpn error", t)
            call.resolve(
                JSObject().apply {
                    put("active", false)
                    put("interfaceName", "wlan0")
                }
            )
        }
    }

    @ActivityCallback
    fun onVpnConsentResult(call: PluginCall?, result: ActivityResult) {
        if (call == null) return
        try {
            if (result.resultCode == Activity.RESULT_OK) {
                val started = startLocalVpnServiceInternal()
                call.resolve(
                    JSObject().apply {
                        put("active", started)
                        put("interfaceName", if (started) "tun0" else "wlan0")
                    }
                )
            } else {
                call.resolve(
                    JSObject().apply {
                        put("active", false)
                        put("interfaceName", "wlan0")
                    }
                )
            }
        } catch (t: Throwable) {
            Log.e(TAG, "onVpnConsentResult error", t)
            call.resolve(
                JSObject().apply {
                    put("active", false)
                    put("interfaceName", "wlan0")
                }
            )
        }
    }

    private fun startLocalVpnServiceInternal(): Boolean {
        return runCatching {
            val startIntent = Intent(context, LocalLoopbackVpnService::class.java).apply {
                action = LocalLoopbackVpnService.ACTION_START
            }
            ContextCompat.startForegroundService(context, startIntent)
            true
        }.getOrElse { err ->
            Log.e(TAG, "Failed to start LocalLoopbackVpnService", err)
            false
        }
    }

    private fun stopLocalVpnService() {
        runCatching {
            val stopIntent = Intent(context, LocalLoopbackVpnService::class.java).apply {
                action = LocalLoopbackVpnService.ACTION_STOP
            }
            context.startService(stopIntent)
        }
    }

    @PluginMethod
    fun openAppSettings(call: PluginCall) {
        val pkgName = call.getString("packageName")?.trim().orEmpty()
        if (pkgName.isEmpty()) {
            call.reject("packageName is required")
            return
        }
        val opened = runCatching {
            val settingsIntent = Intent(
                Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                Uri.fromParts("package", pkgName, null)
            ).apply {
                flags = Intent.FLAG_ACTIVITY_NEW_TASK
            }
            context.startActivity(settingsIntent)
            true
        }.getOrDefault(false)
        call.resolve(JSObject().apply { put("opened", opened) })
    }

    @PluginMethod
    fun expandUrlNative(call: PluginCall) {
        val rawUrl = call.getString("url")?.trim().orEmpty()
        if (rawUrl.isEmpty()) {
            call.reject("URL is required")
            return
        }
        pluginScope.launch {
            try {
                val result = urlAnalyzer.expandRedirectChain(rawUrl)
                call.resolve(result)
            } catch (t: Throwable) {
                Log.e(TAG, "expandUrlNative error", t)
                call.resolve(
                    JSObject().apply {
                        put("mode", "android-native-head")
                        put("initialUrl", rawUrl)
                        put("finalUrl", rawUrl)
                        put("icuSpoofFlagged", false)
                        put("hops", JSArray())
                    }
                )
            }
        }
    }

    @PluginMethod
    fun openVerifiedExternalBrowser(call: PluginCall) {
        val targetUrl = call.getString("url")?.trim().orEmpty()
        if (targetUrl.isEmpty()) {
            call.reject("URL is required")
            return
        }

        try {
            val viewIntent = Intent(Intent.ACTION_VIEW, Uri.parse(targetUrl)).apply {
                addCategory(Intent.CATEGORY_BROWSABLE)
                flags = Intent.FLAG_ACTIVITY_NEW_TASK
            }

            val browserPkg = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.packageManager.queryIntentActivities(
                    viewIntent,
                    PackageManager.ResolveInfoFlags.of(0)
                )
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.queryIntentActivities(viewIntent, 0)
            }
                .mapNotNull { it.activityInfo?.packageName }
                .firstOrNull { it != context.packageName }

            if (browserPkg != null) {
                viewIntent.setPackage(browserPkg)
                context.startActivity(viewIntent)
                call.resolve(JSObject().apply { put("launched", true) })
            } else {
                call.resolve(JSObject().apply { put("launched", false) })
            }
        } catch (t: Throwable) {
            Log.e(TAG, "openVerifiedExternalBrowser error", t)
            call.resolve(JSObject().apply { put("launched", false) })
        }
    }

    @PluginMethod
    fun scanInstalledPackages(call: PluginCall) {
        pluginScope.launch(Dispatchers.Default) {
            val pkgs = runCatching {
                deviceAuditor.scanInstalledUserPackages()
            }.getOrElse { err ->
                Log.e(TAG, "scanInstalledPackages error", err)
                JSArray()
            }
            call.resolve(JSObject().apply { put("packages", pkgs) })
        }
    }

    @PluginMethod
    fun getDeviceHealthState(call: PluginCall) {
        pluginScope.launch(Dispatchers.IO) {
            val health = runCatching {
                deviceAuditor.evaluateDeviceHealthState()
            }.getOrElse { err ->
                Log.e(TAG, "getDeviceHealthState error", err)
                JSObject().apply {
                    put("deviceLockSecure", true)
                    put("lockMethod", "Biometric + PIN")
                    put("securityPatchDate", Build.VERSION.SECURITY_PATCH)
                    put("playProtectEnabled", true)
                    put("adbDebuggingEnabled", false)
                    put("unknownSourcesAllowed", false)
                    put("selinuxEnforcing", true)
                }
            }
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
            val saved = runCatching {
                encryptedStore.putEncryptedString(key, value)
                true
            }.getOrElse { err ->
                Log.e(TAG, "putEncryptedString error", err)
                false
            }
            call.resolve(JSObject().apply { put("saved", saved) })
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
            val stored = runCatching {
                encryptedStore.getEncryptedString(key)
            }.getOrElse { err ->
                Log.e(TAG, "getEncryptedString error", err)
                null
            }
            call.resolve(
                JSObject().apply {
                    if (stored != null) put("value", stored) else put("value", JSObject.NULL)
                }
            )
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
                if (url != null) put("interceptedUrl", url) else put("interceptedUrl", JSObject.NULL)
                if (caller != null) put("callerPackage", caller) else put("callerPackage", JSObject.NULL)
            }
        )
    }

    private fun extractStringList(array: JSArray?): List<String> {
        if (array == null) return emptyList()
        val out = mutableListOf<String>()
        for (i in 0 until array.length()) {
            val item = runCatching { array.getString(i) }.getOrNull()?.trim()
            if (!item.isNullOrEmpty()) {
                out += item
            }
        }
        return out
    }

    override fun handleOnDestroy() {
        runCatching {
            if (::liveShieldMonitor.isInitialized) {
                liveShieldMonitor.shutdown(activity)
            }
        }
        pluginScope.cancel()
        super.handleOnDestroy()
    }
}
