package com.aegislocal.security.shield

import android.Manifest
import android.accessibilityservice.AccessibilityServiceInfo
import android.app.Activity
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.database.ContentObserver
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Debug
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.WindowManager
import android.view.accessibility.AccessibilityManager
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.aegislocal.security.network.LocalLoopbackVpnService
import com.getcapacitor.JSArray
import com.getcapacitor.JSObject
import java.io.File
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.time.Instant
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger

/**
 * Real-time non-root Android Intrusion & Anti-Hacking Watchdog (Android 9–16).
 * Monitors runtime attack surfaces using zero-polling OS callbacks:
 *  1. ConnectivityManager.NetworkCallback (HTTP MITM proxy injection & captive portal traps)
 *  2. Package BroadcastReceiver (real-time sideloaded APK dropper & spyware triad detection)
 *  3. ContentObserver on USB & Wireless ADB debugging (Juice-Jacking & LAN ADB exploit defense)
 *  4. AccessibilityStateChangeListener (screen-scraping stalkerware activation)
 *  5. AndroidCAStore user Root CA inspection + /proc/self/maps Frida/LSPosed hook sweep
 *  6. Android 12+ Window.setHideOverlayWindows(true) + FLAG_SECURE anti-tapjacking shield
 */
class LiveShieldMonitor(
    context: Context,
    private val onAlertEmitted: (JSObject) -> Unit
) {

    private val appContext = context.applicationContext
    private val mainHandler = Handler(Looper.getMainLooper())
    private val recentEvents = CopyOnWriteArrayList<JSObject>()
    private val notificationSeq = AtomicInteger(5200)

    @Volatile
    var isArmed: Boolean = false
        private set

    @Volatile
    var overlayShieldActive: Boolean = false
        private set

    @Volatile
    var usbAdbWatchdogEnabled: Boolean = true

    private var receiversRegistered = false
    private var networkCallbackRegistered = false
    private var observersRegistered = false
    private var a11yListenerRegistered = false

    companion object {
        private const val ALERT_CHANNEL_ID = "aegis_intrusion_alerts"
        private const val MAX_RECENT_EVENTS = 40
    }

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
            if (!isArmed) return
            runCatching {
                val proxy = linkProperties.httpProxy
                if (proxy != null && !proxy.host.isNullOrBlank()) {
                    recordIntrusionEvent(
                        surface = "NETWORK_MITM",
                        severity = "Critical",
                        title = "Active HTTP MITM Proxy Detected",
                        detail = "Network interface configured outbound proxy ${proxy.host}:${proxy.port}, enabling traffic interception.",
                        indicator = "${proxy.host}:${proxy.port}"
                    )
                }
            }
        }

        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            if (!isArmed) return
            runCatching {
                if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL)) {
                    recordIntrusionEvent(
                        surface = "NETWORK_MITM",
                        severity = "Warning",
                        title = "Captive Portal Interception Active",
                        detail = "Current Wi-Fi network is redirecting traffic through an unverified captive portal login page.",
                        indicator = "NET_CAPABILITY_CAPTIVE_PORTAL"
                    )
                }
            }
        }
    }

    private val packageAndUsbReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (!isArmed || intent == null) return
            runCatching {
                when (intent.action) {
                    Intent.ACTION_PACKAGE_ADDED, Intent.ACTION_PACKAGE_REPLACED -> {
                        val pkgName = intent.data?.schemeSpecificPart ?: return
                        if (pkgName != appContext.packageName) {
                            inspectNewlyInstalledPackage(pkgName)
                        }
                    }
                    Intent.ACTION_POWER_CONNECTED -> {
                        if (usbAdbWatchdogEnabled && (isUsbAdbEnabled() || isWirelessAdbEnabled())) {
                            recordIntrusionEvent(
                                surface = "USB_ADB_GUARD",
                                severity = "Critical",
                                title = "External Power/USB Connected While ADB Active",
                                detail = "USB or Wireless ADB debugging is enabled during physical cable connection (Juice-Jacking / shell pairing risk).",
                                indicator = "ADB_ACTIVE_ON_USB_ATTACH"
                            )
                        }
                    }
                }
            }
        }
    }

    private val adbObserver = object : ContentObserver(mainHandler) {
        override fun onChange(selfChange: Boolean) {
            if (!isArmed || !usbAdbWatchdogEnabled) return
            runCatching {
                if (isWirelessAdbEnabled()) {
                    recordIntrusionEvent(
                        surface = "USB_ADB_GUARD",
                        severity = "Critical",
                        title = "Wireless ADB Debugging Activated",
                        detail = "adb_wifi_enabled was turned ON — exposes remote Android shell pairing over the local network.",
                        indicator = "adb_wifi_enabled=1"
                    )
                } else if (isUsbAdbEnabled()) {
                    recordIntrusionEvent(
                        surface = "USB_ADB_GUARD",
                        severity = "Warning",
                        title = "USB ADB Debugging Activated",
                        detail = "Settings.Global.ADB_ENABLED was turned ON — disable immediately unless actively developing.",
                        indicator = "adb_enabled=1"
                    )
                }
            }
        }
    }

    private val a11yListener = AccessibilityManager.AccessibilityStateChangeListener { enabled ->
        if (!isArmed || !enabled) return@AccessibilityStateChangeListener
        runCatching {
            val activePkgs = getThirdPartyAccessibilityPackages()
            if (activePkgs.isNotEmpty()) {
                recordIntrusionEvent(
                    surface = "ACCESSIBILITY_WATCH",
                    severity = "Warning",
                    title = "Accessibility Screen-Reader Service Enabled",
                    detail = "Active non-system Accessibility Service(s): ${activePkgs.joinToString(", ")}. Verify against banking overlay spyware.",
                    indicator = activePkgs.first()
                )
            }
        }
    }

    init {
        runCatching {
            val nm = appContext.getSystemService(NotificationManager::class.java)
            val ch = NotificationChannel(
                ALERT_CHANNEL_ID,
                "AegisLocal Real-Time Intrusion Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "High-priority alerts for MITM proxies, rogue Root CAs, stalkerware APKs, and DNS C2 blocks"
            }
            nm?.createNotificationChannel(ch)
        }
    }

    fun arm(
        activity: Activity?,
        enableOverlayShield: Boolean,
        enableUsbWatchdog: Boolean
    ) {
        usbAdbWatchdogEnabled = enableUsbWatchdog
        isArmed = true

        LocalLoopbackVpnService.onThreatSinkholed = { domain, reason ->
            recordIntrusionEvent(
                surface = "DNS_SINKHOLE",
                severity = "Critical",
                title = "Malicious DNS Query Sinkholed",
                detail = reason,
                indicator = domain
            )
        }

        applyWindowProtection(activity, enableOverlayShield)
        registerSensors()
    }

    fun disarm(activity: Activity?) {
        isArmed = false
        LocalLoopbackVpnService.onThreatSinkholed = null
        applyWindowProtection(activity, false)
        unregisterSensors()
    }

    fun applyWindowProtection(activity: Activity?, enable: Boolean) {
        overlayShieldActive = enable
        if (activity == null || activity.isFinishing || activity.isDestroyed) return
        activity.runOnUiThread {
            runCatching {
                if (enable) {
                    activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                } else {
                    activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    activity.window.setHideOverlayWindows(enable)
                }
            }
        }
    }

    private fun registerSensors() {
        if (!networkCallbackRegistered) {
            runCatching {
                val cm = appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                cm?.registerDefaultNetworkCallback(networkCallback)
                networkCallbackRegistered = true
            }
        }

        if (!receiversRegistered) {
            runCatching {
                val pkgFilter = IntentFilter().apply {
                    addAction(Intent.ACTION_PACKAGE_ADDED)
                    addAction(Intent.ACTION_PACKAGE_REPLACED)
                    addDataScheme("package")
                }
                ContextCompat.registerReceiver(
                    appContext,
                    packageAndUsbReceiver,
                    pkgFilter,
                    ContextCompat.RECEIVER_NOT_EXPORTED
                )

                val powerFilter = IntentFilter(Intent.ACTION_POWER_CONNECTED)
                ContextCompat.registerReceiver(
                    appContext,
                    packageAndUsbReceiver,
                    powerFilter,
                    ContextCompat.RECEIVER_NOT_EXPORTED
                )
                receiversRegistered = true
            }
        }

        if (!observersRegistered) {
            runCatching {
                val cr = appContext.contentResolver
                cr.registerContentObserver(
                    Settings.Global.getUriFor(Settings.Global.ADB_ENABLED),
                    false,
                    adbObserver
                )
                cr.registerContentObserver(
                    Settings.Global.getUriFor("adb_wifi_enabled"),
                    false,
                    adbObserver
                )
                observersRegistered = true
            }
        }

        if (!a11yListenerRegistered) {
            runCatching {
                val am = appContext.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
                am?.addAccessibilityStateChangeListener(a11yListener)
                a11yListenerRegistered = true
            }
        }
    }

    private fun unregisterSensors() {
        if (networkCallbackRegistered) {
            runCatching {
                val cm = appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                cm?.unregisterNetworkCallback(networkCallback)
            }
            networkCallbackRegistered = false
        }

        if (receiversRegistered) {
            runCatching { appContext.unregisterReceiver(packageAndUsbReceiver) }
            receiversRegistered = false
        }

        if (observersRegistered) {
            runCatching { appContext.contentResolver.unregisterContentObserver(adbObserver) }
            observersRegistered = false
        }

        if (a11yListenerRegistered) {
            runCatching {
                val am = appContext.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
                am?.removeAccessibilityStateChangeListener(a11yListener)
            }
            a11yListenerRegistered = false
        }
    }

    private fun inspectNewlyInstalledPackage(pkgName: String) {
        val pm = appContext.packageManager
        val pkg: PackageInfo = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(
                    pkgName,
                    PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong())
                )
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(pkgName, PackageManager.GET_PERMISSIONS)
            }
        }.getOrNull() ?: return

        val reqPerms = pkg.requestedPermissions?.toSet().orEmpty()
        val hasA11y = Manifest.permission.BIND_ACCESSIBILITY_SERVICE in reqPerms
        val hasOverlay = Manifest.permission.SYSTEM_ALERT_WINDOW in reqPerms
        val hasSms = Manifest.permission.RECEIVE_SMS in reqPerms || Manifest.permission.READ_SMS in reqPerms
        val hasDropper = Manifest.permission.REQUEST_INSTALL_PACKAGES in reqPerms

        val installer = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(pkgName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(pkgName)
            }
        }.getOrNull()

        val trustedStore = installer == "com.android.vending" || installer == "com.sec.android.app.samsungapps"

        if ((hasA11y && (hasOverlay || hasSms)) || (!trustedStore && (hasA11y || hasDropper))) {
            recordIntrusionEvent(
                surface = "PACKAGE_GUARD",
                severity = "Critical",
                title = "High-Risk APK Installed ($pkgName)",
                detail = "Newly installed package from ${installer ?: "sideload"} requests spyware/dropper capabilities (Accessibility=$hasA11y, Overlay=$hasOverlay, SMS=$hasSms).",
                indicator = pkgName
            )
        }
    }

    fun captureTelemetrySnapshot(): JSObject {
        val userCas = inspectUserRootCaCertificates()
        val memoryHookFound = detectMemoryInstrumentationHooks()
        val debuggerAttached = runCatching { Debug.isDebuggerConnected() }.getOrDefault(false)
        val rootFound = detectRootIndicators()
        val usbAdb = isUsbAdbEnabled()
        val wifiAdb = isWirelessAdbEnabled()
        val proxyHost = detectActiveHttpProxy()
        val a11yPkgs = getThirdPartyAccessibilityPackages()

        val caArray = JSArray()
        userCas.forEach { caArray.put(it) }

        val a11yArray = JSArray()
        a11yPkgs.forEach { a11yArray.put(it) }

        val eventsArray = JSArray()
        recentEvents.forEach { eventsArray.put(it) }

        return JSObject().apply {
            put("shieldArmed", isArmed)
            put("vpnTunnelActive", LocalLoopbackVpnService.isTunnelRunning)
            put("overlayShieldActive", overlayShieldActive)
            put("userRootCaCount", userCas.size)
            put("userRootCaSubjects", caArray)
            put("fridaOrXposedDetected", memoryHookFound)
            put("debuggerAttached", debuggerAttached)
            put("rootIndicatorsFound", rootFound)
            put("usbAdbEnabled", usbAdb)
            put("wirelessAdbEnabled", wifiAdb)
            if (proxyHost != null) put("httpProxyHost", proxyHost) else put("httpProxyHost", JSObject.NULL)
            put("enabledAccessibilityPackages", a11yArray)
            put("inspectedDnsQueries", LocalLoopbackVpnService.inspectedDnsCount.get())
            put("blockedDnsQueries", LocalLoopbackVpnService.blockedDnsCount.get())
            put("recentEvents", eventsArray)
            put("checkedAtIso", Instant.now().toString())
        }
    }

    private fun inspectUserRootCaCertificates(): List<String> {
        return runCatching {
            val ks = KeyStore.getInstance("AndroidCAStore")
            ks.load(null, null)
            val found = mutableListOf<String>()
            val aliases = ks.aliases()
            while (aliases.hasMoreElements()) {
                val alias = aliases.nextElement() ?: continue
                if (alias.startsWith("user:")) {
                    val cert = ks.getCertificate(alias) as? X509Certificate
                    found += (cert?.subjectX500Principal?.name?.takeIf { it.isNotBlank() } ?: alias)
                }
            }
            found
        }.getOrDefault(emptyList())
    }

    private fun detectMemoryInstrumentationHooks(): Boolean {
        return runCatching {
            val mapsFile = File("/proc/self/maps")
            if (!mapsFile.canRead()) return@runCatching false
            val markers = listOf("frida-agent", "frida-gadget", "xposedbridge", "lsposed", "edxposed", "libsubstrate")
            mapsFile.bufferedReader().useLines { lines ->
                lines.any { line ->
                    val lower = line.lowercase()
                    markers.any { marker -> lower.contains(marker) }
                }
            }
        }.getOrDefault(false)
    }

    private fun detectRootIndicators(): Boolean {
        return runCatching {
            if (Build.TAGS?.contains("test-keys") == true) return@runCatching true
            val suPaths = listOf(
                "/system/bin/su",
                "/system/xbin/su",
                "/sbin/su",
                "/product/bin/su",
                "/apex/com.android.runtime/bin/su"
            )
            suPaths.any { File(it).exists() }
        }.getOrDefault(false)
    }

    private fun isUsbAdbEnabled(): Boolean {
        return runCatching {
            Settings.Global.getInt(appContext.contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
        }.getOrDefault(false)
    }

    private fun isWirelessAdbEnabled(): Boolean {
        return runCatching {
            Settings.Global.getInt(appContext.contentResolver, "adb_wifi_enabled", 0) == 1
        }.getOrDefault(false)
    }

    private fun detectActiveHttpProxy(): String? {
        return runCatching {
            val cm = appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            val net = cm?.activeNetwork
            val lp = net?.let { cm.getLinkProperties(it) }
            val proxy = lp?.httpProxy
            if (proxy != null && !proxy.host.isNullOrBlank()) {
                "${proxy.host}:${proxy.port}"
            } else {
                System.getProperty("http.proxyHost")?.takeIf { it.isNotBlank() }
            }
        }.getOrNull()
    }

    private fun getThirdPartyAccessibilityPackages(): List<String> {
        return runCatching {
            val am = appContext.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
            am?.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
                ?.mapNotNull { it.resolveInfo?.serviceInfo?.packageName }
                ?.filter { pkg ->
                    pkg != appContext.packageName &&
                        !pkg.startsWith("com.google.android.marvin") &&
                        !pkg.startsWith("com.android.")
                }
                ?.distinct()
                .orEmpty()
        }.getOrDefault(emptyList())
    }

    private fun recordIntrusionEvent(
        surface: String,
        severity: String,
        title: String,
        detail: String,
        indicator: String?
    ) {
        val nowIso = Instant.now().toString()
        val eventObj = JSObject().apply {
            put("id", "evt-${System.currentTimeMillis()}-${notificationSeq.incrementAndGet()}")
            put("timestampIso", nowIso)
            put("surface", surface)
            put("severity", severity)
            put("title", title)
            put("detail", detail)
            if (indicator != null) put("indicator", indicator)
        }

        recentEvents.add(0, eventObj)
        while (recentEvents.size > MAX_RECENT_EVENTS) {
            runCatching { recentEvents.removeAt(recentEvents.size - 1) }
        }

        runCatching { onAlertEmitted(eventObj) }

        if (severity == "Critical") {
            postLocalAlertNotification(title, detail)
        }
    }

    private fun postLocalAlertNotification(title: String, body: String) {
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                val granted = ContextCompat.checkSelfPermission(
                    appContext,
                    Manifest.permission.POST_NOTIFICATIONS
                ) == PackageManager.PERMISSION_GRANTED
                if (!granted) return
            }
            val nm = appContext.getSystemService(NotificationManager::class.java) ?: return
            val notif = NotificationCompat.Builder(appContext, ALERT_CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentTitle(title)
                .setContentText(body)
                .setStyle(NotificationCompat.BigTextStyle().bigText(body))
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(true)
                .build()
            nm.notify(notificationSeq.incrementAndGet(), notif)
        }
    }

    fun shutdown(activity: Activity?) {
        disarm(activity)
    }
}
