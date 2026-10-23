package com.aegislocal.security.links

import com.getcapacitor.JSArray
import com.getcapacitor.JSObject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.IDN
import java.net.URL
import java.text.Normalizer

/**
 * Non-rendering HTTP HEAD redirect chain resolver + public SDK IDN & UnicodeScript
 * mixed-script homograph verifier. Never loads untrusted URLs inside a WebView.
 */
class UrlThreatAnalyzer {

    @Suppress("DEPRECATION")
    suspend fun expandRedirectChain(rawUrl: String, maxHops: Int = 6): JSObject =
        withContext(Dispatchers.IO) {
            val hopsArray = JSArray()
            var currentUrl = rawUrl

            for (step in 1..(maxHops + 1)) {
                val startMs = System.currentTimeMillis()
                val connection = runCatching {
                    (URL(currentUrl).openConnection() as HttpURLConnection).apply {
                        requestMethod = "HEAD"
                        instanceFollowRedirects = false
                        connectTimeout = 3500
                        readTimeout = 3500
                        setRequestProperty(
                            "User-Agent",
                            "AegisLocal-AndroidInspector/1.0 (Non-Browser Preflight)"
                        )
                    }
                }.getOrNull() ?: break

                try {
                    val statusCode = connection.responseCode
                    val latencyMs = (System.currentTimeMillis() - startMs).coerceAtLeast(1L)
                    val location = connection.getHeaderField("Location")
                    val contentType = connection.contentType

                    val hopObj = JSObject().apply {
                        put("step", step)
                        put("url", currentUrl)
                        put("statusCode", statusCode)
                        put("latencyMs", latencyMs)
                        if (!location.isNullOrBlank()) put("location", location)
                        if (!contentType.isNullOrBlank()) put("contentType", contentType)
                    }
                    hopsArray.put(hopObj)

                    if (statusCode in 300..399 && !location.isNullOrBlank()) {
                        val nextResolved = runCatching {
                            URL(URL(currentUrl), location).toString()
                        }.getOrNull() ?: break
                        if (!nextResolved.startsWith("http://") && !nextResolved.startsWith("https://")) {
                            break
                        }
                        currentUrl = nextResolved
                    } else {
                        break
                    }
                } catch (_: Throwable) {
                    break
                } finally {
                    runCatching { connection.disconnect() }
                }
            }

            val host = runCatching { URL(currentUrl).host.orEmpty().lowercase() }.getOrDefault("")
            val unicodeHost = runCatching { IDN.toUnicode(host, IDN.ALLOW_UNASSIGNED) }.getOrDefault(host)
            val homographFlagged = runCatching {
                host.isNotEmpty() && hasDeceptiveUnicodeScript(host, unicodeHost)
            }.getOrDefault(false)

            JSObject().apply {
                put("mode", "android-native-head")
                put("initialUrl", rawUrl)
                put("finalUrl", currentUrl)
                put("icuSpoofFlagged", homographFlagged)
                put("hops", hopsArray)
            }
        }

    private fun hasDeceptiveUnicodeScript(asciiHost: String, unicodeHost: String): Boolean {
        if (asciiHost.contains("xn--")) return true
        val normalized = Normalizer.normalize(unicodeHost, Normalizer.Form.NFKC)
        for (label in normalized.split('.')) {
            if (label.isEmpty()) continue
            val scripts = mutableSetOf<Character.UnicodeScript>()
            var i = 0
            while (i < label.length) {
                val cp = label.codePointAt(i)
                val script = Character.UnicodeScript.of(cp)
                if (script != Character.UnicodeScript.COMMON && script != Character.UnicodeScript.INHERITED) {
                    scripts += script
                }
                i += Character.charCount(cp)
            }
            if (scripts.size > 1) return true
            if (Character.UnicodeScript.CYRILLIC in scripts || Character.UnicodeScript.GREEK in scripts) {
                return true
            }
        }
        return false
    }
}
