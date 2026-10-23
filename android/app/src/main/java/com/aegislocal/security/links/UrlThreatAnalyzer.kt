package com.aegislocal.security.links

import android.icu.text.SpoofChecker
import com.getcapacitor.JSArray
import com.getcapacitor.JSObject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.HttpURLConnection
import java.net.IDN
import java.net.URI

/**
 * Non-rendering HTTP HEAD redirect chain resolver + Android ICU SpoofChecker
 * homograph verifier. Never loads untrusted URLs inside a WebView.
 */
class UrlThreatAnalyzer {

    private val spoofChecker: SpoofChecker = SpoofChecker.Builder()
        .setRestrictionLevel(SpoofChecker.RestrictionLevel.MODERATELY_RESTRICTIVE)
        .setChecks(SpoofChecker.RESTRICTION_LEVEL or SpoofChecker.MIXED_NUMBERS)
        .build()

    suspend fun expandRedirectChain(rawUrl: String, maxHops: Int = 6): JSObject =
        withContext(Dispatchers.IO) {
            val hopsArray = JSArray()
            var currentUrl = rawUrl

            for (step in 1..(maxHops + 1)) {
                val startMs = System.currentTimeMillis()
                val connection = runCatching {
                    (URI.create(currentUrl).toURL().openConnection() as HttpURLConnection).apply {
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
                        val nextResolved = URI.create(currentUrl).resolve(location).toString()
                        if (!nextResolved.startsWith("http://") && !nextResolved.startsWith("https://")) {
                            break
                        }
                        currentUrl = nextResolved
                    } else {
                        break
                    }
                } catch (_: Exception) {
                    break
                } finally {
                    connection.disconnect()
                }
            }

            val host = runCatching { URI.create(currentUrl).host.orEmpty() }.getOrDefault("")
            val unicodeHost = runCatching { IDN.toUnicode(host, IDN.ALLOW_UNASSIGNED) }.getOrDefault(host)
            val icuFlagged = host.isNotEmpty() && spoofChecker.failsChecks(unicodeHost)

            JSObject().apply {
                put("mode", "android-native-head")
                put("initialUrl", rawUrl)
                put("finalUrl", currentUrl)
                put("icuSpoofFlagged", icuFlagged)
                put("hops", hopsArray)
            }
        }
}
