package com.aegislocal.security

import android.content.Intent
import android.os.Bundle
import com.aegislocal.security.plugins.AegisSecurityPlugin
import com.getcapacitor.BridgeActivity

class MainActivity : BridgeActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        registerPlugin(AegisSecurityPlugin::class.java)
        super.onCreate(savedInstanceState)
        captureExternalLinkIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        captureExternalLinkIntent(intent)
    }

    private fun captureExternalLinkIntent(incoming: Intent?) {
        runCatching {
            if (incoming?.action == Intent.ACTION_VIEW) {
                val url = incoming.dataString?.take(8192)
                if (!url.isNullOrBlank() && (url.startsWith("http://") || url.startsWith("https://"))) {
                    val callerHost = runCatching { referrer?.host }.getOrNull() ?: "External App"
                    AegisSecurityPlugin.recordInterceptedIntent(
                        url = url,
                        caller = callerHost
                    )
                }
            }
        }
    }
}
