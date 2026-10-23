package com.aegislocal.security

import android.content.Intent
import android.os.Bundle
import com.aegislocal.security.plugins.AegisSecurityPlugin
import com.getcapacitor.BridgeActivity

class MainActivity : BridgeActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        registerPlugin(AegisSecurityPlugin::class.java)
        captureExternalLinkIntent(intent)
        super.onCreate(savedInstanceState)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        captureExternalLinkIntent(intent)
    }

    private fun captureExternalLinkIntent(incoming: Intent?) {
        if (incoming?.action == Intent.ACTION_VIEW) {
            val url = incoming.dataString?.take(8192)
            if (!url.isNullOrBlank() && (url.startsWith("http://") || url.startsWith("https://"))) {
                AegisSecurityPlugin.recordInterceptedIntent(
                    url = url,
                    caller = referrer?.host ?: "External App"
                )
            }
        }
    }
}
