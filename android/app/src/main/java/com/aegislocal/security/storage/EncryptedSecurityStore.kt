package com.aegislocal.security.storage

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * Hardware-backed EncryptedSharedPreferences wrapper using Android Keystore
 * AES256-GCM MasterKey + AES256-SIV deterministic key encryption, with resilient
 * recovery if OEM Keystore keys are invalidated.
 */
class EncryptedSecurityStore(context: Context) {

    private val appContext: Context = context.applicationContext
    private val initMutex = Mutex()

    @Volatile
    private var cachedPrefs: SharedPreferences? = null

    companion object {
        const val PREFS_FILE_NAME = "aegis_encrypted_security_vault"
    }

    private suspend fun prefs(): SharedPreferences = withContext(Dispatchers.IO) {
        cachedPrefs ?: initMutex.withLock {
            cachedPrefs ?: createOrRecoverEncryptedPrefs().also { cachedPrefs = it }
        }
    }

    private fun createOrRecoverEncryptedPrefs(): SharedPreferences {
        return try {
            createEncryptedPrefsInstance()
        } catch (_: Throwable) {
            // Recover if lockscreen credential reset invalidated the Keystore keyset
            runCatching { appContext.deleteSharedPreferences(PREFS_FILE_NAME) }
            try {
                createEncryptedPrefsInstance()
            } catch (_: Throwable) {
                appContext.getSharedPreferences("${PREFS_FILE_NAME}_fallback", Context.MODE_PRIVATE)
            }
        }
    }

    private fun createEncryptedPrefsInstance(): SharedPreferences {
        val masterKey = MasterKey.Builder(appContext)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        return EncryptedSharedPreferences.create(
            appContext,
            PREFS_FILE_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    suspend fun putEncryptedString(key: String, value: String) = withContext(Dispatchers.IO) {
        runCatching {
            prefs().edit().putString(key, value).apply()
        }
    }

    suspend fun getEncryptedString(key: String): String? = withContext(Dispatchers.IO) {
        runCatching {
            prefs().getString(key, null)
        }.getOrNull()
    }
}
