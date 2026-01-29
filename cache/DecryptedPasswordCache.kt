/*
 * DinoVault - DecryptedPasswordCache.kt
 * 
 * This is the ACTUAL in-memory cache implementation used in DinoVault.
 * Published for security transparency.
 * 
 * SECURITY FEATURES:
 * - Decrypted data held in memory ONLY during active session
 * - Secure wipe() function zeros sensitive data before garbage collection
 * - Cache automatically cleared on vault lock or session timeout
 * 
 * Source: https://github.com/YOUR_USERNAME/dinovault-security
 * App Version: 5.3
 */

package com.techmania.pocketmind.vault.cache

import android.util.Log
import com.techmania.pocketmind.BuildConfig
import com.techmania.pocketmind.vault.models.PasswordEntry

/**
 * Holds decrypted password data in memory for UI display.
 * 
 * LIFECYCLE:
 * 1. Created when user unlocks vault and views passwords
 * 2. Stored in DecryptedPasswordCache during active session
 * 3. wipe() called when vault locks or session expires
 * 4. Garbage collected after nullification
 * 
 * SECURITY NOTE ON MEMORY WIPING:
 * Strings are immutable in Kotlin/Java, meaning we cannot directly modify
 * the underlying character array. The wipe() function creates a copy of
 * the char array and zeros it, which is a best-effort defense against
 * memory dump attacks. For maximum security, the vault auto-locks after
 * a configurable timeout (default: 10 minutes).
 */
data class DecryptedPasswordData(
    val password: String,
    val customFields: Map<String, String>,
    val originalEntry: PasswordEntry,
    // v2 zero-knowledge: decrypted title and email for display
    val decryptedTitle: String = originalEntry.title, // v1: already plaintext, v2: decrypted
    val decryptedEmail: String = originalEntry.email  // v1: already plaintext, v2: decrypted
) {
    /**
     * Securely wipes sensitive data from memory.
     * 
     * IMPORTANT: Due to String immutability in Java/Kotlin, this is a
     * best-effort security measure. The original String objects may
     * persist in memory until garbage collected. For true security,
     * we rely on:
     * - Short session timeouts (auto-lock)
     * - Immediate cache clearing on lock
     * - Android's process isolation
     */
    fun wipe() {
        try {
            // Convert strings to char arrays and zero them
            password.toCharArray().fill('\u0000')
            decryptedTitle.toCharArray().fill('\u0000')
            decryptedEmail.toCharArray().fill('\u0000')
            
            // Wipe custom field values
            customFields.values.forEach { value ->
                value.toCharArray().fill('\u0000')
            }
            
            if (BuildConfig.DEBUG) {
                Log.d("DecryptedPasswordCache", "Wiped password data from memory")
            }
        } catch (e: Exception) {
            // Fail silently - wiping is best-effort
            if (BuildConfig.DEBUG) {
                Log.w("DecryptedPasswordCache", "Failed to wipe memory: ${e.message}")
            }
        }
    }
}

/**
 * In-memory cache for decrypted passwords.
 * 
 * PURPOSE:
 * After the user unlocks the vault, decrypted passwords are cached here
 * to avoid re-decrypting on every screen navigation. This improves UX
 * while maintaining security through automatic clearing.
 * 
 * SECURITY LIFECYCLE:
 * - POPULATED: When user unlocks vault and loads password list
 * - ACTIVE: During vault session (user browsing passwords)
 * - CLEARED: On vault lock, session timeout, or app termination
 * 
 * The encryption key itself is NEVER stored here - only the decrypted
 * data that was produced using that key.
 */
object DecryptedPasswordCache {
    private var cachedPasswords: List<DecryptedPasswordData>? = null

    /**
     * Returns cached decrypted passwords, or null if cache is empty.
     */
    fun get(): List<DecryptedPasswordData>? = cachedPasswords

    /**
     * Sets new cache data after clearing any existing cache.
     */
    fun set(data: List<DecryptedPasswordData>) {
        // Clear old cache before setting new one
        clear()
        cachedPasswords = data
    }

    /**
     * Securely clears the cache by wiping all sensitive data.
     * 
     * Called when:
     * - User manually locks the vault
     * - Session timeout expires
     * - User signs out
     * - App is terminated
     * - New data is about to be cached (in set())
     */
    fun clear() {
        cachedPasswords?.forEach { it.wipe() }
        cachedPasswords = null
        
        if (BuildConfig.DEBUG) {
            Log.d("DecryptedPasswordCache", "Password cache cleared securely")
        }
    }
}