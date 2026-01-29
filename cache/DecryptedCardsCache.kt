/*
 * DinoVault - DecryptedCardsCache.kt
 * 
 * This is the ACTUAL in-memory cache for decrypted card data.
 * Published for security transparency.
 * 
 * SECURITY: Card numbers, CVVs, and PINs are wiped from memory
 * when the cache is cleared (on vault lock or session timeout).
 * 
 * Source: https://github.com/YOUR_USERNAME/dinovault-security
 * App Version: 5.3
 */

package com.techmania.pocketmind.vault.cache

import android.util.Log
import com.techmania.pocketmind.BuildConfig
import com.techmania.pocketmind.vault.data.DecryptedCardEntry

/**
 * In-memory cache for decrypted card data.
 * 
 * SECURITY LIFECYCLE:
 * - POPULATED: When user unlocks vault and loads card list
 * - ACTIVE: During vault session (user browsing cards)
 * - CLEARED: On vault lock, session timeout, or app termination
 * 
 * CRITICAL: This cache holds sensitive payment card data including
 * card numbers, CVVs, and PINs. The clear() function calls wipe()
 * on each entry to zero this data from memory.
 */
object DecryptedCardCache {
    private var cachedCards: List<DecryptedCardEntry>? = null

    /**
     * Returns cached decrypted cards, or null if cache is empty.
     */
    fun get(): List<DecryptedCardEntry>? = cachedCards

    /**
     * Sets new cache data after clearing any existing cache.
     */
    fun set(cards: List<DecryptedCardEntry>) {
        // Clear old cache before setting new one
        clear()
        cachedCards = cards
    }

    /**
     * Securely clears the cache by wiping sensitive card data before nullifying.
     * 
     * CRITICAL: This wipes card numbers, CVVs, and PINs from memory.
     * 
     * Called when:
     * - User manually locks the vault
     * - Session timeout expires
     * - User signs out
     * - App is terminated
     */
    fun clear() {
        cachedCards?.forEach { it.wipe() }
        cachedCards = null
        
        if (BuildConfig.DEBUG) {
            Log.d("DecryptedCardCache", "Card cache cleared securely")
        }
    }
}
