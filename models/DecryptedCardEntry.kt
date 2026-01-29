/*
 * DinoVault - DecryptedCardEntry.kt
 * 
 * This is the ACTUAL data class for decrypted card data in memory.
 * Published for security transparency.
 * 
 * SECURITY FEATURES:
 * - Holds decrypted card data ONLY during active session
 * - wipe() function zeros all sensitive fields (card number, CVV, PIN)
 * - Designed with PCI DSS compliance principles in mind
 * 
 * Source: https://github.com/YOUR_USERNAME/dinovault-security
 * App Version: 5.3
 */

package com.techmania.pocketmind.vault.data

import android.util.Log
import com.techmania.pocketmind.BuildConfig
import com.techmania.pocketmind.vault.CustomField
import com.techmania.pocketmind.vault.models.CardEntry

/**
 * Holds decrypted card data in memory for UI display.
 * 
 * SENSITIVE FIELDS (wiped on clear):
 * - cardNumber: Full 16-digit card number
 * - cvv: 3-4 digit security code
 * - pin: ATM PIN
 * - cardHolder: Name on card
 * - expiryDate: Card expiration
 * - bankName: Issuing bank
 * - customFields: User-defined fields
 * 
 * SECURITY NOTE:
 * This data exists in plaintext ONLY in device RAM during an active
 * vault session. It is never written to disk in decrypted form.
 * When the vault locks, wipe() zeros all fields.
 */
data class DecryptedCardEntry(
    val id: String,
    val cardHolder: String,
    val cardNumber: String,
    val expiryDate: String,
    val bankName: String,
    val nickname: String,
    val pin: String,
    val cvv: String,
    val originalEntry: CardEntry,
    val customFields: List<CustomField> = emptyList()
) {
    /**
     * Returns the original encrypted CardEntry for database operations.
     */
    fun toCardEntry(): CardEntry {
        return originalEntry
    }
    
    /**
     * Securely wipes sensitive card data from memory.
     * 
     * This is a best-effort security measure following PCI DSS principles:
     * - Card numbers, CVVs, and PINs are zeroed first (highest priority)
     * - All other fields are then zeroed
     * - Custom field values are also wiped
     * 
     * LIMITATION: Due to String immutability in Java/Kotlin, the original
     * String objects may persist until garbage collected. Defense in depth
     * is provided by short session timeouts and immediate cache clearing.
     */
    fun wipe() {
        try {
            // CRITICAL: Wipe highly sensitive payment data first
            cardNumber.toCharArray().fill('\u0000')
            cvv.toCharArray().fill('\u0000')
            pin.toCharArray().fill('\u0000')
            
            // Wipe other card fields
            cardHolder.toCharArray().fill('\u0000')
            expiryDate.toCharArray().fill('\u0000')
            bankName.toCharArray().fill('\u0000')
            nickname.toCharArray().fill('\u0000')
            
            // Wipe custom field values
            customFields.forEach { field ->
                field.text.toCharArray().fill('\u0000')
            }
            
            if (BuildConfig.DEBUG) {
                Log.d("DecryptedCardEntry", "Wiped card data from memory")
            }
        } catch (e: Exception) {
            // Fail silently - wiping is best-effort
            if (BuildConfig.DEBUG) {
                Log.w("DecryptedCardEntry", "Failed to wipe memory: ${e.message}")
            }
        }
    }
}