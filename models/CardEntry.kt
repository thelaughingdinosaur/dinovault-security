/*
 * DinoVault - CardEntry.kt
 * 
 * This is the ACTUAL data model used in DinoVault for storing cards.
 * Published for security transparency.
 * 
 * ALL fields containing card data are encrypted with XChaCha20-Poly1305
 * BEFORE being stored locally (Room) or synced to cloud (Firebase).
 * 
 * Source: https://github.com/YOUR_USERNAME/dinovault-security
 * App Version: 5.3
 */

package com.techmania.pocketmind.vault.models

import androidx.annotation.Keep
import androidx.room.Entity
import androidx.room.PrimaryKey
import com.google.firebase.firestore.IgnoreExtraProperties
import java.util.UUID

/**
 * Represents a single credit/debit card entry in the vault.
 *
 * STORAGE:
 * - Local: Room database (SQLite)
 * - Cloud: Firebase Firestore (optional sync)
 *
 * ENCRYPTION:
 * Every single field containing card information is encrypted:
 * - cardHolderEncrypted: Encrypted (name on card)
 * - cardNumberEncrypted: Encrypted (16-digit card number)
 * - expiryDateEncrypted: Encrypted (MM/YY)
 * - bankNameEncrypted: Encrypted (issuing bank)
 * - nicknameEncrypted: Encrypted (user's label for the card)
 * - pinEncrypted: Encrypted (ATM PIN)
 * - cvvEncrypted: Encrypted (3-digit security code)
 * - customFieldsJsonEncrypted: Encrypted (user-defined fields as JSON)
 * - historyJsonEncrypted: Encrypted (PIN change history, cloud-only)
 *
 * The server NEVER sees card numbers, CVVs, PINs, or any card data in plaintext.
 */
@Keep
@IgnoreExtraProperties
@Entity(tableName = "card_entries")
data class CardEntry(
    @PrimaryKey val id: String = UUID.randomUUID().toString(),
    val cardHolderEncrypted: String = "",
    val cardNumberEncrypted: String = "",
    val expiryDateEncrypted: String = "",
    val bankNameEncrypted: String = "",
    val nicknameEncrypted: String = "",
    val pinEncrypted: String = "",
    val cvvEncrypted: String = "",
    val timestamp: Long = System.currentTimeMillis(),
    val customFieldsJsonEncrypted: String = "",
    val historyJsonEncrypted: String? = null
)