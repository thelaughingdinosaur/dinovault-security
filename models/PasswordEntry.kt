/*
 * DinoVault - PasswordEntry.kt
 * 
 * This is the ACTUAL data model used in DinoVault.
 * Published for security transparency.
 * 
 * All sensitive fields are encrypted with XChaCha20-Poly1305
 * BEFORE being stored locally (Room) or synced to cloud (Firebase).
 * 
 * Source: https://github.com/thelaughingdinosaur/dinovault-security
 * App Version: 5.3
 */

package com.techmania.pocketmind.vault.models

import androidx.annotation.Keep
import androidx.room.Entity
import androidx.room.PrimaryKey
import com.google.firebase.firestore.IgnoreExtraProperties
import java.util.UUID

/**
 * Represents a single password entry in the vault.
 *
 * STORAGE:
 * - Local: Room database (SQLite)
 * - Cloud: Firebase Firestore (optional sync)
 *
 * ENCRYPTION (v2 Zero-Knowledge):
 * - title: Encrypted (website/service name)
 * - email: Encrypted (username/email)
 * - passwordEncrypted: Encrypted (the actual password)
 * - customFieldsJsonEncrypted: Encrypted (user-defined fields as JSON)
 * - historyJsonEncrypted: Encrypted (previous passwords, cloud-only feature)
 *
 * The server NEVER sees any of this data in plaintext.
 */
@Keep
@IgnoreExtraProperties
@Entity(tableName = "password_entries")
data class PasswordEntry(
    @PrimaryKey val id: String = UUID.randomUUID().toString(),
    val title: String = "",
    val email: String = "",
    val passwordEncrypted: String = "",
    val customFieldsJsonEncrypted: String = "",
    val historyJsonEncrypted: String? = null,
    val timestamp: Long = System.currentTimeMillis()
)
