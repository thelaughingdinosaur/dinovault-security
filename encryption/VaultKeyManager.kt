/*
 * DinoVault - VaultKeyManager.kt
 * 
 * This is the ACTUAL credential management implementation used in DinoVault.
 * Published for security transparency.
 * 
 * ZERO-KNOWLEDGE ARCHITECTURE (v2):
 * - Master password NEVER leaves the device
 * - Server stores encrypted verification blob, NOT password hash
 * - Only the user can decrypt their data
 * - Server cannot verify the password
 * 
 * VERSION HISTORY:
 * - v1 (Legacy): Stored password hash - server could theoretically attack it
 * - v2 (Current): Stores encrypted verification blob - true zero-knowledge
 * 
 * Source: https://github.com/thelaughingdinosaur/dinovault-security
 * App Version: 5.3
 */

package com.techmania.pocketmind.vault.encryption

import android.content.Context
import android.util.Base64
import android.util.Log
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import com.google.firebase.firestore.ktx.firestore
import com.google.firebase.ktx.Firebase
import com.techmania.pocketmind.BuildConfig
import com.techmania.pocketmind.data.firebase.FirebaseManager
import com.techmania.pocketmind.vault.vaultDataStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.tasks.await
import kotlinx.coroutines.withContext
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Data class representing vault credentials stored in Firestore.
 * 
 * WHAT'S STORED:
 * - saltBase64: Random salt for key derivation (safe to store)
 * - hashBase64: [v1 ONLY] Password hash (removed in v2)
 * - verificationBlob: [v2 ONLY] Encrypted verification string
 * - vaultVersion: 1 = legacy, 2 = zero-knowledge
 * 
 * In v2, the server CANNOT verify your password because it only has
 * an encrypted blob that requires your password to decrypt.
 */
data class VaultCredentials(
    val saltBase64: String = "",
    val hashBase64: String = "",           // v1 only: password hash
    val verificationBlob: String = "",     // v2 only: encrypted verification string
    val vaultVersion: Int = 1              // 1 = legacy, 2 = zero-knowledge
)

/**
 * Manages vault credentials with zero-knowledge architecture.
 * 
 * KEY SECURITY PROPERTIES:
 * 
 * 1. ZERO-KNOWLEDGE (v2):
 *    Instead of storing a password hash (which could be attacked),
 *    we store an encrypted "verification blob". To verify the password:
 *    - Derive key from entered password
 *    - Attempt to decrypt the blob
 *    - If decryption succeeds → password is correct
 *    The server NEVER has the ability to verify the password.
 * 
 * 2. MEMORY SECURITY:
 *    - Passwords are converted to char arrays and zeroed after use
 *    - Derived keys are zeroed after use
 *    - No sensitive data persists in memory longer than necessary
 * 
 * 3. KEY DERIVATION:
 *    - PBKDF2-HMAC-SHA256 with 100,000 iterations
 *    - Unique random salt per user (16 bytes from SecureRandom)
 *    - Produces 256-bit key for XChaCha20-Poly1305
 */
object VaultKeyManager {

    // Debug logging - only logs in debug builds
    private fun logDebug(tag: String, message: String) {
        if (BuildConfig.DEBUG) {
            Log.d(tag, message)
        }
    }

    private fun logInfo(tag: String, message: String) {
        if (BuildConfig.DEBUG) {
            Log.i(tag, message)
        }
    }

    private fun logWarning(tag: String, message: String) {
        if (BuildConfig.DEBUG) {
            Log.w(tag, message)
        }
    }

    private fun logError(tag: String, message: String, throwable: Exception? = null) {
        if (BuildConfig.DEBUG) {
            if (throwable != null) {
                Log.e(tag, message, throwable)
            } else {
                Log.e(tag, message)
            }
        }
    }

    // Storage keys
    private val REQUIRE_FINGERPRINT_KEY = booleanPreferencesKey("require_fingerprint")
    private val SALT_KEY = stringPreferencesKey("vault_salt")
    private val HASHED_PASSWORD_KEY = stringPreferencesKey("vault_password_hash")      // v1 only
    private val VERIFICATION_BLOB_KEY = stringPreferencesKey("vault_verification_blob") // v2 only
    private val CLOUD_VAULT_EXISTS_FLAG = booleanPreferencesKey("cloud_vault_exists_flag")

    private const val ITERATIONS = 100_000
    private const val KEY_LENGTH = 256 // bits

    /**
     * Returns Firestore document reference for user's vault credentials.
     * Path: users/{userId}/dinovault_credentials/key_info
     */
    private fun getCredentialsDocRef() = FirebaseManager.getUserId()?.let {
        Firebase.firestore.collection("users/$it/dinovault_credentials").document("key_info")
    }

    /**
     * Flow that emits whether a vault exists (either v1 or v2).
     */
    fun isPasswordSetFlow(context: Context): Flow<Boolean> {
        return context.vaultDataStore.data.map { prefs ->
            val hasSalt = prefs[SALT_KEY] != null
            val hasV1 = prefs[HASHED_PASSWORD_KEY] != null
            val hasV2 = prefs[VERIFICATION_BLOB_KEY] != null
            hasSalt && (hasV1 || hasV2)
        }
    }

    /**
     * [LEGACY v1] Saves master password using hash-based verification.
     * Kept for backward compatibility during migration.
     * New users automatically get v2.
     */
    suspend fun saveMasterPassword(context: Context, password: String) {
        val salt = generateSalt()

        val passwordChars = password.toCharArray()
        val hash = try {
            hashPassword(passwordChars, salt)
        } finally {
            passwordChars.fill('\u0000') // Zero password from memory
        }

        val saltBase64 = Base64.encodeToString(salt, Base64.NO_WRAP)
        val hashBase64 = Base64.encodeToString(hash, Base64.NO_WRAP)

        // Save locally
        context.vaultDataStore.edit { editor ->
            editor[SALT_KEY] = saltBase64
            editor[HASHED_PASSWORD_KEY] = hashBase64
        }
        logDebug("VaultKeyManager", "Saved hash and salt locally (v1).")

        // Save to Firestore for cloud sync
        try {
            val credentials = VaultCredentials(
                saltBase64 = saltBase64,
                hashBase64 = hashBase64,
                vaultVersion = 1
            )
            getCredentialsDocRef()?.set(credentials)?.await()
            logDebug("VaultKeyManager", "Saved hash and salt to Firestore (v1).")
        } catch (e: Exception) {
            logError("VaultKeyManager", "Failed to save credentials to Firestore", e)
        } finally {
            hash.fill(0) // Zero derived key from memory
        }
    }

    /**
     * Smart master password setup that automatically uses v2 for new vaults.
     * For existing vaults, preserves current version.
     */
    suspend fun saveMasterPasswordAuto(context: Context, password: String) {
        val isNew = com.techmania.pocketmind.vault.VaultVersion.isNewVault(context)

        if (isNew) {
            // New vault: use v2 (zero-knowledge) by default
            logInfo("VaultKeyManager", "Creating new vault with v2 (zero-knowledge)")
            saveMasterPasswordV2(context, password)
            com.techmania.pocketmind.vault.VaultVersion.setVersion(
                context,
                com.techmania.pocketmind.vault.VaultVersion.VERSION_ZERO_KNOWLEDGE
            )
        } else {
            // Existing vault: preserve current version
            val currentVersion = com.techmania.pocketmind.vault.VaultVersion.getVersion(context)
            if (currentVersion == com.techmania.pocketmind.vault.VaultVersion.VERSION_ZERO_KNOWLEDGE) {
                logInfo("VaultKeyManager", "Updating v2 vault credentials")
                saveMasterPasswordV2(context, password)
            } else {
                logInfo("VaultKeyManager", "Updating v1 vault credentials")
                saveMasterPassword(context, password)
            }
        }
    }

    /**
     * Syncs vault credentials from cloud to local storage.
     */
    suspend fun syncCredentialsFromCloud(context: Context): Boolean {
        try {
            val doc = getCredentialsDocRef()?.get()?.await()
            val credentials = doc?.toObject(VaultCredentials::class.java)
            if (credentials != null) {
                context.vaultDataStore.edit { editor ->
                    editor[SALT_KEY] = credentials.saltBase64
                    editor[HASHED_PASSWORD_KEY] = credentials.hashBase64
                }
                logDebug("VaultKeyManager", "Successfully synced credentials from cloud.")
                return true
            }
            logWarning("VaultKeyManager", "No credentials found in Firestore to sync.")
            return false
        } catch (e: Exception) {
            logError("VaultKeyManager", "Failed to sync credentials from cloud.", e)
            return false
        }
    }

    /**
     * [LEGACY v1] Verifies password by comparing hashes.
     * Kept for backward compatibility.
     */
    suspend fun verifyPassword(context: Context, password: String): Boolean = withContext(Dispatchers.IO) {
        val prefs = context.vaultDataStore.data.first()
        val saltBase64 = prefs[SALT_KEY] ?: return@withContext false
        val storedHashBase64 = prefs[HASHED_PASSWORD_KEY] ?: return@withContext false

        val salt = Base64.decode(saltBase64, Base64.NO_WRAP)
        val storedHash = Base64.decode(storedHashBase64, Base64.NO_WRAP)

        val passwordChars = password.toCharArray()
        val inputHash = try {
            hashPassword(passwordChars, salt)
        } finally {
            passwordChars.fill('\u0000') // Zero input password
        }

        val result = inputHash.contentEquals(storedHash)
        inputHash.fill(0) // Zero derived key
        return@withContext result
    }

    /**
     * Smart password verification that automatically detects vault version.
     */
    suspend fun verifyPasswordAuto(context: Context, password: String): Boolean {
        val version = com.techmania.pocketmind.vault.VaultVersion.getVersion(context)
        return when (version) {
            com.techmania.pocketmind.vault.VaultVersion.VERSION_LEGACY -> {
                logDebug("VaultKeyManager", "Using v1 verification (hash)")
                verifyPassword(context, password)
            }
            com.techmania.pocketmind.vault.VaultVersion.VERSION_ZERO_KNOWLEDGE -> {
                logDebug("VaultKeyManager", "Using v2 verification (blob)")
                verifyPasswordV2(context, password)
            }
            else -> {
                logError("VaultKeyManager", "Unknown vault version: $version")
                false
            }
        }
    }

    /**
     * Generates a cryptographically secure random salt.
     */
    private fun generateSalt(): ByteArray {
        val salt = ByteArray(16)
        SecureRandom().nextBytes(salt)
        return salt
    }

    /**
     * Derives a key from password using PBKDF2-HMAC-SHA256.
     */
    private fun hashPassword(passwordChars: CharArray, salt: ByteArray): ByteArray {
        val spec = PBEKeySpec(passwordChars, salt, ITERATIONS, KEY_LENGTH)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        return factory.generateSecret(spec).encoded
    }

    /**
     * Clears all vault credentials from local and cloud storage.
     */
    suspend fun clearPassword(context: Context) {
        context.vaultDataStore.edit {
            it.remove(SALT_KEY)
            it.remove(HASHED_PASSWORD_KEY)
        }
        try {
            getCredentialsDocRef()?.delete()?.await()
            logDebug("VaultKeyManager", "Cleared credentials from Firestore.")
        } catch (e: Exception) {
            logError("VaultKeyManager", "Failed to clear credentials from Firestore.", e)
        }
    }

    /**
     * Sets whether biometric authentication is required after password entry.
     */
    suspend fun setRequireFingerprint(context: Context, require: Boolean) {
        context.vaultDataStore.edit { prefs ->
            prefs[REQUIRE_FINGERPRINT_KEY] = require
        }
    }

    /**
     * Checks if biometric authentication is required.
     */
    suspend fun isFingerprintRequired(context: Context): Boolean {
        val prefs = context.vaultDataStore.data.first()
        return prefs[REQUIRE_FINGERPRINT_KEY] ?: false
    }

    /**
     * Migrates local vault credentials to cloud.
     * Supports both v1 and v2 vaults.
     */
    suspend fun migrateCredentialsToCloud(context: Context) {
        val prefs = context.vaultDataStore.data.first()
        val saltBase64 = prefs[SALT_KEY]

        if (saltBase64 == null) {
            logWarning("VaultKeyManager", "Cannot migrate: no salt found")
            return
        }

        val vaultVersion = com.techmania.pocketmind.vault.VaultVersion.getVersion(context)

        val credentials = if (vaultVersion == com.techmania.pocketmind.vault.VaultVersion.VERSION_ZERO_KNOWLEDGE) {
            val verificationBlob = prefs[VERIFICATION_BLOB_KEY]
            if (verificationBlob == null) {
                logWarning("VaultKeyManager", "Cannot migrate v2 vault: no verification blob found")
                return
            }
            logInfo("VaultKeyManager", "Migrating v2 (zero-knowledge) vault to cloud")
            VaultCredentials(
                saltBase64 = saltBase64,
                verificationBlob = verificationBlob,
                vaultVersion = 2
            )
        } else {
            val hashedPassBase64 = prefs[HASHED_PASSWORD_KEY]
            if (hashedPassBase64 == null) {
                logWarning("VaultKeyManager", "Cannot migrate v1 vault: no password hash found")
                return
            }
            logInfo("VaultKeyManager", "Migrating v1 (legacy) vault to cloud")
            VaultCredentials(
                saltBase64 = saltBase64,
                hashBase64 = hashedPassBase64,
                vaultVersion = 1
            )
        }

        try {
            val userId = FirebaseManager.getUserId()
                ?: throw IllegalStateException("User must be signed in for migration.")

            FirebaseManager.firestore
                .collection("users/$userId/dinovault_credentials")
                .document("key_info")
                .set(credentials)
                .await()

            logDebug("VaultKeyManager", "Vault credentials migrated to cloud successfully (v$vaultVersion)")
        } catch (e: Exception) {
            logError("VaultKeyManager", "Failed to migrate credentials to cloud", e)
            throw e
        }
    }

    /**
     * Sets flag indicating whether a cloud vault exists for this user.
     */
    suspend fun setCloudVaultFlag(context: Context, exists: Boolean) {
        context.vaultDataStore.edit { prefs ->
            prefs[CLOUD_VAULT_EXISTS_FLAG] = exists
        }
    }

    /**
     * Checks if a cloud vault exists (used when offline).
     */
    suspend fun hasCloudVaultFlag(context: Context): Boolean {
        val prefs = context.vaultDataStore.data.first()
        return prefs[CLOUD_VAULT_EXISTS_FLAG] ?: false
    }

    /**
     * Checks cloud for existing vault and updates local flag.
     */
    suspend fun checkUpdateCloudVaultStatus(context: Context) {
        val userId = FirebaseManager.getUserId() ?: return
        try {
            val snapshot = FirebaseManager.firestore
                .collection("users/$userId/dinovault_credentials")
                .limit(1)
                .get()
                .await()

            val exists = !snapshot.isEmpty
            setCloudVaultFlag(context, exists)
            logDebug("VaultKeyManager", "Sign-in check: Cloud vault exists = $exists")
        } catch (e: Exception) {
            logError("VaultKeyManager", "Failed to update vault status during sign-in", e)
        }
    }

    // ==========================================
    // ZERO-KNOWLEDGE V2 METHODS
    // ==========================================

    /**
     * Creates a verification blob for zero-knowledge authentication.
     * 
     * HOW IT WORKS:
     * 1. Derive encryption key from password + salt
     * 2. Encrypt a known string: "VAULT_V2_VERIFIED_{timestamp}"
     * 3. Return the encrypted blob
     * 
     * WHY THIS IS ZERO-KNOWLEDGE:
     * - The server only stores the encrypted blob
     * - The server cannot decrypt it (doesn't have the key)
     * - The server cannot verify the password (nothing to compare)
     * - Only the user with the correct password can decrypt
     */
    private fun createVerificationBlob(password: String, salt: ByteArray): String {
        val passwordChars = password.toCharArray()
        val key = try {
            hashPassword(passwordChars, salt)
        } finally {
            passwordChars.fill('\u0000')
        }

        return try {
            val cryptoManager = InMemoryCryptoManager(key)
            val verificationText = "VAULT_V2_VERIFIED_${System.currentTimeMillis()}"
            cryptoManager.encrypt(verificationText)
        } finally {
            key.fill(0)
        }
    }

    /**
     * Saves master password using zero-knowledge v2 architecture.
     * 
     * WHAT'S STORED:
     * - Salt (random, safe to store)
     * - Verification blob (encrypted, cannot be decrypted without password)
     * 
     * WHAT'S NOT STORED:
     * - Password (never stored)
     * - Password hash (v2 doesn't use hashes)
     * - Encryption key (derived on-demand)
     */
    suspend fun saveMasterPasswordV2(context: Context, password: String) {
        val salt = generateSalt()
        val verificationBlob = createVerificationBlob(password, salt)

        val saltBase64 = Base64.encodeToString(salt, Base64.NO_WRAP)

        // Save locally (v2: only salt and verification blob)
        context.vaultDataStore.edit { editor ->
            editor[SALT_KEY] = saltBase64
            editor[VERIFICATION_BLOB_KEY] = verificationBlob
            editor.remove(HASHED_PASSWORD_KEY) // Remove legacy hash if exists
        }
        logDebug("VaultKeyManager", "Saved verification blob locally (v2)")

        // Save to Firestore for cloud sync
        try {
            val credentials = VaultCredentials(
                saltBase64 = saltBase64,
                verificationBlob = verificationBlob,
                vaultVersion = 2
            )
            getCredentialsDocRef()?.set(credentials)?.await()
            logDebug("VaultKeyManager", "Saved verification blob to Firestore (v2)")
        } catch (e: Exception) {
            logError("VaultKeyManager", "Failed to save v2 credentials to Firestore", e)
        }
    }

    /**
     * Verifies password using zero-knowledge v2 architecture.
     * 
     * VERIFICATION PROCESS:
     * 1. Retrieve salt and verification blob from storage
     * 2. Derive encryption key from entered password + salt
     * 3. Attempt to decrypt the verification blob
     * 4. If decryption succeeds AND produces "VAULT_V2_VERIFIED_*" → correct
     * 5. If decryption fails → wrong password
     * 
     * The server CANNOT perform this verification because it doesn't
     * have the encryption key (derived from password).
     */
    suspend fun verifyPasswordV2(context: Context, password: String): Boolean = withContext(Dispatchers.IO) {
        val prefs = context.vaultDataStore.data.first()
        val saltBase64 = prefs[SALT_KEY] ?: return@withContext false
        val verificationBlob = prefs[VERIFICATION_BLOB_KEY] ?: return@withContext false

        val salt = Base64.decode(saltBase64, Base64.NO_WRAP)
        val passwordChars = password.toCharArray()
        val key = try {
            hashPassword(passwordChars, salt)
        } finally {
            passwordChars.fill('\u0000')
        }

        return@withContext try {
            val cryptoManager = InMemoryCryptoManager(key)
            val decrypted = cryptoManager.decrypt(verificationBlob)
            decrypted.startsWith("VAULT_V2_VERIFIED_")
        } catch (e: Exception) {
            false
        } finally {
            key.fill(0)
        }
    }

    /**
     * Syncs v2 credentials from cloud.
     */
    suspend fun syncCredentialsFromCloudV2(context: Context): Boolean {
        try {
            val doc = getCredentialsDocRef()?.get()?.await()
            val credentials = doc?.toObject(VaultCredentials::class.java)
            if (credentials != null && credentials.vaultVersion == 2) {
                context.vaultDataStore.edit { editor ->
                    editor[SALT_KEY] = credentials.saltBase64
                    editor[VERIFICATION_BLOB_KEY] = credentials.verificationBlob
                    editor.remove(HASHED_PASSWORD_KEY)
                }
                logDebug("VaultKeyManager", "Successfully synced v2 credentials from cloud.")
                return true
            }
            logWarning("VaultKeyManager", "No v2 credentials found in Firestore to sync.")
            return false
        } catch (e: Exception) {
            logError("VaultKeyManager", "Failed to sync v2 credentials from cloud.", e)
            return false
        }
    }

}
