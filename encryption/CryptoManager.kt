/*
 * DinoVault - CryptoManager.kt
 * 
 * This is the ACTUAL encryption implementation used in DinoVault.
 * Published for security transparency.
 * 
 * ENCRYPTION:
 * - Algorithm: XChaCha20-Poly1305 (authenticated encryption)
 * - Library: Google Tink
 * - Key Size: 256 bits
 * - Nonce: 192 bits (24 bytes) - automatically managed by Tink
 * 
 * KEY DERIVATION:
 * - Algorithm: PBKDF2-HMAC-SHA256
 * - Iterations: 100,000 (vault) / 310,000 (export files)
 * - Salt: 128 bits (16 bytes) from SecureRandom
 * 
 * Source: https://github.com/thelaughingdinosaur/dinovault-security
 * App Version: 5.3
 */

package com.techmania.pocketmind.vault.encryption

import android.content.Context
import android.util.Base64
import android.util.Log
import com.google.crypto.tink.Aead
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.subtle.XChaCha20Poly1305
import com.techmania.pocketmind.vault.vaultDataStore
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Interface defining encryption/decryption operations.
 * 
 * All vault data passes through this interface before storage.
 * The implementation uses XChaCha20-Poly1305 which provides:
 * - Confidentiality (data is encrypted)
 * - Integrity (tampering is detected via Poly1305 MAC)
 * - 192-bit nonce eliminates nonce collision concerns
 */
interface CryptoManager {
    fun encrypt(plaintext: String, associatedData: ByteArray = ByteArray(0)): String
    fun decrypt(ciphertextBase64: String, associatedData: ByteArray = ByteArray(0)): String

    companion object {
        private const val SALT_KEY = "vault_salt"
        private const val ITERATIONS = 100_000
        private const val KEY_LENGTH = 32 // bytes (256 bits)

        /**
         * Creates a CryptoManager instance from the user's master password.
         * 
         * KEY DERIVATION PROCESS:
         * 1. Retrieve the unique salt stored during vault creation
         * 2. Convert password to char array (for secure wiping)
         * 3. Derive 256-bit key using PBKDF2-HMAC-SHA256 with 100,000 iterations
         * 4. Zero the password char array immediately after use
         * 5. Return CryptoManager initialized with the derived key
         * 
         * The salt is unique per user and generated using SecureRandom
         * during initial vault setup.
         */
        fun fromPassword(password: String, context: Context): CryptoManager {
            val prefs = runBlocking { context.vaultDataStore.data.first() }
            val saltBase64 = prefs[androidx.datastore.preferences.core.stringPreferencesKey(SALT_KEY)]
                ?: throw IllegalStateException("Salt not found in vault")

            val salt = Base64.decode(saltBase64, Base64.NO_WRAP)
            val passwordChars = password.toCharArray()

            val key = try {
                val spec = PBEKeySpec(passwordChars, salt, ITERATIONS, KEY_LENGTH * 8)
                val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                factory.generateSecret(spec).encoded
            } finally {
                // CRITICAL: Zero master password from memory immediately
                passwordChars.fill('\u0000')
            }

            return InMemoryCryptoManager(key)
        }
    }
}

/**
 * In-memory implementation of CryptoManager using XChaCha20-Poly1305.
 * 
 * SECURITY PROPERTIES:
 * - XChaCha20: Stream cipher resistant to timing attacks
 * - Poly1305: Message authentication code for integrity
 * - 256-bit key: Computationally infeasible to brute-force
 * - 192-bit nonce: Eliminates nonce collision concerns (vs 96-bit in AES-GCM)
 * 
 * The key is held in memory only during an active vault session
 * and is zeroed when clear() is called.
 */
class InMemoryCryptoManager(private var key: ByteArray) : CryptoManager {

    private var aead: Aead? = null

    init {
        AeadConfig.register()
        require(key.size == 32) { "Key must be 32 bytes for XChaCha20Poly1305" }
        aead = XChaCha20Poly1305(key)
    }

    /**
     * Encrypts plaintext string and returns Base64-encoded ciphertext.
     * 
     * The ciphertext includes:
     * - 24-byte nonce (generated automatically by Tink)
     * - Encrypted data
     * - 16-byte Poly1305 authentication tag
     */
    override fun encrypt(plaintext: String, associatedData: ByteArray): String {
        val cipher = aead?.encrypt(plaintext.toByteArray(Charsets.UTF_8), associatedData)
            ?: throw IllegalStateException("AEAD is not initialized")
        return Base64.encodeToString(cipher, Base64.NO_WRAP)
    }

    /**
     * Decrypts Base64-encoded ciphertext and returns plaintext string.
     * 
     * Throws exception if:
     * - Ciphertext has been tampered with (MAC verification fails)
     * - Wrong key is used (decryption fails)
     */
    override fun decrypt(ciphertextBase64: String, associatedData: ByteArray): String {
        val cipher = Base64.decode(ciphertextBase64, Base64.NO_WRAP)
        val decrypted = aead?.decrypt(cipher, associatedData)
            ?: throw IllegalStateException("AEAD is not initialized")
        return String(decrypted, Charsets.UTF_8)
    }

    /**
     * Securely wipes the encryption key from memory.
     * Called when vault is locked or session expires.
     */
    fun clear() {
        key.fill(0)
        key = ByteArray(0)
        aead = null
    }

    companion object {
        private const val NONCE_SIZE = 24
        private const val SALT_SIZE = 16
        // Export files use 310,000 iterations per OWASP 2023 recommendations
        private const val ITERATIONS = 310_000
        private const val KEY_LENGTH_BYTES = 32

        /**
         * Encrypts data for export/backup files with enhanced security.
         * 
         * Uses 310,000 PBKDF2 iterations (vs 100,000 for main vault)
         * because export files may be stored on less secure media.
         * 
         * OUTPUT FORMAT: salt|nonce|ciphertext (Base64 encoded, pipe-separated)
         * 
         * Each export generates:
         * - New random 16-byte salt
         * - New random 24-byte nonce
         * - Fresh key derivation
         */
        fun encryptForExport(plainText: String, password: String): String {
            val salt = ByteArray(SALT_SIZE).apply { SecureRandom().nextBytes(this) }
            val nonce = ByteArray(NONCE_SIZE).apply { SecureRandom().nextBytes(this) }

            val passwordChars = password.toCharArray()
            val key = try {
                val spec = PBEKeySpec(passwordChars, salt, ITERATIONS, KEY_LENGTH_BYTES * 8)
                val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                factory.generateSecret(spec).encoded
            } finally {
                passwordChars.fill('\u0000') // Wipe password
            }

            val aead = XChaCha20Poly1305(key)
            val cipher = aead.encrypt(plainText.toByteArray(Charsets.UTF_8), nonce)
            key.fill(0) // Wipe key

            return listOf(salt, nonce, cipher).joinToString("|") {
                Base64.encodeToString(it, Base64.NO_WRAP)
            }
        }

        /**
         * Decrypts data from export/backup files.
         * 
         * INPUT FORMAT: salt|nonce|ciphertext (Base64 encoded, pipe-separated)
         */
        fun decryptFromExport(base64Data: String, password: String): String {
            val parts = base64Data.split("|")
            require(parts.size == 3) { "Invalid encrypted format" }

            val salt = Base64.decode(parts[0], Base64.NO_WRAP)
            val nonce = Base64.decode(parts[1], Base64.NO_WRAP)
            val ciphertext = Base64.decode(parts[2], Base64.NO_WRAP)

            val passwordChars = password.toCharArray()
            val key = try {
                val spec = PBEKeySpec(passwordChars, salt, ITERATIONS, KEY_LENGTH_BYTES * 8)
                val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                factory.generateSecret(spec).encoded
            } finally {
                passwordChars.fill('\u0000') // Wipe password
            }

            val aead = XChaCha20Poly1305(key)
            val plain = aead.decrypt(ciphertext, nonce)
            key.fill(0) // Wipe key

            return String(plain, Charsets.UTF_8)
        }
    }
}
