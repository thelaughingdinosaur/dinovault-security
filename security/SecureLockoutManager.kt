/*
 * DinoVault - SecureLockoutManager.kt
 * 
 * This is the ACTUAL brute-force protection implementation used in DinoVault.
 * Published for security transparency.
 * 
 * SECURITY FEATURES:
 * - EncryptedSharedPreferences (AES256-GCM) to prevent tampering
 * - SystemClock.elapsedRealtime() to prevent clock manipulation attacks
 * - Rate limiting (500ms minimum between attempts)
 * - Exponential backoff (5min → 10min → 20min → 40min → 80min → 2hr max)
 * - Permanent lockout after 100 total lifetime attempts
 * - Attack logging for forensic analysis
 * - Tamper detection (root, debugger, emulator)
 * 
 * Source: https://github.com/YOUR_USERNAME/dinovault-security
 * App Version: 5.3
 */

package com.techmania.pocketmind.vault.security

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.os.SystemClock
import android.provider.Settings
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlin.math.pow

/**
 * Industry-grade brute-force protection for DinoVault.
 * 
 * SECURITY PARAMETERS:
 * - Rate limiting: 500ms minimum between attempts (blocks automated tools)
 * - Lockout trigger: After 10 failed attempts
 * - Initial lockout: 5 minutes
 * - Maximum lockout: 2 hours
 * - Permanent lockout: After 100 total lifetime attempts
 * 
 * ANTI-TAMPERING:
 * - Uses EncryptedSharedPreferences (AES256-GCM key encryption, AES256-SIV value encryption)
 * - Uses SystemClock.elapsedRealtime() instead of System.currentTimeMillis()
 *   This prevents attackers from bypassing lockouts by changing the device clock
 * - Tamper detection for rooted devices, debuggers, and emulators
 */
object SecureLockoutManager {

    private const val TAG = "SecureLockoutManager"
    
    // Encrypted storage - prevents tampering on rooted devices
    private const val ENCRYPTED_PREF_NAME = "secure_vault_lockout"
    
    // Legacy storage - for migration from older versions only
    private const val LEGACY_PREF_NAME = "vault_lockout_prefs"
    
    // Storage keys
    private const val KEY_ATTEMPTS = "failed_attempts"
    private const val KEY_LOCKOUT_END_REALTIME = "lockout_end_realtime_ms"
    private const val KEY_LAST_ATTEMPT_REALTIME = "last_attempt_realtime_ms"
    private const val KEY_TOTAL_LIFETIME_ATTEMPTS = "total_lifetime_attempts"
    private const val KEY_MIGRATION_VERSION = "migration_version"
    private const val KEY_PERMANENT_LOCKOUT = "permanent_lockout"
    private const val KEY_ATTACK_LOG = "attack_log"
    
    // Legacy keys for migration
    private const val LEGACY_KEY_ATTEMPTS = "failed_attempts"
    private const val LEGACY_KEY_END_TIME = "lockout_end_time"
    
    // Security parameters
    private const val BASE_LOCKOUT_SECONDS = 300      // 5 minutes
    private const val MAX_LOCKOUT_SECONDS = 7200      // 2 hours
    private const val MIN_ATTEMPT_INTERVAL_MS = 500L  // Rate limiting: 500ms between attempts
    private const val PERMANENT_LOCKOUT_THRESHOLD = 100
    private const val CURRENT_MIGRATION_VERSION = 1
    
    /**
     * Creates encrypted SharedPreferences with automatic migration from legacy storage.
     * 
     * Encryption:
     * - Key encryption: AES256-SIV (deterministic, for key lookup)
     * - Value encryption: AES256-GCM (authenticated encryption)
     * - Master key: Stored in Android Keystore (hardware-backed when available)
     */
    private fun getEncryptedPrefs(context: Context): SharedPreferences {
        try {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

            val encryptedPrefs = EncryptedSharedPreferences.create(
                context,
                ENCRYPTED_PREF_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
            
            // Perform one-time migration from legacy storage
            performMigrationIfNeeded(context, encryptedPrefs)
            
            return encryptedPrefs
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create EncryptedSharedPreferences. Using fallback.", e)
            // Fallback to regular SharedPreferences if encryption fails
            return context.getSharedPreferences(ENCRYPTED_PREF_NAME, Context.MODE_PRIVATE)
        }
    }
    
    /**
     * Migrates existing user data from legacy unencrypted storage.
     * Preserves active lockouts during app upgrades.
     */
    private fun performMigrationIfNeeded(context: Context, encryptedPrefs: SharedPreferences) {
        val migrationVersion = encryptedPrefs.getInt(KEY_MIGRATION_VERSION, 0)
        
        if (migrationVersion >= CURRENT_MIGRATION_VERSION) {
            return // Already migrated
        }
        
        Log.i(TAG, "Performing migration from legacy LockoutTimerManager...")
        
        try {
            val legacyPrefs = context.getSharedPreferences(LEGACY_PREF_NAME, Context.MODE_PRIVATE)
            val editor = encryptedPrefs.edit()
            
            // Migrate failed attempts count
            val legacyAttempts = legacyPrefs.getInt(LEGACY_KEY_ATTEMPTS, 0)
            if (legacyAttempts > 0) {
                editor.putInt(KEY_ATTEMPTS, legacyAttempts)
                editor.putInt(KEY_TOTAL_LIFETIME_ATTEMPTS, legacyAttempts)
                Log.i(TAG, "Migrated $legacyAttempts failed attempts")
            }
            
            // Migrate lockout end time from currentTimeMillis to elapsedRealtime
            val legacyEndTime = legacyPrefs.getLong(LEGACY_KEY_END_TIME, 0L)
            if (legacyEndTime > 0L) {
                val now = System.currentTimeMillis()
                if (legacyEndTime > now) {
                    // Lockout is still active, preserve remaining time
                    val remainingMs = legacyEndTime - now
                    val newEndTimeRealtime = SystemClock.elapsedRealtime() + remainingMs
                    editor.putLong(KEY_LOCKOUT_END_REALTIME, newEndTimeRealtime)
                    Log.i(TAG, "Migrated active lockout with ${remainingMs / 1000}s remaining")
                }
            }
            
            editor.putInt(KEY_MIGRATION_VERSION, CURRENT_MIGRATION_VERSION)
            editor.apply()
            
            Log.i(TAG, "Migration completed successfully")
            
        } catch (e: Exception) {
            Log.e(TAG, "Migration failed, continuing with new system", e)
        }
    }
    
    /**
     * Records a failed login attempt with comprehensive security checks.
     * 
     * @return Triple<isRateLimited, isPermanentlyLocked, message>
     *         - isRateLimited: true if attempt was blocked
     *         - isPermanentlyLocked: true if account is permanently locked
     *         - message: User-facing message explaining the lockout
     */
    fun recordFailedAttempt(context: Context): Triple<Boolean, Boolean, String?> {
        val prefs = getEncryptedPrefs(context)
        
        // CHECK 1: Permanent lockout
        if (prefs.getBoolean(KEY_PERMANENT_LOCKOUT, false)) {
            return Triple(true, true, "Account permanently locked. Contact support.")
        }
        
        // CHECK 2: Rate limiting - blocks automated/scripted attacks
        val lastAttemptTime = prefs.getLong(KEY_LAST_ATTEMPT_REALTIME, 0L)
        val currentTime = SystemClock.elapsedRealtime()
        val timeSinceLastAttempt = currentTime - lastAttemptTime
        
        if (lastAttemptTime > 0 && timeSinceLastAttempt < MIN_ATTEMPT_INTERVAL_MS) {
            val waitTimeMs = MIN_ATTEMPT_INTERVAL_MS - timeSinceLastAttempt
            Log.w(TAG, "Rate limit triggered. Wait ${waitTimeMs}ms")
            return Triple(true, false, "Too fast. Wait ${waitTimeMs / 1000.0}s")
        }
        
        // CHECK 3: Active lockout timer
        val lockoutEndTime = prefs.getLong(KEY_LOCKOUT_END_REALTIME, 0L)
        if (lockoutEndTime > 0 && currentTime < lockoutEndTime) {
            val remainingSeconds = ((lockoutEndTime - currentTime) / 1000).toInt()
            return Triple(true, false, formatLockoutMessage(remainingSeconds))
        }
        
        // RECORD THE ATTEMPT
        val editor = prefs.edit()
        val attempts = prefs.getInt(KEY_ATTEMPTS, 0) + 1
        val totalLifetimeAttempts = prefs.getInt(KEY_TOTAL_LIFETIME_ATTEMPTS, 0) + 1
        
        editor.putInt(KEY_ATTEMPTS, attempts)
        editor.putInt(KEY_TOTAL_LIFETIME_ATTEMPTS, totalLifetimeAttempts)
        editor.putLong(KEY_LAST_ATTEMPT_REALTIME, currentTime)
        
        // Log attack for forensic analysis
        logAttack(context, editor, attempts, totalLifetimeAttempts)
        
        // CHECK 4: Permanent lockout threshold (100 lifetime attempts)
        if (totalLifetimeAttempts >= PERMANENT_LOCKOUT_THRESHOLD) {
            editor.putBoolean(KEY_PERMANENT_LOCKOUT, true)
            editor.apply()
            Log.e(TAG, "PERMANENT LOCKOUT: $totalLifetimeAttempts total lifetime attempts")
            return Triple(true, true, "Too many attempts. Account permanently locked.")
        }
        
        // CHECK 5: Temporary lockout (after 10 failed attempts in session)
        if (attempts >= 10) {
            val lockoutAttemptNumber = attempts - 10 + 1
            val lockoutDurationSeconds = calculateLockoutDuration(lockoutAttemptNumber)
            val lockoutEndRealtime = currentTime + (lockoutDurationSeconds * 1000L)
            
            editor.putLong(KEY_LOCKOUT_END_REALTIME, lockoutEndRealtime)
            editor.apply()
            
            Log.w(TAG, "Lockout activated: ${lockoutDurationSeconds}s (attempt #$attempts)")
            return Triple(true, false, formatLockoutMessage(lockoutDurationSeconds))
        }
        
        editor.apply()
        Log.i(TAG, "Recorded failed attempt #$attempts (lifetime: $totalLifetimeAttempts)")
        return Triple(false, false, null)
    }
    
    /**
     * Gets remaining lockout time in seconds.
     * Uses SystemClock.elapsedRealtime() to prevent clock manipulation attacks.
     * 
     * @return Seconds remaining, 0 if not locked, Int.MAX_VALUE if permanently locked
     */
    fun getRemainingLockoutSeconds(context: Context): Int {
        val prefs = getEncryptedPrefs(context)
        
        if (prefs.getBoolean(KEY_PERMANENT_LOCKOUT, false)) {
            return Int.MAX_VALUE // Represents permanent lockout
        }
        
        val lockoutEndTime = prefs.getLong(KEY_LOCKOUT_END_REALTIME, 0L)
        if (lockoutEndTime == 0L) return 0
        
        val currentTime = SystemClock.elapsedRealtime()
        val remainingMs = lockoutEndTime - currentTime
        
        if (remainingMs <= 0) {
            prefs.edit().remove(KEY_LOCKOUT_END_REALTIME).apply()
            return 0
        }
        
        return (remainingMs / 1000).toInt()
    }
    
    /**
     * Gets current session's failed attempts count.
     * Automatically resets if a previous lockout has expired.
     */
    fun getFailedAttempts(context: Context): Int {
        val prefs = getEncryptedPrefs(context)
        
        val lockoutEndTime = prefs.getLong(KEY_LOCKOUT_END_REALTIME, 0L)
        val currentTime = SystemClock.elapsedRealtime()
        
        if (lockoutEndTime > 0 && currentTime >= lockoutEndTime) {
            // Lockout expired, reset session attempts (lifetime counter preserved)
            prefs.edit()
                .remove(KEY_ATTEMPTS)
                .remove(KEY_LOCKOUT_END_REALTIME)
                .apply()
            return 0
        }
        
        return prefs.getInt(KEY_ATTEMPTS, 0)
    }
    
    /**
     * Resets lockout counters after successful login.
     * Note: Lifetime counter is NOT reset - only cleared on vault reset.
     */
    fun reset(context: Context) {
        val prefs = getEncryptedPrefs(context)
        prefs.edit()
            .remove(KEY_ATTEMPTS)
            .remove(KEY_LOCKOUT_END_REALTIME)
            .remove(KEY_LAST_ATTEMPT_REALTIME)
            .apply()
        Log.i(TAG, "Lockout reset after successful login")
    }
    
    /**
     * Gets total lifetime failed attempts across all sessions.
     */
    fun getTotalLifetimeAttempts(context: Context): Int {
        return getEncryptedPrefs(context).getInt(KEY_TOTAL_LIFETIME_ATTEMPTS, 0)
    }
    
    /**
     * Checks if account is permanently locked (100+ lifetime attempts).
     */
    fun isPermanentlyLocked(context: Context): Boolean {
        return getEncryptedPrefs(context).getBoolean(KEY_PERMANENT_LOCKOUT, false)
    }
    
    /**
     * EMERGENCY ONLY: Clears permanent lockout.
     * Should only be called after user verification (e.g., vault reset with biometric).
     */
    fun clearPermanentLockout(context: Context, reason: String) {
        val prefs = getEncryptedPrefs(context)
        prefs.edit()
            .putBoolean(KEY_PERMANENT_LOCKOUT, false)
            .putInt(KEY_TOTAL_LIFETIME_ATTEMPTS, 0)
            .apply()
        Log.w(TAG, "PERMANENT LOCKOUT CLEARED: $reason")
    }
    
    /**
     * Gets attack log for security monitoring/debugging.
     * Stores last 20 failed attempt timestamps.
     */
    fun getAttackLog(context: Context): String {
        return getEncryptedPrefs(context).getString(KEY_ATTACK_LOG, "No attacks recorded") ?: ""
    }
    
    /**
     * Calculates lockout duration using exponential backoff.
     * 
     * Progression:
     * - 1st lockout (10th attempt): 5 minutes
     * - 2nd lockout (11th attempt): 10 minutes
     * - 3rd lockout (12th attempt): 20 minutes
     * - 4th lockout (13th attempt): 40 minutes
     * - 5th lockout (14th attempt): 80 minutes
     * - 6th+ lockout: 2 hours (maximum)
     */
    private fun calculateLockoutDuration(lockoutAttemptNumber: Int): Int {
        val backoff = BASE_LOCKOUT_SECONDS * 2.0.pow(lockoutAttemptNumber - 1)
        return backoff.toInt().coerceAtMost(MAX_LOCKOUT_SECONDS)
    }
    
    /**
     * Logs attack attempts for forensic analysis.
     * Keeps last 20 entries to avoid unbounded storage growth.
     */
    private fun logAttack(context: Context, editor: SharedPreferences.Editor, attempts: Int, totalAttempts: Int) {
        try {
            val timestamp = System.currentTimeMillis()
            val deviceId = getDeviceId(context)
            val logEntry = "[$timestamp] Attempt #$attempts (Total: $totalAttempts) Device: $deviceId"
            
            val existingLog = getEncryptedPrefs(context).getString(KEY_ATTACK_LOG, "") ?: ""
            val updatedLog = if (existingLog.isBlank()) {
                logEntry
            } else {
                val entries = existingLog.split("\n").takeLast(19)
                (entries + logEntry).joinToString("\n")
            }
            
            editor.putString(KEY_ATTACK_LOG, updatedLog)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to log attack", e)
        }
    }
    
    /**
     * Gets truncated device ID for attack correlation.
     * Only first 8 characters of Android ID (privacy-preserving).
     */
    private fun getDeviceId(context: Context): String {
        return try {
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
                ?.take(8) ?: "unknown"
        } catch (e: Exception) {
            "unknown"
        }
    }
    
    /**
     * Formats lockout duration for user display.
     */
    private fun formatLockoutMessage(seconds: Int): String {
        if (seconds == Int.MAX_VALUE) return "Account permanently locked"
        
        return when {
            seconds >= 3600 -> {
                val hours = seconds / 3600
                val mins = (seconds % 3600) / 60
                "Locked for ${hours}h ${mins}m"
            }
            seconds >= 60 -> {
                val mins = seconds / 60
                val secs = seconds % 60
                "Locked for ${mins}m ${secs}s"
            }
            else -> "Locked for ${seconds}s"
        }
    }
    
    /**
     * Performs tamper detection checks.
     * Currently logs warnings but does not block access.
     * 
     * Detects:
     * - Rooted devices (su binary present)
     * - Attached debuggers
     * - Emulator environments
     */
    fun performTamperCheck(context: Context): TamperStatus {
        val issues = mutableListOf<String>()
        
        if (isDeviceRooted()) {
            issues.add("Device is rooted")
        }
        
        if (isDebuggerConnected()) {
            issues.add("Debugger detected")
        }
        
        if (isEmulator()) {
            issues.add("Running on emulator")
        }
        
        return if (issues.isEmpty()) {
            TamperStatus.SECURE
        } else {
            Log.w(TAG, "Tamper detected: ${issues.joinToString(", ")}")
            TamperStatus.COMPROMISED(issues)
        }
    }
    
    /**
     * Basic root detection - checks for common su binary locations.
     */
    private fun isDeviceRooted(): Boolean {
        return try {
            val paths = arrayOf(
                "/system/app/Superuser.apk",
                "/sbin/su",
                "/system/bin/su",
                "/system/xbin/su",
                "/data/local/xbin/su",
                "/data/local/bin/su",
                "/system/sd/xbin/su",
                "/system/bin/failsafe/su",
                "/data/local/su"
            )
            paths.any { java.io.File(it).exists() }
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Debugger detection using Android Debug API.
     */
    private fun isDebuggerConnected(): Boolean {
        return android.os.Debug.isDebuggerConnected()
    }
    
    /**
     * Emulator detection using Build properties.
     */
    private fun isEmulator(): Boolean {
        return (Build.FINGERPRINT.startsWith("generic")
                || Build.FINGERPRINT.startsWith("unknown")
                || Build.MODEL.contains("google_sdk")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK built for x86")
                || Build.MANUFACTURER.contains("Genymotion")
                || Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")
                || "google_sdk" == Build.PRODUCT)
    }
}

/**
 * Result of tamper detection check.
 */
sealed class TamperStatus {
    object SECURE : TamperStatus()
    data class COMPROMISED(val issues: List<String>) : TamperStatus()
}
