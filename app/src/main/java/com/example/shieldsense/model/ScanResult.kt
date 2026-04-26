package com.shieldsense.app.model

import android.os.Parcelable
import kotlinx.parcelize.Parcelize

/**
 * ScanResult
 *
 * The single data object that flows from MessageScanner
 * through to ThreatAlertActivity and Firebase logging.
 *
 * Parcelable so it can be passed via Intent extras.
 */
@Parcelize
data class ScanResult(
    val sender:           String,
    val messageBody:      String,
    val urls:             List<String>,
    val nlpScore:         Int,        // 0–100
    val urlScore:         Int,        // 0–100
    val safeBrowseScore:  Int,        // 0–100 (100 = flagged by Safe Browsing)
    val riskScore:        Int,        // 0–100  (weighted final score)
    val verdict:          Verdict,
    val attackType:       String,     // e.g. "Smishing — Bank Impersonation"
    val explanation:      String,     // plain-language "Why" card text
    val timestamp:        Long = System.currentTimeMillis()
) : Parcelable

enum class Verdict {
    SAFE,       // < 40
    UNCERTAIN,  // 40–69
    SUSPICIOUS, // 70–89
    PHISHING    // 90–100
}
