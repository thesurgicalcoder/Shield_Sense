package com.shieldsense.app.scanner

import android.util.Log
import java.net.URL
import kotlin.math.log2

/**
 * UrlAnalyzer
 *
 * Scores a single URL on suspicious features — fully offline, no API needed.
 * Returns a risk probability 0.0–1.0.
 *
 * Signals checked:
 *   1. URL shortener detection        (bit.ly, tinyurl, etc.)
 *   2. Domain entropy (obfuscation)   (high entropy = likely random/generated)
 *   3. Excessive subdomains           (paypal.verify.evil.com)
 *   4. Lookalike domain patterns      (hdfcbank vs hdfc-bank-secure)
 *   5. Base64 / hex encoding in path  (obfuscated payload)
 *   6. Missing HTTPS                  (no SSL)
 *   7. Suspicious TLDs                (.xyz, .tk, .ml, .ga, .cf)
 *   8. IP address as host             (numeric host = always suspicious)
 *   9. Extremely long URL             (>200 chars = obfuscation attempt)
 *  10. Brand name in subdomain        (hdfc.evil.com pattern)
 */
object UrlAnalyzer {

    private const val TAG = "ShieldSense:UrlAnalyzer"

    // Common Indian bank and service brands to check for impersonation
    private val TARGET_BRANDS = setOf(
        "hdfc", "sbi", "icici", "axis", "kotak", "paytm", "phonepe",
        "gpay", "bhim", "upi", "npci", "uidai", "irctc", "amazon",
        "flipkart", "jio", "airtel", "vodafone"
    )

    private val URL_SHORTENERS = setOf(
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
        "is.gd", "buff.ly", "adf.ly", "short.st", "rebrand.ly",
        "cutt.ly", "rb.gy", "shorte.st"
    )

    private val SUSPICIOUS_TLDS = setOf(
        ".xyz", ".tk", ".ml", ".ga", ".cf", ".pw", ".top",
        ".gq", ".click", ".link", ".work", ".loan"
    )

    fun analyze(rawUrl: String): Float {
        var score = 0f  // accumulate suspicious signal weights

        val url = try {
            URL(if (rawUrl.startsWith("http")) rawUrl else "https://$rawUrl")
        } catch (e: Exception) {
            Log.w(TAG, "Could not parse URL: $rawUrl")
            return 0.5f  // unparseable URL is mildly suspicious
        }

        val host    = url.host?.lowercase() ?: return 0.5f
        val path    = url.path?.lowercase() ?: ""
        val fullUrl = rawUrl.lowercase()

        // ── 1. URL shortener ──────────────────────────────────────────────
        if (URL_SHORTENERS.any { host.endsWith(it) }) {
            score += 0.35f  // high weight — shorteners hide real destination
            Log.d(TAG, "[$rawUrl] shortener detected +0.35")
        }

        // ── 2. Domain entropy ─────────────────────────────────────────────
        val domainPart  = host.substringBeforeLast('.').substringAfterLast('.')
        val entropy     = shannonEntropy(domainPart)
        if (entropy > 3.8f) {
            score += 0.20f  // high entropy = randomly generated domain
            Log.d(TAG, "[$rawUrl] high entropy ${"%.2f".format(entropy)} +0.20")
        }

        // ── 3. Excessive subdomains ───────────────────────────────────────
        val subdomainCount = host.split('.').size - 2
        if (subdomainCount >= 3) {
            score += 0.15f
            Log.d(TAG, "[$rawUrl] $subdomainCount subdomains +0.15")
        }

        // ── 4. Brand name in subdomain (not in main domain) ──────────────
        val registeredDomain = host.split('.').takeLast(2).joinToString(".")
        val subdomains       = host.removeSuffix(".$registeredDomain")
        val brandInSub = TARGET_BRANDS.any { brand ->
            subdomains.contains(brand) && !registeredDomain.contains(brand)
        }
        if (brandInSub) {
            score += 0.40f  // very strong signal — classic impersonation pattern
            Log.d(TAG, "[$rawUrl] brand in subdomain +0.40")
        }

        // ── 5. Base64 / hex in path ───────────────────────────────────────
        if (Regex("[A-Za-z0-9+/]{40,}={0,2}").containsMatchIn(path) ||
            Regex("%[0-9a-f]{2}(%[0-9a-f]{2}){5,}").containsMatchIn(fullUrl)) {
            score += 0.15f
            Log.d(TAG, "[$rawUrl] encoded payload in path +0.15")
        }

        // ── 6. No HTTPS ───────────────────────────────────────────────────
        if (url.protocol == "http") {
            score += 0.10f
            Log.d(TAG, "[$rawUrl] no SSL +0.10")
        }

        // ── 7. Suspicious TLD ─────────────────────────────────────────────
        if (SUSPICIOUS_TLDS.any { fullUrl.contains(it) }) {
            score += 0.20f
            Log.d(TAG, "[$rawUrl] suspicious TLD +0.20")
        }

        // ── 8. IP address as host ─────────────────────────────────────────
        if (Regex("^\\d{1,3}(\\.\\d{1,3}){3}$").matches(host)) {
            score += 0.45f  // almost always malicious
            Log.d(TAG, "[$rawUrl] IP address host +0.45")
        }

        // ── 9. Very long URL ──────────────────────────────────────────────
        if (rawUrl.length > 200) {
            score += 0.10f
            Log.d(TAG, "[$rawUrl] very long URL (${rawUrl.length} chars) +0.10")
        }

        // ── 10. Lookalike brand spelling ──────────────────────────────────
        val hasDashBrand = TARGET_BRANDS.any { brand ->
            registeredDomain.contains("$brand-") || registeredDomain.contains("-$brand")
        }
        if (hasDashBrand) {
            score += 0.30f
            Log.d(TAG, "[$rawUrl] lookalike brand with dash +0.30")
        }

        val clamped = score.coerceIn(0f, 1f)
        Log.d(TAG, "[$rawUrl] final URL risk: ${"%.2f".format(clamped)}")
        return clamped
    }

    /** Shannon entropy — measures randomness of a string */
    private fun shannonEntropy(s: String): Float {
        if (s.isEmpty()) return 0f
        val freq = s.groupBy { it }.mapValues { it.value.size.toFloat() / s.length }
        return -freq.values.sumOf { p -> (p * log2(p.toDouble())).toDouble() }.toFloat()
    }
}

/**
 * UrlExtractor
 * Pulls all URLs out of a raw message body using a broad regex.
 */
object UrlExtractor {
    private val URL_REGEX = Regex(
        """(https?://[^\s]+|www\.[^\s]+|[a-z0-9\-]+\.[a-z]{2,}(/[^\s]*)?)""",
        RegexOption.IGNORE_CASE
    )

    fun extractUrls(text: String): List<String> =
        URL_REGEX.findAll(text).map { it.value }.toList()
}
