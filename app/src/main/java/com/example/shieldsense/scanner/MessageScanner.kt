package com.example.shieldsense.scanner

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.util.concurrent.TimeUnit

object MessageScanner {

    private const val TAG = "ShieldSense:Scanner"
    
    // Increased timeouts for Render (Free Tier needs more time)
    private val client = OkHttpClient.Builder()
        .connectTimeout(120, TimeUnit.SECONDS)
        .writeTimeout(120, TimeUnit.SECONDS)
        .readTimeout(120, TimeUnit.SECONDS)
        .retryOnConnectionFailure(true)
        .build()

    suspend fun scan(context: Context, sender: String, body: String): ScanResult = withContext(Dispatchers.IO) {
        var riskScore = 0
        var apiVerdict = "Analysing..."
        var attackType = "None"
        var finalVerdict = Verdict.SAFE

        Log.d(TAG, "Calling API for: $body")

        try {
            // Create JSON request body as required by your Python API
            val jsonBody = JSONObject().put("text", body)
            val request = Request.Builder()
                .url("https://shield-sense-api.onrender.com/predict")
                .post(jsonBody.toString().toRequestBody("application/json".toMediaType()))
                .addHeader("Content-Type", "application/json")
                .build()

            val response = client.newCall(request).execute()
            val responseData = response.body?.string() ?: ""
            Log.d(TAG, "Server Response: $responseData")

            if (response.isSuccessful && responseData.isNotEmpty()) {
                val jsonResponse = JSONObject(responseData)
                // Assuming your API returns {"prediction": "1"} for Scam and "0" for Safe
                val prediction = jsonResponse.optString("prediction", "0")
                
                if (prediction == "1") {
                    riskScore = 95
                    finalVerdict = Verdict.PHISHING
                    apiVerdict = "CLOUD: VERIFIED SCAM"
                    attackType = detectAttackType(body)
                } else {
                    riskScore = 5
                    finalVerdict = Verdict.SAFE
                    apiVerdict = "CLOUD: VERIFIED SAFE"
                }
            } else {
                Log.e(TAG, "API Error: ${response.code}")
                // LOCAL FALLBACK IF API FAILS
                val localResult = runLocalScan(body)
                riskScore = localResult.first
                finalVerdict = localResult.second
                apiVerdict = "LOCAL AI (Cloud Offline)"
                attackType = detectAttackType(body)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Connection Failed: ${e.message}")
            // LOCAL FALLBACK IF NETWORK FAILS
            val localResult = runLocalScan(body)
            riskScore = localResult.first
            finalVerdict = localResult.second
            apiVerdict = "LOCAL AI (Network Error)"
            attackType = detectAttackType(body)
        }

        ScanResult(
            sender = sender,
            messageBody = body,
            urls = extractUrls(body),
            nlpScore = riskScore,
            urlScore = if (extractUrls(body).isNotEmpty()) 80 else 0,
            safeBrowseScore = 0,
            riskScore = riskScore,
            verdict = finalVerdict,
            attackType = attackType,
            explanation = apiVerdict
        )
    }

    private fun runLocalScan(body: String): Pair<Int, Verdict> {
        val lowerBody = body.lowercase()
        val phishingKeywords = listOf("otp", "verify", "bank", "kyc", "blocked", "suspended", "won", "gift", "prize", "click", "update", "urgent", "bit.ly")
        val matchCount = phishingKeywords.count { lowerBody.contains(it) }
        
        return if (matchCount >= 2 || extractUrls(body).isNotEmpty()) {
            Pair(85, Verdict.PHISHING)
        } else {
            Pair(10, Verdict.SAFE)
        }
    }

    private fun extractUrls(text: String): List<String> {
        val urls = mutableListOf<String>()
        val matcher = android.util.Patterns.WEB_URL.matcher(text)
        while (matcher.find()) { urls.add(matcher.group()) }
        return urls
    }

    private fun detectAttackType(body: String): String {
        val lower = body.lowercase()
        return when {
            lower.contains("otp") -> "OTP Fraud"
            lower.contains("bank") || lower.contains("kyc") -> "Bank Phishing"
            lower.contains("won") || lower.contains("prize") -> "Lottery Scam"
            else -> "Phishing Attempt"
        }
    }
}

enum class Verdict { SAFE, SUSPICIOUS, PHISHING }

data class ScanResult(
    val sender: String,
    val messageBody: String,
    val urls: List<String>,
    val nlpScore: Int,
    val urlScore: Int,
    val safeBrowseScore: Int,
    val riskScore: Int,
    val verdict: Verdict,
    val attackType: String,
    val explanation: String
)