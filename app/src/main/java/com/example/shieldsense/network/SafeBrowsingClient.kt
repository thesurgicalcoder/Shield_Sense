package com.example.shieldsense.network // Tera correct package name

import android.util.Log
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.Body
import retrofit2.http.POST
import retrofit2.http.Query

// Note: Yahan se 'import com.shieldsense.app.BuildConfig' hata diya gaya hai

object SafeBrowsingClient {

    private const val TAG      = "ShieldSense:SafeBrowse"
    private const val BASE_URL = "https://safebrowsing.googleapis.com/"

    private val api: SafeBrowsingApi by lazy {
        Retrofit.Builder()
            .baseUrl(BASE_URL)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(SafeBrowsingApi::class.java)
    }

    // Teri API Key (Direct use ke liye)
    val apiKey = "AIzaSyDhpTCvgMBqR-JQyo68EGFJNU5rWP7W1lI"

    suspend fun checkUrls(urls: List<String>): Boolean {
        if (urls.isEmpty()) return false

        val requestBody = SafeBrowsingRequest(
            client = ClientInfo(
                clientId      = "shieldsense",
                clientVersion = "1.0.0"
            ),
            threatInfo = ThreatInfo(
                threatTypes      = listOf(
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ),
                platformTypes    = listOf("ANDROID"),
                threatEntryTypes = listOf("URL"),
                threatEntries    = urls.map { ThreatEntry(url = it) }
            )
        )

        return try {
            // YAHAN THA ERROR: BuildConfig hata kar direct 'apiKey' variable pass kiya hai
            val response = api.findThreatMatches(
                key  = apiKey,
                body = requestBody
            )
            val flagged = response.matches?.isNotEmpty() == true
            if (flagged) {
                Log.w(TAG, "Safe Browsing flagged: ${response.matches?.map { it.threat.url }}")
            }
            flagged
        } catch (e: Exception) {
            Log.e(TAG, "Safe Browsing API error: ${e.message}", e)
            false  // fail open — don't block on API failure
        }
    }
}

// ── Retrofit interface ────────────────────────────────────────────────────────

interface SafeBrowsingApi {
    @POST("v4/threatMatches:find")
    suspend fun findThreatMatches(
        @Query("key")  key:  String,
        @Body          body: SafeBrowsingRequest
    ): SafeBrowsingResponse
}

// ── Request data classes ──────────────────────────────────────────────────────

data class SafeBrowsingRequest(
    val client:     ClientInfo,
    val threatInfo: ThreatInfo
)

data class ClientInfo(
    val clientId:      String,
    val clientVersion: String
)

data class ThreatInfo(
    val threatTypes:      List<String>,
    val platformTypes:    List<String>,
    val threatEntryTypes: List<String>,
    val threatEntries:    List<ThreatEntry>
)

data class ThreatEntry(val url: String)

// ── Response data classes ─────────────────────────────────────────────────────

data class SafeBrowsingResponse(
    val matches: List<ThreatMatch>?  // null = no threats found
)

data class ThreatMatch(
    val threatType:      String,
    val platformType:    String,
    val threat:          ThreatEntry,
    val cacheDuration:   String?
)