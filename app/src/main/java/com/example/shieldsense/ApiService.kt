package com.example.shieldsense

import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import retrofit2.http.Body
import retrofit2.http.POST

data class PredictionRequest(val text: String)
data class PredictionResponse(val prediction: String)

interface ApiService {
    @POST("predict")
    suspend fun getPrediction(@Body request: PredictionRequest): PredictionResponse

    companion object {
        // Pointing to your live Render server instead of local emulator
        private const val BASE_URL = "https://shield-sense-api.onrender.com/"

        fun create(): ApiService {
            return Retrofit.Builder()
                .baseUrl(BASE_URL)
                .addConverterFactory(GsonConverterFactory.create())
                .build()
                .create(ApiService::class.java)
        }
    }
}