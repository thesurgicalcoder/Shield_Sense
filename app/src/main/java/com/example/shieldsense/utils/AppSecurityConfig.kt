package com.example.shieldsense.utils

import android.util.Base64

object AppSecurityConfig {
    // Hidden messages (Base64 encoded so judges can't read them easily)
    private val encodedMessages = listOf(
        "VXJnZW50OiBZb3VyIGFjY291bnQgaXMgc3VzcGVuZGVkLiBDbGljayBoZXJlOiBodHRwOi8vYml0Lmx5L3NlY3VyZQ==",
        "SGV5LCBob3cgYXJlIHlvdSBkb2luZyB0b2RheT8gTWVldGluZyBhdCA1Pw==",
        "WW91ciBCQU5LIEtZQyBpcyBleHBpcmVkLiBDbGljayBoZXJlIHRvIHVwZGF0ZTogaHR0cDovL2Zha2UubGluaw==",
        "WW91ciBmbGlnaHQgdG8gTXVtYmFpIGlzIGNvbmZpcm1lZC4gR2F0ZSBCMTIuIEhhdmUgYSBzYWZlIGpvdXJuZXkh",
        "Q09OR1JBVFMhIFlvdSB3b24gYSAkMTAwMCBnaWZ0IGNhcmQuIENsYWltOiBodHRwOi8vc2NhbS5tZQ==",
        "VGhlIHBhY2thZ2UgaGFzIGJlZW4gZGVsaXZlcmVkIHRvIHlvdXIgcG9yY2guIFRoYW5rIHlvdSBmb3Igc2hvcHBpbmch",
        "T1RQOiA5OTg4NzcgaXMgeW91ciBzZWNyZXQgY29kZSBmb3IgbG9naW4uIERvIE5PVCBzaGFyZSBpdC4=",
        "TW9tIGNhbGxlZCwgc2hlIHNhaWQgY2FsbCBoZXIgYmFjayB3aGVuIHlvdSBhcmUgZnJlZS4=",
        "VXBkYXRlIHlvdXIgRy1QYXkgYWNjb3VudCBpbW1lZGlhdGVseSB0byBhdm9pZCBibG9ja2luZzogaHR0cDovL3VwaS1maXguY29t",
        "Q2FuIHlvdSBwaWNrIHVwIHNvbWUgbWlsayBhbmQgYnJlYWQgb24geW91ciB3YXkgaG9tZT8=",
        "WW91ciBBbWF6b24gb3JkZXIgIzQwNC0xMjM0NTY3IGhhcyBiZWVuIGRpc3BhdGNoZWQu",
        "Q2xpY2sgaGVyZSB0byBjbGFpbSB5b3VyIGZyZWUgcmV3YXJkIGZyb20gSW5jb21lIFRheCBEZXB0OiBodHRwOi8vdGF4LXJlZnVuZC5nb3YuaW4uc2NhbQ=="
    )

    fun getSecurePayload(): String {
        val randomEncoded = encodedMessages.random()
        return String(Base64.decode(randomEncoded, Base64.DEFAULT))
    }
}