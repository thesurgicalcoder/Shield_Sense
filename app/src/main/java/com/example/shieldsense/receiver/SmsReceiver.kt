package com.example.shieldsense.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.telephony.SmsMessage
import android.util.Log
import android.widget.Toast
import com.example.shieldsense.scanner.MessageScanner
import com.example.shieldsense.scanner.ScanResult
import com.example.shieldsense.NotificationHelper
import com.example.shieldsense.MainActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class SmsReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return

        try {
            val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
            if (messages.isNullOrEmpty()) {
                Log.e("ShieldSense", "No messages found in intent")
                return
            }

            val senderNum = messages[0].originatingAddress ?: "Unknown"
            // Reassemble multi-part messages
            val body = messages.joinToString("") { it.displayMessageBody ?: "" }

            if (body.isEmpty()) {
                Log.e("ShieldSense", "Message body is empty")
                return
            }

            Log.d("ShieldSense", "New SMS from $senderNum: $body")
            
            // UI Update: Turant screen pe dikhao ki message aa gaya hai
            MainActivity.instance?.updateStatus("----------------------")
            MainActivity.instance?.updateStatus("INCOMING SMS FROM: $senderNum")
            MainActivity.instance?.updateStatus("READING: $body")

            val pendingResult = goAsync()
            CoroutineScope(Dispatchers.IO).launch {
                try {
                    val result = MessageScanner.scan(context, senderNum, body)
                    val isScam = result.riskScore >= 70
                    
                    MainActivity.instance?.updateDashboard(isScam, body)
                    
                    if (isScam) {
                        NotificationHelper.showNotification(
                            context,
                            "🚨 SCAM DETECTED",
                            "From $senderNum: ${result.attackType}"
                        )
                    }
                } catch (e: Exception) {
                    Log.e("ShieldSense", "Scan Error: ${e.message}")
                    MainActivity.instance?.updateStatus("SCAN ERROR: ${e.message}")
                } finally {
                    pendingResult.finish()
                }
            }
        } catch (e: Exception) {
            Log.e("ShieldSense", "Receiver Crash: ${e.message}")
        }
    }
}