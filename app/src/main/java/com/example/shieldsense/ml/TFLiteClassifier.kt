package com.shieldsense.app.ml

import android.content.Context
import android.util.Log
import org.tensorflow.lite.Interpreter
import java.io.FileInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel

/**
 * TFLiteClassifier
 *
 * Singleton wrapper around Person B's exported .tflite model.
 *
 * CONTRACT WITH PERSON B (agree before hackathon):
 *   Input:  int32[1, MAX_SEQ_LEN]  — tokenised message IDs
 *   Output: float32[1, 1]          — phishing probability 0.0–1.0
 *            OR float32[1, 2]      — [safe_prob, phishing_prob]  (two-class softmax)
 *
 * Model file: place  shieldsense_model.tflite  in  app/src/main/assets/
 */
class TFLiteClassifier private constructor(context: Context) {

    companion object {
        private const val TAG          = "ShieldSense:TFLite"
        private const val MODEL_FILE   = "shieldsense_model.tflite"
        const val MAX_SEQ_LEN          = 128   // Must match Person B's tokeniser max_length

        @Volatile private var instance: TFLiteClassifier? = null

        fun getInstance(context: Context): TFLiteClassifier {
            return instance ?: synchronized(this) {
                instance ?: TFLiteClassifier(context.applicationContext).also { instance = it }
            }
        }
    }

    private val interpreter: Interpreter
    private val tokenizer: SimpleTokenizer

    init {
        val model  = loadModelFile(context)
        val options = Interpreter.Options().apply {
            setNumThreads(2)        // 2 threads is optimal for on-device inference
            setUseNNAPI(true)       // Use hardware accelerator if available
        }
        interpreter = Interpreter(model, options)
        tokenizer   = SimpleTokenizer(context)
        Log.d(TAG, "TFLite interpreter initialised. Input: ${interpreter.getInputTensor(0).shape().toList()}")
    }

    /**
     * Classify a message body.
     * Returns probability 0.0–1.0 (higher = more likely phishing).
     */
    fun classify(text: String): Float {
        val inputIds   = tokenizer.encode(text, MAX_SEQ_LEN)
        val inputBuffer = ByteBuffer.allocateDirect(4 * MAX_SEQ_LEN).apply {
            order(ByteOrder.nativeOrder())
            inputIds.forEach { putInt(it) }
            rewind()
        }

        // Output buffer: single float OR two-class — handle both shapes
        val outputShape = interpreter.getOutputTensor(0).shape()
        val outputSize  = outputShape.last()  // 1 or 2
        val outputBuffer = Array(1) { FloatArray(outputSize) }

        interpreter.run(
            arrayOf(inputBuffer),   // wrap in array for dynamic batching
            mapOf(0 to outputBuffer)
        )

        return when (outputSize) {
            1    -> outputBuffer[0][0]                    // single sigmoid output
            else -> outputBuffer[0][1]                    // two-class: take phishing class
        }
    }

    private fun loadModelFile(context: Context): ByteBuffer {
        val assetFileDescriptor = context.assets.openFd(MODEL_FILE)
        val inputStream         = FileInputStream(assetFileDescriptor.fileDescriptor)
        val fileChannel         = inputStream.channel
        val startOffset         = assetFileDescriptor.startOffset
        val declaredLength      = assetFileDescriptor.declaredLength
        return fileChannel.map(FileChannel.MapMode.READ_ONLY, startOffset, declaredLength)
    }

    fun close() {
        interpreter.close()
    }
}

/**
 * SimpleTokenizer
 *
 * Minimal whitespace tokenizer with a fixed vocab loaded from assets.
 * Person B must supply  vocab.txt  (one token per line) alongside the model.
 *
 * If Person B uses a HuggingFace tokenizer, replace this with
 * a Kotlin port of the WordPiece tokenizer or use tokenizers-android.
 */
class SimpleTokenizer(context: Context) {

    private val vocab: Map<String, Int>

    init {
        val lines = context.assets.open("vocab.txt").bufferedReader().readLines()
        vocab = lines.mapIndexed { idx, token -> token.trim() to idx }.toMap()
    }

    fun encode(text: String, maxLen: Int): IntArray {
        val tokens  = text.lowercase()
            .split(Regex("\\s+"))
            .map { vocab[it] ?: vocab["[UNK]"] ?: 1 }
            .take(maxLen - 2)  // leave space for [CLS] and [SEP]

        val ids = mutableListOf(vocab["[CLS]"] ?: 101)
        ids.addAll(tokens)
        ids.add(vocab["[SEP]"] ?: 102)

        // Pad to maxLen
        while (ids.size < maxLen) ids.add(vocab["[PAD]"] ?: 0)

        return ids.take(maxLen).toIntArray()
    }
}
