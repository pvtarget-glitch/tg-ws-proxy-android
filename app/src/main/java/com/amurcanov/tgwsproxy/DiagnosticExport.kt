package com.amurcanov.tgwsproxy

import android.content.Context
import android.net.Uri
import android.util.Log
import android.widget.Toast
import java.io.IOException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Export state is private app data, not ephemeral Compose remember state.
 * SAF creates an empty target document before delivering a result URI.
 */
internal object DiagnosticExport {
    private const val PENDING = "tg-ws-proxy-diagnostic-pending.json"
    private const val TAG = "TgWsProxy"
    private val exportScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    fun prepare(context: Context, json: String): Int {
        val bytes = json.toByteArray(Charsets.UTF_8)
        require(bytes.size >= 2 && json.trimStart().startsWith("{")) {
            "JSON report is empty or invalid"
        }
        context.applicationContext.openFileOutput(PENDING, Context.MODE_PRIVATE).use {
            it.write(bytes)
            it.flush()
        }
        Log.i(TAG, "DIAG EXPORT stage=prepared bytes=${bytes.size}")
        return bytes.size
    }

    fun saveToDocument(context: Context, uri: Uri) {
        val appContext = context.applicationContext
        // Independent of Activity lifecycle and rememberCoroutineScope.
        exportScope.launch {
            val outcome = runCatching {
                val payload = appContext.openFileInput(PENDING).use { it.readBytes() }
                if (payload.isEmpty()) throw IOException("Empty private diagnostic payload")
                appContext.contentResolver.openOutputStream(uri, "wt")?.use { output ->
                    output.write(payload)
                    output.flush()
                } ?: throw IOException("Destination stream unavailable")
                val actual = runCatching {
                    appContext.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                }.getOrNull()
                if (actual != null && !actual.contentEquals(payload)) {
                    throw IOException("Export verification failed: expected ${payload.size}, read ${actual.size}")
                }
                Log.i(TAG, "DIAG EXPORT stage=written bytes=${payload.size} verified=${actual != null}")
                payload.size
            }
            outcome.exceptionOrNull()?.let {
                Log.e(TAG, "DIAG EXPORT stage=failed reason=${it.javaClass.simpleName}: ${it.message}")
            }
            withContext(Dispatchers.Main) {
                Toast.makeText(
                    appContext,
                    if (outcome.isSuccess) appContext.getString(R.string.diag_saved)
                    else appContext.getString(R.string.log_export_failed),
                    Toast.LENGTH_LONG
                ).show()
            }
        }
    }
}
