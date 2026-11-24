package com.amurcanov.tgwsproxy.ui

import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.amurcanov.tgwsproxy.DiagnosticAnalyzer
import com.amurcanov.tgwsproxy.DiagnosticProbe
import com.amurcanov.tgwsproxy.DiagnosticExport
import com.amurcanov.tgwsproxy.LogManager
import com.amurcanov.tgwsproxy.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
internal fun DiagnosticsPanel(onClose: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var result by remember { mutableStateOf<DiagnosticAnalyzer.Report?>(null) }
    var busy by remember { mutableStateOf(false) }
    val export = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        if (uri != null) DiagnosticExport.saveToDocument(context, uri)
    }
    fun analyze(probes: List<DiagnosticProbe.Result> = emptyList()) {
        val journal = LogManager.snapshot()
        result = DiagnosticAnalyzer.analyze(journal.lines, journal.stats.truncated, probes)
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(stringResource(R.string.diag_title), style = MaterialTheme.typography.titleMedium)
        Text(stringResource(R.string.diag_notice), style = MaterialTheme.typography.bodySmall)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { analyze() }, enabled = !busy, modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.diag_analyze))
            }
            Button(onClick = {
                busy = true
                scope.launch {
                    try {
                        val probes = DiagnosticProbe.run(context)
                        analyze(probes)
                    } catch (e: Exception) {
                        Toast.makeText(context, "Diagnostic error: " + e.javaClass.simpleName, Toast.LENGTH_LONG).show()
                    } finally { busy = false }
                }
            }, enabled = !busy, modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.diag_probe))
            }
        }
        if (busy) {
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            Text(stringResource(R.string.diag_running), style = MaterialTheme.typography.bodySmall)
        }
        result?.let { r ->
            Text(r.summary(), style = MaterialTheme.typography.bodySmall)
            Button(onClick = {
                val json = reportJson(r).toString(2)
                val saved = runCatching { DiagnosticExport.prepare(context, json) }
                if (saved.isSuccess) {
                    val stamp = SimpleDateFormat("yyyy-MM-dd_HH-mm-ss", Locale.US).format(Date())
                    export.launch("tg-ws-proxy-diag-$stamp.json")
                } else {
                    Toast.makeText(context, context.getString(R.string.log_export_failed), Toast.LENGTH_LONG).show()
                }
            }) { Text(stringResource(R.string.diag_export)) }
        }
        OutlinedButton(onClick = onClose) { Text(stringResource(R.string.diag_back)) }
        Spacer(Modifier.height(16.dp))
    }
}

private fun reportJson(r: DiagnosticAnalyzer.Report): JSONObject = JSONObject().apply {
    put("schema", "tgwsproxy.diag.v1")
    put("version", "1.2.5.2-diag2")
    put("total_lines", r.total)
    put("truncated", r.truncated)
    put("current_network", r.current)
    put("network_changes", r.changes)
    put("warning", "Successful TCP/WS handshake does not prove full media download")
    put("networks", JSONArray().apply {
        r.groups.forEach { c ->
            put(JSONObject().apply {
                put("network", c.network)
                put("tcp_ok", c.tcpOk); put("tcp_timeout", c.tcpTimeout); put("tcp_other", c.tcpOther)
                put("tls_ok", c.tlsOk); put("tls_other", c.tlsOther)
                put("ws_ok", c.wsOk); put("ws_timeout", c.wsTimeout); put("ws_other", c.wsOther)
                put("media_sessions", c.mediaSessions); put("media_bytes", c.mediaBytes)
                put("cf_starts", c.cfStarts); put("cf_ends", c.cfEnds)
                put("cf_suspicious", c.cfSuspicious); put("cf_bytes", c.cfBytes)
                put("cf_cooldown", c.cfCooldown); put("cf_saturated", c.cfSaturated)
                put("local_capacity", c.localCapacity)
            })
        }
    })
    put("probes", JSONArray().apply {
        r.probes.forEach { p ->
            put(JSONObject().apply {
                put("network", p.network); put("label", p.label)
                put("host", p.host); put("port", p.port)
                put("attempt", p.attempt); put("ok", p.ok)
                put("elapsed_ms", p.elapsedMs); put("reason", p.reason)
            })
        }
    })
}
