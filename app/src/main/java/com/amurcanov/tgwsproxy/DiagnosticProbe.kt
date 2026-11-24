package com.amurcanov.tgwsproxy

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.util.Log
import java.net.InetSocketAddress
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Opt-in, bounded network checks: NO root, VPN, routing changes or packet interception. */
internal object DiagnosticProbe {
    data class Result(
        val network: String, val label: String, val host: String,
        val port: Int, val attempt: Int, val ok: Boolean,
        val elapsedMs: Long, val reason: String
    )
    suspend fun run(context: Context): List<Result> = withContext(Dispatchers.IO) {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val net = cm.activeNetwork ?: return@withContext listOf(
            Result("offline", "network", "-", 0, 1, false, 0L, "No active network")
        )
        val caps = cm.getNetworkCapabilities(net)
        val type = when {
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> "wifi"
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> "cellular"
            else -> "other"
        }
        // Defaults only; manual DC overrides are not covered by these checks.
        val targets = listOf(
            Triple("DC2 direct", "149.154.167.220", 443),
            Triple("media fallback 80", "149.154.167.51", 80),
            Triple("media fallback 443", "149.154.167.51", 443),
            Triple("WS host DNS/TCP", "kws2.web.telegram.org", 443)
        )
        val results = ArrayList<Result>()
        for ((label, host, port) in targets) {
            repeat(2) { i ->
                val start = System.nanoTime()
                var ok = false
                val reason: String
                try {
                    val address = net.getAllByName(host).first()
                    net.socketFactory.createSocket().use { socket ->
                        socket.connect(InetSocketAddress(address, port), 2000)
                        ok = true
                    }
                    reason = "TCP connected"
                } catch (e: Exception) {
                    reason = e.javaClass.simpleName
                }
                val elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start)
                results.add(Result(type, label, host, port, i + 1, ok, elapsed, reason))
                Log.i("TgWsProxy", "DIAG PROBE network=$type target=$host port=$port attempt=" +
                    (i + 1) + " ok=$ok ms=$elapsed reason=$reason")
            }
        }
        results
    }
}
