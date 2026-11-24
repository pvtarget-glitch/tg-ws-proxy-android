package com.amurcanov.tgwsproxy

/** Passive diagnostics. No traffic changes. */
internal object DiagnosticAnalyzer {
    data class Counts(
        val network: String,
        var tcpOk: Int = 0, var tcpTimeout: Int = 0, var tcpOther: Int = 0,
        var tlsOk: Int = 0, var tlsOther: Int = 0,
        var wsOk: Int = 0, var wsTimeout: Int = 0, var wsOther: Int = 0,
        var mediaSessions: Int = 0, var mediaBytes: Long = 0L,
        var cfStarts: Int = 0, var cfEnds: Int = 0, var cfSuspicious: Int = 0,
        var cfBytes: Long = 0L, var cfCooldown: Int = 0, var cfSaturated: Int = 0,
        var localCapacity: Int = 0
    )
    data class Report(
        val groups: List<Counts>, val total: Int, val truncated: Boolean,
        val current: String, val changes: Int,
        val probes: List<DiagnosticProbe.Result> = emptyList()
    ) {
        fun summary(): String = buildString {
            appendLine("TG WS Proxy 1.2.5.2-diag1")
            appendLine("Lines: $total; truncated: $truncated; latest default: $current; changes: $changes")
            appendLine("Handshake success does not prove full media download.")
            for (c in groups) {
                appendLine()
                appendLine("[" + c.network + "]")
                appendLine("TCP ok=" + c.tcpOk + " timeout=" + c.tcpTimeout + " other=" + c.tcpOther)
                appendLine("TLS ok=" + c.tlsOk + " other=" + c.tlsOther)
                appendLine("WS ok=" + c.wsOk + " timeout=" + c.wsTimeout + " other=" + c.wsOther)
                appendLine("Media sessions=" + c.mediaSessions + " received=" + c.mediaBytes + " bytes")
                appendLine("CF starts=" + c.cfStarts + " ends=" + c.cfEnds + " suspicious=" + c.cfSuspicious + " received=" + c.cfBytes)
                appendLine("CF cooldown=" + c.cfCooldown + " saturated=" + c.cfSaturated + " local capacity=" + c.localCapacity)
            }
            if (probes.isNotEmpty()) {
                appendLine()
                appendLine("[Manual TCP/DNS probes]")
                for (p in probes) {
                    appendLine(p.network + " " + p.label + " " + p.host + ":" + p.port +
                        " try=" + p.attempt + " ok=" + p.ok + " ms=" + p.elapsedMs + " " + p.reason)
                }
            }
        }
    }
    private val mode = Regex("""transports=([a-zA-Z_]+)""")
    private val received = Regex("""down_bytes=(\d+)""")
    fun analyze(lines: List<String>, truncated: Boolean = false,
                probes: List<DiagnosticProbe.Result> = emptyList()): Report {
        val groups = linkedMapOf<String, Counts>()
        var network = "unknown"
        var changes = 0
        for (line in lines) {
            if (line.contains("ARCH NETWORK event=capabilities") && line.contains("transports=")) {
                network = mode.find(line)?.groupValues?.get(1) ?: "unknown"
            }
            if (line.contains("ARCH NETWORK event=native_change action=")) changes++
            val s = groups.getOrPut(network) { Counts(network) }
            when {
                line.contains("RC3 DIAL ") && line.contains("stage=tcp result=ok") -> s.tcpOk++
                line.contains("RC3 DIAL ") && line.contains("stage=tcp result=timeout") -> s.tcpTimeout++
                line.contains("RC3 DIAL ") && line.contains("stage=tcp result=") -> s.tcpOther++
                line.contains("RC3 DIAL ") && line.contains("stage=tls result=ok") -> s.tlsOk++
                line.contains("RC3 DIAL ") && line.contains("stage=tls result=") -> s.tlsOther++
                line.contains("RC3 DIAL ") && line.contains("stage=ws result=ok") -> s.wsOk++
                line.contains("RC3 DIAL ") && line.contains("stage=ws result=timeout") -> s.wsTimeout++
                line.contains("RC3 DIAL ") && line.contains("stage=ws result=") -> s.wsOther++
            }
            if (line.contains("RC3 TRANSFER") && line.contains("media=true")) {
                s.mediaSessions++
                s.mediaBytes += received.find(line)?.groupValues?.get(1)?.toLongOrNull() ?: 0L
            }
            if (line.contains("ARCH MEDIA_CF event=trial_start")) s.cfStarts++
            if (line.contains("ARCH MEDIA_CF event=session_end") && line.contains("route=cf_proxy")) {
                s.cfEnds++
                if (line.contains("suspicious=true")) s.cfSuspicious++
                s.cfBytes += received.find(line)?.groupValues?.get(1)?.toLongOrNull() ?: 0L
            }
            if (line.contains("ARCH MEDIA_CF event=trial_suppressed") && line.contains("reason=Cooldown")) s.cfCooldown++
            if (line.contains("ARCH MEDIA_CF event=trial_suppressed") && line.contains("reason=Saturated")) s.cfSaturated++
            if (line.contains("ARCH POLICY event=direct_failed") && line.contains("kind=LocalCapacity")) s.localCapacity++
        }
        return Report(groups.values.toList(), lines.size, truncated, network, changes, probes)
    }
}
