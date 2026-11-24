package com.amurcanov.tgwsproxy

/**
 * Full-fidelity, bounded log archive. UI filtering and UI batching never
 * remove entries from this archive. Every entry is kept verbatim.
 *
 * The cap protects Android memory on long-running sessions. Once a cap is hit,
 * the oldest entries are evicted, and the export explicitly reports the loss.
 */
internal class LogJournal(
    private val maxEntries: Int = 30_000,
    private val maxBytes: Int = 12 * 1024 * 1024
) {
    init {
        require(maxEntries > 0 && maxBytes > 0)
    }

    private val lines = ArrayDeque<String>()
    private var retainedBytes = 0L
    private var retainedCount = 0L
    private var evictedCount = 0L
    private var capturedCount = 0L

    @Synchronized
    fun append(line: String) {
        val bytes = line.toByteArray(Charsets.UTF_8).size.toLong() + 1L
        capturedCount++
        if (bytes > maxBytes) {
            // An anomalously huge single line cannot fit the bounded archive.
            evictedCount++
            return
        }
        lines.addLast(line)
        retainedCount++
        retainedBytes += bytes
        while (lines.size > maxEntries || retainedBytes > maxBytes) {
            val removed = lines.removeFirst()
            retainedBytes -= removed.toByteArray(Charsets.UTF_8).size.toLong() + 1L
            retainedCount--
            evictedCount++
        }
    }

    @Synchronized
    fun clear() {
        lines.clear()
        retainedBytes = 0
        retainedCount = 0
        evictedCount = 0
        capturedCount = 0
    }

    @Synchronized
    fun stats(): LogJournalStats =
        LogJournalStats(
            captured = capturedCount,
            stored = retainedCount,
            bytes = retainedBytes,
            evicted = evictedCount,
            maxEntries = maxEntries,
            maxBytes = maxBytes
        )

    @Synchronized
    fun snapshot(): LogJournalSnapshot =
        LogJournalSnapshot(lines.toList(), stats())
}

internal data class LogJournalStats(
    val captured: Long,
    val stored: Long,
    val bytes: Long,
    val evicted: Long,
    val maxEntries: Int,
    val maxBytes: Int
) {
    val truncated: Boolean get() = evicted > 0L
}

internal data class LogJournalSnapshot(
    val lines: List<String>,
    val stats: LogJournalStats
) {
    fun writeTo(out: Appendable) {
        out.append("TG WS Proxy — complete retained diagnostic log\n")
        out.append("Captured lines: ").append(stats.captured.toString()).append('\n')
        out.append("Saved lines: ").append(stats.stored.toString()).append('\n')
        out.append("Saved UTF-8 bytes (with newline): ").append(stats.bytes.toString()).append('\n')
        out.append("Older/missing lines discarded by retention limit: ").append(stats.evicted.toString()).append('\n')
        out.append("Retention limit: ").append(stats.maxEntries.toString())
            .append(" lines / ").append(stats.maxBytes.toString()).append(" bytes\n")
        out.append("Truncated: ").append(if (stats.truncated) "YES" else "NO").append("\n\n")
        for (line in lines) {
            out.append(line).append('\n')
        }
    }

    fun asText(): String = buildString { writeTo(this) }
}
