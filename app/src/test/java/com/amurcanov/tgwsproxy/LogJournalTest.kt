package com.amurcanov.tgwsproxy

import org.junit.Assert.*
import org.junit.Test

class LogJournalTest {

    @Test
    fun noUiFilteringAffectsRawArchiveOrderOrMetrics() {
        val journal = LogJournal(maxEntries = 8, maxBytes = 2048)
        val a = "11-24 14:48:20.988 I/TgWsProxy: DC2 media v145.4KB ↑12.3KB"
        val b = "11-24 14:48:21.141 D/TgWsProxy: ARCH SESSION event=early_upstream_close"
        journal.append(a)
        journal.append(b)
        val snapshot = journal.snapshot()
        assertEquals(listOf(a, b), snapshot.lines)
        assertEquals(2L, snapshot.stats.stored)
        assertFalse(snapshot.stats.truncated)
        assertTrue(snapshot.asText().contains("↑12.3KB"))
        assertTrue(snapshot.asText().contains("Truncated: NO"))
    }

    @Test
    fun evictedCountTracksCountCapAndExportReportsTruncation() {
        val journal = LogJournal(maxEntries = 2, maxBytes = 2048)
        journal.append("first")
        journal.append("second")
        journal.append("third")
        val snap = journal.snapshot()
        assertEquals(listOf("second", "third"), snap.lines)
        assertEquals(3L, snap.stats.captured)
        assertEquals(2L, snap.stats.stored)
        assertEquals(1L, snap.stats.evicted)
        assertTrue(snap.stats.truncated)
        assertTrue(snap.asText().contains("Truncated: YES"))
    }

    @Test
    fun utf8ByteBoundAndOversizedEntryAreReported() {
        val journal = LogJournal(maxEntries = 8, maxBytes = 9)
        journal.append("а") // two UTF-8 bytes plus newline
        journal.append("б")
        journal.append("very long entry")
        assertEquals(2L, journal.stats().stored)
        assertEquals(1L, journal.stats().evicted)
        assertEquals(6L, journal.stats().bytes)
        assertTrue(journal.stats().truncated)
    }

    @Test
    fun previousSnapshotCannotBeChangedByNewEntriesOrClear() {
        val journal = LogJournal(maxEntries = 2, maxBytes = 2048)
        journal.append("alpha")
        val snap = journal.snapshot()
        journal.append("beta")
        journal.clear()
        assertEquals(listOf("alpha"), snap.lines)
        assertEquals(1L, snap.stats.captured)
        assertEquals(0L, journal.stats().stored)
        assertFalse(journal.stats().truncated)
    }
}
