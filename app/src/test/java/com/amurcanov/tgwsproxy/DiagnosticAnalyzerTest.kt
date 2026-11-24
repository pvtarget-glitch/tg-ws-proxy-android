package com.amurcanov.tgwsproxy

import org.junit.Assert.*
import org.junit.Test

class DiagnosticAnalyzerTest {
    @Test fun parsesNetworkTransitionAndMediaFailures() {
        val log = listOf(
            "ARCH NETWORK event=capabilities network=1 transports=wifi",
            "RC3 DIAL id=1 stage=tcp result=ok",
            "RC3 DIAL id=1 stage=ws result=ok",
            "RC3 TRANSFER media=true down_bytes=1024",
            "ARCH NETWORK event=native_change action=invalidate_idle",
            "ARCH NETWORK event=capabilities network=2 transports=cellular",
            "RC3 DIAL id=2 stage=tcp result=timeout",
            "ARCH POLICY event=direct_failed dc=2 kind=LocalCapacity",
            "ARCH MEDIA_CF event=trial_start dc=2",
            "ARCH MEDIA_CF event=session_end route=cf_proxy down_bytes=20 suspicious=true",
            "ARCH MEDIA_CF event=trial_suppressed dc=2 reason=Cooldown"
        )
        val r = DiagnosticAnalyzer.analyze(log)
        assertEquals(1, r.changes)
        assertEquals("cellular", r.current)
        val a = r.groups.single { it.network == "wifi" }
        val b = r.groups.single { it.network == "cellular" }
        assertEquals(1, a.tcpOk)
        assertEquals(1, a.wsOk)
        assertEquals(1024L, a.mediaBytes)
        assertEquals(1, b.tcpTimeout)
        assertEquals(1, b.localCapacity)
        assertEquals(1, b.cfStarts)
        assertEquals(1, b.cfSuspicious)
        assertEquals(20L, b.cfBytes)
        assertEquals(1, b.cfCooldown)
    }
    @Test fun emptyLogIsSafe() {
        val r = DiagnosticAnalyzer.analyze(emptyList(), truncated = true)
        assertEquals(0, r.total)
        assertTrue(r.truncated)
        assertTrue(r.groups.isEmpty())
    }
}
