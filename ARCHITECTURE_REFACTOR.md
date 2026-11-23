# Architecture refactor roadmap — 1.2.5.x

The architecture branch deliberately changes one control boundary at a time.

## Current split (implemented in 1.2.5.0-rc1)

- `src/connection_manager.rs`: admission of foreground and background direct-connection attempts; owns concurrent dial limits and RAII permits, not transport implementation.
- `src/transport_policy.rs`: pure error-to-reputation policy. Local queue saturation is **not** a network failure.
- `src/ws.rs`: protocol framing, TLS/WebSocket handshake and socket lifecycle; requests an admission permit before dialing a direct endpoint.
- `src/proxy.rs`: MTProto session, pools, fallback and relay. It calls policy helpers, but still owns the existing routing implementation.
- `src/cf_routes.rs`: existing CF connector with independent health and race logic.
- `ProxyService.kt`: Android service lifecycle and connectivity diagnostics.

## Boundaries and invariants

1. No changes to network destinations or fallback routing in this prerelease.
2. Background pool dials can use at most 2 of the 4 global direct dial slots.
3. `Busy` from local admission does not set an endpoint IP or DC cooldown.
4. Errors are logged by class, duration and connection ID; never log keys or payload.
5. Release builds remain behind their own branches, with reproducible Rust tests and APK CI jobs.

## Next independent refactors (NOT part of this prerelease)

- Extract WS pool lifecycle and health scoring from `proxy.rs`.
- Replace cancellation-unsafe frame reads with a persistent frame decoder (requires independent tests).
- Drive connection pool reset by Android network transitions without start/stop races.
- Study the upstream media protocol separately with bounded memory, backpressure and observability.
- Replace insecure TLS server certificate verification with a proper trust policy.

Do not conflate a successful WebSocket handshake with a successfully transmitted media session.
Compare full media downloads, retry count and queue delays rather than only connection success.
