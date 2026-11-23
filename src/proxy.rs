use crate::cfproxy::*;
use crate::config::*;
use crate::crypto::*;
use crate::faketls;
use crate::ws::*;
use crate::{ldebug, linfo, lwarn};
use byteorder::{ByteOrder, LittleEndian};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Fronting flag — proxy/pool.py::_WsPool.try_fronting_first (начинается true)
// ---------------------------------------------------------------------------

static TRY_FRONTING_FIRST: AtomicBool = AtomicBool::new(true);

pub fn ws_pool_fronting_first() -> bool {
    TRY_FRONTING_FIRST.load(Ordering::Relaxed)
}

pub fn set_ws_pool_fronting_first(v: bool) {
    TRY_FRONTING_FIRST.store(v, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Target resolution
// ---------------------------------------------------------------------------

pub fn resolve_configured_target(dc: i32, is_media: bool) -> Option<String> {
    let map = DC_OPT.read();
    if is_media {
        if let Some(t) = map.get(&(-dc)) {
            if !t.is_empty() {
                return Some(t.clone());
            }
        }
    }
    if let Some(t) = map.get(&dc) {
        if !t.is_empty() {
            return Some(t.clone());
        }
    }
    None
}

pub fn resolve_fallback_target(dc: i32, _is_media: bool, is_test: bool) -> String {
    if is_test {
        DC_TEST_IPS
            .get(&dc)
            .map(|s| s.to_string())
            .unwrap_or_default()
    } else {
        DC_DEFAULT_IPS
            .get(&dc)
            .map(|s| s.to_string())
            .unwrap_or_default()
    }
}

pub fn ws_domains(dc: i32, is_media: bool) -> Vec<String> {
    let mut effective_dc = dc;
    if let Some(o) = DC_OVERRIDES.get(&dc) {
        effective_dc = *o;
    }
    if is_media {
        vec![
            format!("kws{}-1.web.telegram.org", effective_dc),
            format!("kws{}.web.telegram.org", effective_dc),
        ]
    } else {
        vec![
            format!("kws{}.web.telegram.org", effective_dc),
            format!("kws{}-1.web.telegram.org", effective_dc),
        ]
    }
}

pub fn ws_path_for(is_test: bool) -> &'static str {
    if is_test {
        WS_PATH_TEST
    } else {
        WS_PATH
    }
}

pub fn media_tag(is_media: bool) -> &'static str {
    if is_media {
        " media"
    } else {
        ""
    }
}

pub fn is_media_int(b: bool) -> i32 {
    if b {
        1
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// WsPool — порт proxy/pool.py::_WsPool
// refilling-backoff (1s..3600s), rotation протухших, fronting-first.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DcSlot {
    pub dc: i32,
    pub is_media: i32,
}

pub struct PoolEntry {
    pub ws: RawWebSocket,
    pub created: f64, // monotonic, как time.monotonic() в оригинале
}

struct SlotState {
    queue: Mutex<VecDeque<PoolEntry>>,
    refilling: AtomicI32,
}

pub struct WsPool {
    slots: Mutex<HashMap<DcSlot, Arc<SlotState>>>,
    rotating: Mutex<HashSet<DcSlot>>,
    refill_failures: Mutex<HashMap<DcSlot, (u32, f64)>>,
    cancel_token: CancellationToken,
}

impl WsPool {
    pub fn new(cancel_token: CancellationToken) -> WsPool {
        WsPool {
            slots: Mutex::new(HashMap::new()),
            rotating: Mutex::new(HashSet::new()),
            refill_failures: Mutex::new(HashMap::new()),
            cancel_token,
        }
    }

    async fn get_slot(&self, slot: DcSlot) -> Arc<SlotState> {
        let mut map = self.slots.lock().await;
        map.entry(slot)
            .or_insert_with(|| {
                Arc::new(SlotState {
                    queue: Mutex::new(VecDeque::with_capacity(16)),
                    refilling: AtomicI32::new(0),
                })
            })
            .clone()
    }

    pub async fn get(
        self: &Arc<Self>,
        dc: i32,
        is_media: bool,
        target_ip: String,
        domains: Vec<String>,
    ) -> Option<RawWebSocket> {
        let slot = DcSlot {
            dc,
            is_media: is_media_int(is_media),
        };
        let state = self.get_slot(slot).await;
        let now = now_monotonic();

        let mut ws: Option<RawWebSocket> = None;
        {
            let mut q = state.queue.lock().await;
            while let Some(entry) = q.pop_front() {
                let age = now - entry.created;
                if age > WS_POOL_REUSE_MAX_AGE || entry.ws.is_closed() {
                    ldebug!("RC3 POOL event=discard dc={} media={} ws_id={} age_ms={} reason={}",
                        dc, is_media, entry.ws.diagnostic_id(), (age.max(0.0) * 1000.0) as u64,
                        if entry.ws.is_closed() { "locally_closed" } else { "max_age" });
                    let e = entry;
                    tokio::spawn(async move {
                        e.ws.close().await;
                    });
                    continue;
                }
                STATS.pool_hits.fetch_add(1, Ordering::Relaxed);
                ldebug!(
                    "RC3 POOL event=checkout ws_id={} DC{}{} (age={:.1}s, left={})",
                    entry.ws.diagnostic_id(),
                    dc,
                    if is_media { "m" } else { "" },
                    age,
                    q.len()
                );
                ws = Some(entry.ws);
                break;
            }
            if ws.is_none() {
                STATS.pool_misses.fetch_add(1, Ordering::Relaxed);
            }
        }

        if ws.is_some() {
            self.report_success(dc, is_media).await;
        }
        self.schedule_refill(slot, target_ip, domains).await;
        ws
    }

    async fn schedule_refill(
        self: &Arc<Self>,
        slot: DcSlot,
        target_ip: String,
        domains: Vec<String>,
    ) {
        // Backoff как в оригинале: не раньше _refill_after.
        {
            let failures = self.refill_failures.lock().await;
            if let Some((_, after)) = failures.get(&slot) {
                if now_monotonic() < *after {
                    return;
                }
            }
        }
        let state = self.get_slot(slot).await;
        if state
            .refilling
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        // pool_size <= 0 — преконнект отключён (как pool_size=0 в оригинале).
        if POOL_SIZE.load(Ordering::Relaxed) <= 0 {
            state.refilling.store(0, Ordering::SeqCst);
            return;
        }
        let pool = self.clone();
        spawn_refill_task(pool, slot, state, target_ip, domains);
    }

    async fn refill(
        self: Arc<Self>,
        slot: DcSlot,
        state: Arc<SlotState>,
        target_ip: String,
        domains: Vec<String>,
    ) {
        let _guard = RefillGuard {
            state: state.clone(),
        };
        let cur_len = state.queue.lock().await.len();
        let pool_sz = POOL_SIZE.load(Ordering::Relaxed).max(0) as usize;
        if cur_len >= pool_sz || pool_sz == 0 {
            return;
        }
        let needed = pool_sz - cur_len;

        let mut handles = Vec::new();
        for _ in 0..needed {
            let target_ip = target_ip.clone();
            let domains = domains.clone();
            let cancel = self.cancel_token.clone();
            handles.push(tokio::spawn(async move {
                tokio::select! {
                    _ = cancel.cancelled() => None,
                    r = connect_one_ws(&target_ip, &domains) => r,
                }
            }));
        }

        let mut connected = 0;
        for h in handles {
            if let Ok(Some(ws)) = h.await {
                let now = now_monotonic();
                let mut q = state.queue.lock().await;
                if q.len() < 16 {
                    ldebug!("RC3 POOL event=insert dc={} media={} ws_id={}",
                        slot.dc, slot.is_media != 0, ws.diagnostic_id());
                    q.push_back(PoolEntry { ws, created: now });
                    connected += 1;
                } else {
                    drop(q);
                    tokio::spawn(async move {
                        ws.close().await;
                    });
                }
            }
        }

        if connected > 0 {
            self.report_success(slot.dc, slot.is_media != 0).await;
            // WS до этого DC реально работает: снимаем блэклист и cooldown,
            // поставленные по одиночному таймауту/редиректу (было: до
            // перезапуска / на час).
            let key = DcKey::new(slot.dc, slot.is_media != 0, false);
            let unblocked = WS_BLACKLIST.write().remove(&key).is_some();
            let uncooled = IP_FAIL_UNTIL.write().remove(&target_ip).is_some();
            DC_FAIL_UNTIL.write().remove(&key);
            if unblocked || uncooled {
                linfo!(
                    "WS pool DC{}{}: WS снова работает, блокировка снята",
                    slot.dc,
                    if slot.is_media != 0 { "m" } else { "" }
                );
            }
            self.schedule_rotation(slot, target_ip, domains).await;
        } else {
            // Экспоненциальный backoff 1s..3600s как в оригинале.
            let mut failures = self.refill_failures.lock().await;
            let count = failures.get(&slot).map(|(c, _)| *c).unwrap_or(0) + 1;
            let shift = (count - 1).min(12);
            let delay = (WS_POOL_REFILL_BACKOFF_INITIAL * (2u64.pow(shift) as f64))
                .min(ws_pool_refill_backoff_max());
            failures.insert(slot, (count, now_monotonic() + delay));
            drop(failures);
            linfo!(
                "WS pool refill failed for DC{}{}, retry in {:.0}s",
                slot.dc,
                if slot.is_media != 0 { "m" } else { "" },
                delay
            );
        }
        ldebug!(
            "WS pool refilled DC{}{}: {} ready",
            slot.dc,
            if slot.is_media != 0 { "m" } else { "" },
            state.queue.lock().await.len()
        );
    }

    /// Сбросить пул слота: соединение из него оказалось закрытым (обычно после
    /// обрыва связи сервер закрывает разом и те, что лежат в пуле). Без сброса
    /// каждое следующее подключение брало ещё одно мёртвое соединение и теряло
    /// на нём до 2 с.
    pub async fn drain(&self, dc: i32, is_media: bool) {
        let slot = DcSlot {
            dc,
            is_media: is_media_int(is_media),
        };
        let state = self.get_slot(slot).await;
        let dead: Vec<_> = state.queue.lock().await.drain(..).collect();
        if !dead.is_empty() {
            ldebug!("RC3 POOL event=drain dc={} media={} remaining_ids={:?}",
                dc, is_media, dead.iter().map(|e| e.ws.diagnostic_id()).collect::<Vec<_>>());
            linfo!(
                "WS pool DC{}{}: соединение из пула оказалось закрытым, сбрасываю ещё {}",
                dc,
                if is_media { "m" } else { "" },
                dead.len()
            );
            tokio::spawn(async move {
                for e in dead {
                    e.ws.close().await;
                }
            });
        }
    }

    pub async fn report_success(&self, dc: i32, is_media: bool) {
        let slot = DcSlot {
            dc,
            is_media: is_media_int(is_media),
        };
        self.refill_failures.lock().await.remove(&slot);
    }

    async fn schedule_rotation(
        self: &Arc<Self>,
        slot: DcSlot,
        target_ip: String,
        domains: Vec<String>,
    ) {
        {
            let mut rotating = self.rotating.lock().await;
            if rotating.contains(&slot) {
                return;
            }
            rotating.insert(slot);
        }
        let pool = self.clone();
        let cancel = self.cancel_token.clone();
        spawn_rotate_task(pool, slot, target_ip, domains, cancel);
    }

    async fn rotate(
        self: Arc<Self>,
        slot: DcSlot,
        target_ip: String,
        domains: Vec<String>,
        cancel: CancellationToken,
    ) {
        loop {
            // Спим до ближайшего протухания, но не реже CHECK_INTERVAL.
            let sleep_dur = {
                let map = self.slots.lock().await;
                match map.get(&slot) {
                    Some(state) => {
                        let q = state.queue.lock().await;
                        if q.is_empty() {
                            None
                        } else {
                            let now = now_monotonic();
                            let min_expires = q
                                .iter()
                                .map(|e| e.created + WS_POOL_REUSE_MAX_AGE)
                                .fold(f64::INFINITY, f64::min);
                            Some((min_expires - now).clamp(0.0, WS_POOL_CHECK_INTERVAL))
                        }
                    }
                    None => None,
                }
            };
            let sleep_dur = match sleep_dur {
                Some(d) => d,
                None => break,
            };
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs_f64(sleep_dur)) => {}
            }

            let now = now_monotonic();
            let expired_count: usize;
            let ready_count: usize;
            {
                let map = self.slots.lock().await;
                let state = match map.get(&slot) {
                    Some(s) => s.clone(),
                    None => break,
                };
                let mut q = state.queue.lock().await;
                let mut ready = VecDeque::with_capacity(q.len());
                let mut expired = Vec::new();
                while let Some(e) = q.pop_front() {
                    if now - e.created >= WS_POOL_REUSE_MAX_AGE || e.ws.is_closed() {
                        expired.push(e.ws);
                    } else {
                        ready.push_back(e);
                    }
                }
                expired_count = expired.len();
                *q = ready;
                ready_count = q.len();
                for ws in expired {
                    tokio::spawn(async move {
                        ws.close().await;
                    });
                }
            }
            if expired_count > 0 {
                ldebug!(
                    "WS pool rotated DC{}{}: {} stale, {} ready",
                    slot.dc,
                    if slot.is_media != 0 { "m" } else { "" },
                    expired_count,
                    ready_count
                );
            }
            let pool_sz = POOL_SIZE.load(Ordering::Relaxed).max(0) as usize;
            if ready_count == 0 {
                break;
            }
            if ready_count < pool_sz {
                self.schedule_refill(slot, target_ip.clone(), domains.clone())
                    .await;
            }
        }
        self.rotating.lock().await.remove(&slot);
    }

    pub async fn warmup(self: &Arc<Self>, dc_opt_map: &HashMap<i32, String>) {
        let mut ndcs = 0;
        for (dc, target_ip) in dc_opt_map {
            if target_ip.is_empty() {
                continue;
            }
            ndcs += 1;
            for is_media in [false, true] {
                let domains = ws_domains(*dc, is_media);
                let slot = DcSlot {
                    dc: *dc,
                    is_media: is_media_int(is_media),
                };
                self.schedule_refill(slot, target_ip.clone(), domains).await;
            }
        }
        linfo!("WS pool warmup started for {} DC(s)", ndcs);
    }

    pub async fn idle_count(&self) -> usize {
        let map = self.slots.lock().await;
        let mut count = 0;
        for s in map.values() {
            count += s.queue.lock().await.len();
        }
        count
    }

    pub async fn close_all(&self) {
        let map = self.slots.lock().await;
        for s in map.values() {
            let mut q = s.queue.lock().await;
            for e in q.drain(..) {
                tokio::spawn(async move {
                    e.ws.close().await;
                });
            }
        }
    }

    pub async fn reset(&self) {
        self.close_all().await;
        self.slots.lock().await.clear();
        self.rotating.lock().await.clear();
        self.refill_failures.lock().await.clear();
        set_ws_pool_fronting_first(true);
    }
}

// RefillGuard снимает флаг refilling при выходе (аналог finally: discard).
struct RefillGuard {
    state: Arc<SlotState>,
}
impl Drop for RefillGuard {
    fn drop(&mut self) {
        self.state.refilling.store(0, Ordering::SeqCst);
    }
}

// Синхронные спавн-хелперы: разрывают цикл типов async-future
// (schedule_refill → refill → schedule_rotation → rotate → schedule_refill),
// о который спотыкается rustc (E0391). Sync-fn не вкладывает future одной
// async-функции в другую — внутри только JoinHandle.
fn spawn_refill_task(
    pool: Arc<WsPool>,
    slot: DcSlot,
    state: Arc<SlotState>,
    target_ip: String,
    domains: Vec<String>,
) {
    tokio::spawn(async move {
        pool.refill(slot, state, target_ip, domains).await;
    });
}

fn spawn_rotate_task(
    pool: Arc<WsPool>,
    slot: DcSlot,
    target_ip: String,
    domains: Vec<String>,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        pool.rotate(slot, target_ip, domains, cancel).await;
    });
}

// ---------------------------------------------------------------------------
// CfWorkerPool — порт proxy/pool.py::_CfWorkerPool
// ---------------------------------------------------------------------------

pub struct CfWorkerEntry {
    pub ws: RawWebSocket,
    pub created: f64,
    pub worker_domain: String,
}

pub struct CfWorkerPool {
    idle: Mutex<HashMap<i32, VecDeque<CfWorkerEntry>>>,
    refilling: Mutex<HashSet<i32>>,
    exhausted_until: Mutex<HashMap<String, f64>>,
    cancel_token: CancellationToken,
}

impl CfWorkerPool {
    pub fn new(cancel_token: CancellationToken) -> CfWorkerPool {
        CfWorkerPool {
            idle: Mutex::new(HashMap::new()),
            refilling: Mutex::new(HashSet::new()),
            exhausted_until: Mutex::new(HashMap::new()),
            cancel_token,
        }
    }

    pub async fn get(
        self: &Arc<Self>,
        dc: i32,
        fallback_dst: String,
        worker_domains: Vec<String>,
    ) -> Option<(RawWebSocket, String)> {
        let now = now_monotonic();
        let entry = {
            let mut map = self.idle.lock().await;
            let bucket = map.entry(dc).or_insert_with(VecDeque::new);
            let mut hit = None;
            while let Some(e) = bucket.pop_front() {
                if now - e.created > CF_WORKER_POOL_MAX_AGE || e.ws.is_closed() {
                    let ws = e.ws;
                    tokio::spawn(async move {
                        ws.close().await;
                    });
                    continue;
                }
                hit = Some(e);
                break;
            }
            hit
        };
        match entry {
            Some(e) => {
                STATS.cf_pool_hits.fetch_add(1, Ordering::Relaxed);
                ldebug!(
                    "CF worker pool hit DC{} via {} (age={:.1}s)",
                    dc,
                    e.worker_domain,
                    now - e.created
                );
                self.schedule_refill(dc, fallback_dst, worker_domains).await;
                Some((e.ws, e.worker_domain))
            }
            None => {
                STATS.cf_pool_misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    // Flowseal upstream parity: a pool hit must schedule a real refill.
    // refill_now() owns the in-flight guard and clears it when the task finishes.
    async fn schedule_refill(self: &Arc<Self>, dc: i32, fallback_dst: String, worker_domains: Vec<String>) {
        self.refill_now(dc, fallback_dst, worker_domains).await;
    }

    pub async fn refill_now(
        self: &Arc<Self>,
        dc: i32,
        fallback_dst: String,
        worker_domains: Vec<String>,
    ) {
        // No destinations means no refill job and no stuck in-flight flag.
        if worker_domains.is_empty() {
            return;
        }
        let should = {
            let mut r = self.refilling.lock().await;
            if r.contains(&dc) {
                false
            } else {
                r.insert(dc);
                true
            }
        };
        if !should {
            return;
        }
        let pool = self.clone();
        let cancel = self.cancel_token.clone();
        tokio::spawn(async move {
            let _cancel = cancel;
            {
                let map = pool.idle.lock().await;
                let cur = map.get(&dc).map(|b| b.len()).unwrap_or(0);
                if cur >= CF_WORKER_PER_DC_LIMIT.min(POOL_SIZE.load(Ordering::Relaxed).max(0) as usize) {
                    pool.refilling.lock().await.remove(&dc);
                    return;
                }
            }
            if let Some((ws, domain)) = pool
                .connect_one(worker_domains.clone(), fallback_dst.clone(), dc)
                .await
            {
                let mut map = pool.idle.lock().await;
                map.entry(dc)
                    .or_insert_with(VecDeque::new)
                    .push_back(CfWorkerEntry {
                        ws,
                        created: now_monotonic(),
                        worker_domain: domain,
                    });
                ldebug!("CF worker pool refilled DC{}: ready", dc);
            }
            pool.refilling.lock().await.remove(&dc);
        });
    }

    async fn connect_one(
        &self,
        worker_domains: Vec<String>,
        fallback_dst: String,
        dc: i32,
    ) -> Option<(RawWebSocket, String)> {
        let query = format!("dst={}&dc={}", fallback_dst, dc);
        let path = format!("/apiws?{}", query);
        let targets: Vec<crate::cf_routes::Target> = self
            .available_domains(worker_domains)
            .await
            .into_iter()
            .map(|d| crate::cf_routes::Target { key: d.clone(), host: d })
            .collect();
        let what = format!("DC{} CF worker pool", dc);
        let flight = format!("worker:{}", path);
        crate::cf_routes::connect(&flight, &targets, &path, crate::cf_routes::GROUP_WORKER, "pool", &what, true)
            .await
            .map(|(ws, target, _)| (ws, target.key))
    }

    pub async fn available_domains(&self, worker_domains: Vec<String>) -> Vec<String> {
        let now = now_unix_f64();
        let mut exhausted = self.exhausted_until.lock().await;
        let mut domains = Vec::new();
        let mut seen = HashSet::new();
        for domain in worker_domains {
            if !seen.insert(domain.clone()) {
                continue;
            }
            if let Some(until) = exhausted.get(&domain) {
                if *until > now {
                    continue;
                }
            }
            exhausted.remove(&domain);
            domains.push(domain);
        }
        drop(exhausted);
        // random.shuffle как в оригинале.
        {
            use rand::seq::SliceRandom;
            let mut rng = rand::thread_rng();
            domains.shuffle(&mut rng);
        }
        domains
    }

    pub async fn report_failure(&self, _worker_domain: &str, _exc: &WsError) {
        // TODO: picks up 429/daily-limit handling — как в оригинале пока no-op.
        return;
    }

    pub async fn warmup(self: &Arc<Self>, dc_opt_map: &HashMap<i32, String>) {
        let worker_domains = CF_WORKER_DOMAINS.read().clone();
        if worker_domains.is_empty() {
            return;
        }
        // CF worker греем только для DC, которых НЕТ в прямых редиректах.
        let fallbacks: Vec<(i32, String)> = DC_DEFAULT_IPS
            .iter()
            .filter(|(dc, _)| !dc_opt_map.contains_key(dc))
            .map(|(dc, ip)| (*dc, ip.to_string()))
            .collect();
        if fallbacks.is_empty() {
            return;
        }
        for (dc, fallback_dst) in &fallbacks {
            self.refill_now(*dc, fallback_dst.clone(), worker_domains.clone())
                .await;
        }
        linfo!("CF worker pool warmup started for {} DC(s)", fallbacks.len());
    }

    pub async fn close_all(&self) {
        let mut map = self.idle.lock().await;
        for bucket in map.values_mut() {
            for e in bucket.drain(..) {
                tokio::spawn(async move {
                    e.ws.close().await;
                });
            }
        }
    }

    pub async fn reset(&self) {
        self.close_all().await;
        self.idle.lock().await.clear();
        self.refilling.lock().await.clear();
        self.exhausted_until.lock().await.clear();
    }
}

// ---------------------------------------------------------------------------
// Shared pools (WS + CF worker) — один Arc на соединение.
// ---------------------------------------------------------------------------

pub struct ProxyPools {
    pub ws: Arc<WsPool>,
    pub cf_worker: Arc<CfWorkerPool>,
}

impl ProxyPools {
    pub fn new(cancel_token: CancellationToken) -> Self {
        ProxyPools {
            ws: Arc::new(WsPool::new(cancel_token.clone())),
            cf_worker: Arc::new(CfWorkerPool::new(cancel_token)),
        }
    }

    pub async fn warmup(&self, dc_opt_map: &HashMap<i32, String>) {
        self.ws.warmup(dc_opt_map).await;
        self.cf_worker.warmup(dc_opt_map).await;
    }

    pub async fn close_all(&self) {
        self.ws.close_all().await;
        self.cf_worker.close_all().await;
    }

    pub async fn reset(&self) {
        self.ws.reset().await;
        self.cf_worker.reset().await;
    }
}

// ---------------------------------------------------------------------------
// HTTP transport detection
// ---------------------------------------------------------------------------

pub fn is_http_transport(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    &data[..4] == b"POST"
        || &data[..3] == b"GET"
        || &data[..4] == b"HEAD"
        || (data.len() >= 7 && &data[..7] == b"OPTIONS")
}

// ---------------------------------------------------------------------------
// Bridge WS — generic core + TcpStream wrapper.
// Сессионная статистика как в bridge_ws_reencrypt оригинала.
// ---------------------------------------------------------------------------

pub async fn bridge_ws<R, W>(
    conn_read: R,
    conn_write: W,
    ws: RawWebSocket,
    label: String,
    dc: i32,
    is_media: bool,
    mut splitter: Option<MsgSplitter>,
    mut clt_dec: TrackedStream,
    mut clt_enc: TrackedStream,
    mut tg_enc: TrackedStream,
    mut tg_dec: TrackedStream,
    cancel_token: CancellationToken,
) where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    let dc_tag = format!("DC{}{}", dc, if is_media { "m" } else { "" });
    let ws = Arc::new(ws);
    let last_activity = Arc::new(Mutex::new(std::time::Instant::now()));
    let cancel = Arc::new(tokio::sync::Notify::new());
    let start = now_monotonic();
    let first_up_ms = Arc::new(AtomicU64::new(0));
    let first_down_ms = Arc::new(AtomicU64::new(0));

    let mut conn_read = conn_read;
    let mut conn_write = conn_write;

    // ping keepalive (мобильное улучшение поверх оригинала).
    let ws_ping = ws.clone();
    let la_ping = last_activity.clone();
    let cancel_ping = cancel.clone();
    let cancel_token_ping = cancel_token.clone();
    // Было: тик раз в 30 с и ping только при простое > 30 с, то есть первый
    // ping уходил примерно на 60-й секунде — когда сервер уже закрывал
    // простаивающее соединение (upstream: ws_close на 60 с). Теперь проверка
    // раз в BRIDGE_PING_CHECK, ping при простое от BRIDGE_PING_IDLE.
    let ping_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(BRIDGE_PING_CHECK);
        interval.tick().await;
        let mut last_ping = tokio::time::Instant::now();
        loop {
            tokio::select! {
                _ = cancel_token_ping.cancelled() => return,
                _ = cancel_ping.notified() => return,
                _ = interval.tick() => {
                    let idle = la_ping.lock().await.elapsed();
                    if idle >= BRIDGE_PING_IDLE && last_ping.elapsed() >= BRIDGE_PING_IDLE {
                        last_ping = tokio::time::Instant::now();
                        if ws_ping.send_ping().await.is_err() {
                            cancel_ping.notify_waiters();
                            return;
                        }
                    }
                }
            }
        }
    });

    // up: client -> ws
    let ws_up = ws.clone();
    let la_up = last_activity.clone();
    let cancel_up = cancel.clone();
    let cancel_token_up = cancel_token.clone();
    let up_bytes = Arc::new(std::sync::atomic::AtomicI64::new(0));
    let up_packets = Arc::new(std::sync::atomic::AtomicI64::new(0));
    let up_bytes_c = up_bytes.clone();
    let up_packets_c = up_packets.clone();
    let first_up_c = first_up_ms.clone();
    let close_reason_up = Arc::new(Mutex::new(String::new()));
    let close_reason_up_c = close_reason_up.clone();
    let up_task = tokio::spawn(async move {
        let mut buf = vec![0u8; WS_BRIDGE_CHUNK_SIZE];
        loop {
            let read_res = tokio::select! {
                _ = cancel_token_up.cancelled() => break,
                _ = cancel_up.notified() => break,
                r = tokio::time::timeout(BRIDGE_READ_TIMEOUT, conn_read.read(&mut buf)) => r,
            };
            let n = match read_res {
                Ok(Ok(0)) => {
                    // EOF: flush splitter tail
                    if let Some(sp) = splitter.as_mut() {
                        let tail = sp.flush();
                        if !tail.is_empty() {
                            let r = if tail.len() > 1 {
                                ws_up.send_batch(&tail).await
                            } else {
                                ws_up.send(&tail[0]).await
                            };
                            if r.is_err() {
                                *close_reason_up_c.lock().await =
                                    "upstream: send_failed".to_string();
                                break;
                            }
                        }
                    }
                    break;
                }
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    *close_reason_up_c.lock().await =
                        format!("client: {}", e.kind());
                    break;
                }
                Err(_) => {
                    *close_reason_up_c.lock().await = "client: timeout".to_string();
                    break;
                }
            };

            first_up_c.compare_exchange(0, ((now_monotonic() - start) * 1000.0).max(1.0) as u64,
                Ordering::Relaxed, Ordering::Relaxed).ok();
            let chunk = &mut buf[..n];
            STATS.bytes_up.fetch_add(n as i64, Ordering::Relaxed);
            up_bytes_c.fetch_add(n as i64, Ordering::Relaxed);
            up_packets_c.fetch_add(1, Ordering::Relaxed);
            *la_up.lock().await = std::time::Instant::now();

            clt_dec.xor(chunk);
            tg_enc.xor(chunk);

            let send_err = {
                if let Some(sp) = splitter.as_mut() {
                    let parts = sp.split(chunk);
                    if parts.len() > 1 {
                        ws_up.send_batch(&parts).await.is_err()
                    } else if parts.len() == 1 {
                        ws_up.send(&parts[0]).await.is_err()
                    } else {
                        false
                    }
                } else {
                    ws_up.send(chunk).await.is_err()
                }
            };
            if send_err {
                *close_reason_up_c.lock().await = "upstream: send_failed".to_string();
                break;
            }
        }
        cancel_up.notify_waiters();
    });

    // down: ws -> client
    let ws_down = ws.clone();
    let la_down = last_activity.clone();
    let cancel_down = cancel.clone();
    let cancel_token_down = cancel_token.clone();
    let down_bytes = Arc::new(std::sync::atomic::AtomicI64::new(0));
    let down_packets = Arc::new(std::sync::atomic::AtomicI64::new(0));
    let down_bytes_c = down_bytes.clone();
    let down_packets_c = down_packets.clone();
    let first_down_c = first_down_ms.clone();
    let close_reason_down = Arc::new(Mutex::new(String::new()));
    let close_reason_down_c = close_reason_down.clone();
    let down_task = tokio::spawn(async move {
        loop {
            let recv_res = tokio::select! {
                _ = cancel_token_down.cancelled() => break,
                _ = cancel_down.notified() => break,
                r = ws_down.recv_with_timeout(BRIDGE_READ_TIMEOUT) => r,
            };
            let mut data = match recv_res {
                Ok(d) => d,
                Err(WsError::Timeout) => {
                    *close_reason_down_c.lock().await =
                        "upstream: timeout".to_string();
                    break;
                }
                Err(e) => {
                    let cur = close_reason_down_c.lock().await.clone();
                    if cur.is_empty() {
                        let class = match &e {
                            WsError::Io(io) => format!("io:{:?}:os={:?}", io.kind(), io.raw_os_error()),
                            WsError::Handshake(h) => format!("http:{}", h.status_code),
                            WsError::Canceled => "canceled".to_string(),
                            WsError::Timeout => "timeout".to_string(),
                            WsError::Other(_) => "other".to_string(),
                        };
                        *close_reason_down_c.lock().await = format!("upstream: {}", class);
                    }
                    break;
                }
            };
            first_down_c.compare_exchange(0, ((now_monotonic() - start) * 1000.0).max(1.0) as u64,
                Ordering::Relaxed, Ordering::Relaxed).ok();
            let n = data.len();
            STATS.bytes_down.fetch_add(n as i64, Ordering::Relaxed);
            down_bytes_c.fetch_add(n as i64, Ordering::Relaxed);
            down_packets_c.fetch_add(1, Ordering::Relaxed);
            *la_down.lock().await = std::time::Instant::now();

            tg_dec.xor(&mut data);
            clt_enc.xor(&mut data);
            if conn_write.write_all(&data).await.is_err() {
                *close_reason_down_c.lock().await = "client: write_failed".to_string();
                break;
            }
        }
        cancel_down.notify_waiters();
    });

    let _ = up_task.await;
    let _ = down_task.await;
    cancel.notify_waiters();
    ping_task.abort();

    let close_reason = {
        let up_r = close_reason_up.lock().await.clone();
        let down_r = close_reason_down.lock().await.clone();
        if !down_r.is_empty() {
            down_r
        } else if !up_r.is_empty() {
            up_r
        } else {
            "normal".to_string()
        }
    };
    let elapsed = now_monotonic() - start;
    linfo!(
        "[{}] {} WS session closed ({}): ^{}{} ({} pkts) v{}{} ({} pkts) in {:.1}s",
        label,
        dc_tag,
        close_reason,
        human_bytes(up_bytes.load(Ordering::Relaxed)),
        "",
        up_packets.load(Ordering::Relaxed),
        human_bytes(down_bytes.load(Ordering::Relaxed)),
        "",
        down_packets.load(Ordering::Relaxed),
        elapsed
    );

    linfo!("RC3 TRANSFER session={} ws_id={} dc={} media={} first_up_ms={} first_down_ms={} up_bytes={} down_bytes={} up_pkts={} down_pkts={} avg_down_Bps={:.1}",
        label, ws.diagnostic_id(), dc, is_media,
        first_up_ms.load(Ordering::Relaxed), first_down_ms.load(Ordering::Relaxed),
        up_bytes.load(Ordering::Relaxed), down_bytes.load(Ordering::Relaxed),
        up_packets.load(Ordering::Relaxed), down_packets.load(Ordering::Relaxed),
        down_bytes.load(Ordering::Relaxed) as f64 / elapsed.max(0.001));
    ws.close().await;
}

/// Совместимость: bridge по TcpStream (разрезаем внутри).
pub async fn bridge_ws_stream(
    conn: TcpStream,
    ws: RawWebSocket,
    label: String,
    dc: i32,
    is_media: bool,
    splitter: Option<MsgSplitter>,
    clt_dec: TrackedStream,
    clt_enc: TrackedStream,
    tg_enc: TrackedStream,
    tg_dec: TrackedStream,
    cancel_token: CancellationToken,
) {
    let (conn_read, conn_write) = tokio::io::split(conn);
    bridge_ws(
        conn_read,
        conn_write,
        ws,
        label,
        dc,
        is_media,
        splitter,
        clt_dec,
        clt_enc,
        tg_enc,
        tg_dec,
        cancel_token,
    )
    .await;
}

// ---------------------------------------------------------------------------
// Bridge TCP — generic core + wrapper.
// ---------------------------------------------------------------------------

pub async fn bridge_tcp<CR, CW>(
    mut c_read: CR,
    mut c_write: CW,
    mut remote: TcpStream,
    clt_dec: TrackedStream,
    clt_enc: TrackedStream,
    tg_enc: TrackedStream,
    tg_dec: TrackedStream,
    cancel_token: CancellationToken,
) where
    CR: AsyncReadExt + Unpin + Send + 'static,
    CW: AsyncWriteExt + Unpin + Send + 'static,
{
    let (mut r_read, mut r_write) = remote.split();

    let clt_dec = Arc::new(Mutex::new(clt_dec));
    let clt_enc = Arc::new(Mutex::new(clt_enc));
    let tg_enc = Arc::new(Mutex::new(tg_enc));
    let tg_dec = Arc::new(Mutex::new(tg_dec));

    let cancel = Arc::new(tokio::sync::Notify::new());

    let cancel_up = cancel.clone();
    let cancel_token_up = cancel_token.clone();
    let clt_dec_up = clt_dec.clone();
    let tg_enc_up = tg_enc.clone();
    let up = async move {
        let mut buf = vec![0u8; 131072];
        loop {
            let n = tokio::select! {
                _ = cancel_token_up.cancelled() => break,
                _ = cancel_up.notified() => break,
                r = tokio::time::timeout(BRIDGE_READ_TIMEOUT, c_read.read(&mut buf)) => match r {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => n,
                    _ => break,
                },
            };
            let chunk = &mut buf[..n];
            STATS.bytes_up.fetch_add(n as i64, Ordering::Relaxed);
            clt_dec_up.lock().await.xor(chunk);
            tg_enc_up.lock().await.xor(chunk);
            if r_write.write_all(chunk).await.is_err() {
                break;
            }
        }
        cancel_up.notify_waiters();
    };

    let cancel_down = cancel.clone();
    let cancel_token_down = cancel_token.clone();
    let tg_dec_down = tg_dec.clone();
    let clt_enc_down = clt_enc.clone();
    let down = async move {
        let mut buf = vec![0u8; 131072];
        loop {
            let n = tokio::select! {
                _ = cancel_token_down.cancelled() => break,
                _ = cancel_down.notified() => break,
                r = tokio::time::timeout(BRIDGE_READ_TIMEOUT, r_read.read(&mut buf)) => match r {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => n,
                    _ => break,
                },
            };
            let chunk = &mut buf[..n];
            STATS.bytes_down.fetch_add(n as i64, Ordering::Relaxed);
            tg_dec_down.lock().await.xor(chunk);
            clt_enc_down.lock().await.xor(chunk);
            if c_write.write_all(chunk).await.is_err() {
                break;
            }
        }
        cancel_down.notify_waiters();
    };

    tokio::join!(up, down);
    let _ = (clt_dec, clt_enc, tg_enc, tg_dec);
}

pub async fn bridge_tcp_stream(
    client: TcpStream,
    remote: TcpStream,
    clt_dec: TrackedStream,
    clt_enc: TrackedStream,
    tg_enc: TrackedStream,
    tg_dec: TrackedStream,
    cancel_token: CancellationToken,
) {
    let (c_read, c_write) = tokio::io::split(client);
    bridge_tcp(
        c_read,
        c_write,
        remote,
        clt_dec,
        clt_enc,
        tg_enc,
        tg_dec,
        cancel_token,
    )
    .await;
}

// ---------------------------------------------------------------------------
// TCP fallback — порт bridge._tcp_fallback
// ---------------------------------------------------------------------------

// Telegram принимает MTProto и на 443, и на 80. Раньше Android ходил только
// на один порт (80 при DISABLE_SECURE), и там, где режут именно его, прямой
// путь пропадал. Теперь пробуем оба лесенкой и запоминаем рабочий для адреса.
static TCP_PORT_PREF: once_cell::sync::Lazy<parking_lot::Mutex<std::collections::HashMap<String, u16>>> =
    once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(std::collections::HashMap::new()));

pub const TCP_FALLBACK_PORTS: [u16; 2] = [443, 80];

#[cfg(not(test))]
const TCP_SECOND_PORT_DELAY: Duration = Duration::from_millis(1000);
#[cfg(test)]
const TCP_SECOND_PORT_DELAY: Duration = Duration::from_millis(100);
#[cfg(not(test))]
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(test)]
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_millis(600);

#[cfg(test)]
pub static TCP_TEST_PORT_MAP: once_cell::sync::Lazy<parking_lot::Mutex<std::collections::HashMap<u16, u16>>> =
    once_cell::sync::Lazy::new(|| parking_lot::Mutex::new(std::collections::HashMap::new()));

fn tcp_real_port(port: u16) -> u16 {
    #[cfg(test)]
    {
        if let Some(p) = TCP_TEST_PORT_MAP.lock().get(&port) {
            return *p;
        }
    }
    port
}

pub fn reset_tcp_port_pref() {
    TCP_PORT_PREF.lock().clear();
}

pub async fn tcp_connect_any_port(dst: &str, preferred: u16, label: &str) -> Option<TcpStream> {
    let first = TCP_PORT_PREF.lock().get(dst).copied().unwrap_or(preferred);
    let mut order: Vec<u16> = vec![first];
    for p in TCP_FALLBACK_PORTS.iter().copied().chain(std::iter::once(preferred)) {
        if !order.contains(&p) {
            order.push(p);
        }
    }

    let mut set: tokio::task::JoinSet<(u16, std::io::Result<TcpStream>)> = tokio::task::JoinSet::new();
    let deadline = tokio::time::Instant::now() + TCP_CONNECT_TIMEOUT + TCP_SECOND_PORT_DELAY;
    let mut pending = order.into_iter();
    let spawn = |set: &mut tokio::task::JoinSet<(u16, std::io::Result<TcpStream>)>, port: u16| {
        let addr = if dst.contains(':') {
            format!("[{}]:{}", dst, tcp_real_port(port))
        } else {
            format!("{}:{}", dst, tcp_real_port(port))
        };
        set.spawn(async move {
            let r = match tokio::time::timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(&addr)).await {
                Ok(r) => r,
                Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout")),
            };
            (port, r)
        });
    };
    let order_first = pending.next();
    if let Some(p) = order_first {
        spawn(&mut set, p);
    }
    let mut next_at = tokio::time::Instant::now() + TCP_SECOND_PORT_DELAY;
    let mut errors: Vec<String> = Vec::new();
    let mut started: Vec<u16> = Vec::new();
    if let Some(p) = order_first {
        started.push(p);
    }

    loop {
        let has_more = pending.len() > 0;
        if set.is_empty() && !has_more {
            break;
        }
        let wake = if has_more { next_at.min(deadline) } else { deadline };
        if set.is_empty() {
            tokio::time::sleep_until(wake).await;
        }
        tokio::select! {
            joined = set.join_next(), if !set.is_empty() => {
                let Some(Ok((port, r))) = joined else { continue };
                match r {
                    Ok(stream) => {
                        let prev = TCP_PORT_PREF.lock().insert(dst.to_string(), port);
                        if port != preferred && prev != Some(port) {
                            linfo!("[{}] TCP fallback: {}:{} отвечает, порт {} — нет", label, dst, port, preferred);
                        }
                        set.abort_all();
                        return Some(stream);
                    }
                    Err(e) => {
                        errors.push(format!("{}: {}", port, if e.kind() == std::io::ErrorKind::TimedOut { "timeout".to_string() } else { e.to_string() }));
                        // отказ — следующий порт сразу
                        next_at = tokio::time::Instant::now();
                    }
                }
            }
            _ = tokio::time::sleep_until(wake) => {}
        }
        if tokio::time::Instant::now() >= next_at {
            if let Some(p) = pending.next() {
                spawn(&mut set, p);
                started.push(p);
                next_at = tokio::time::Instant::now() + TCP_SECOND_PORT_DELAY;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
    }
    set.abort_all();
    for p in &started {
        if !errors.iter().any(|e| e.starts_with(&format!("{}:", p))) {
            errors.push(format!("{}: timeout", p));
        }
    }
    lwarn!("[{}] TCP fallback to {} failed: {}", label, dst, errors.join(", "));
    None
}

pub async fn tcp_fallback<R, W>(
    conn_read: R,
    conn_write: W,
    dst: &str,
    port: u16,
    init: &[u8],
    label: String,
    ctx_streams: (TrackedStream, TrackedStream, TrackedStream, TrackedStream),
    cancel_token: CancellationToken,
) -> bool
where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    let mut remote = match tcp_connect_any_port(dst, port, &label).await {
        Some(r) => r,
        None => return false,
    };
    let _ = remote.set_nodelay(true);

    STATS.connections_tcp_fallback.fetch_add(1, Ordering::Relaxed);
    if remote.write_all(init).await.is_err() {
        return false;
    }
    let (clt_dec, clt_enc, tg_enc, tg_dec) = ctx_streams;
    bridge_tcp(
        conn_read,
        conn_write,
        remote,
        clt_dec,
        clt_enc,
        tg_enc,
        tg_dec,
        cancel_token,
    )
    .await;
    true
}

// ---------------------------------------------------------------------------
// Cfproxy fallback: выбор маршрута в cf_routes::race (лесенка доменов и
// режимов 80/443, память отказов, общий бюджет).
// ---------------------------------------------------------------------------

// Только устанавливает WS-соединение через CF, НЕ трогая conn.
async fn cfproxy_acquire_ws(
    dc: i32,
    is_media: bool,
    ws_path: &str,
    label: &str,
) -> Option<(RawWebSocket, String)> {
    let (enabled, has_domains) = {
        let cfg = CFPROXY.read();
        (CFPROXY_ENABLED.load(Ordering::Relaxed), !cfg.domains.is_empty())
    };
    if !enabled || !has_domains {
        return None;
    }

    let ordered = crate::balancer::BALANCER.read().get_domains_for_dc(dc);
    let targets: Vec<crate::cf_routes::Target> = ordered
        .iter()
        .map(|d| crate::cfproxy::cf_domain_key(d))
        .filter(|d| !d.is_empty())
        .filter(|d| cfproxy_429_cooldown_remaining(d) == Duration::ZERO)
        .map(|d| crate::cf_routes::Target { host: format!("kws{}.{}", dc, d), key: d })
        .collect();
    if targets.is_empty() {
        return None;
    }

    let m_tag = if is_media { " media" } else { "" };
    ldebug!(" CF fallback DC{}{}: {} домен(ов)", dc, m_tag, targets.len());
    let what = format!("DC{}{} CF proxy", dc, m_tag);
    let (ws, target, _secure) =
        crate::cf_routes::connect(&format!("cf:{}:{}", dc, ws_path), &targets, ws_path, crate::cf_routes::GROUP_CF, label, &what, false)
            .await?;
    clear_cfproxy_429_cooldown(&target.key);
    if crate::balancer::BALANCER.write().update_domain_for_dc(dc, &target.key) {
        linfo!(" CF домен для DC{} -> {}", dc, target.key);
    }
    Some((ws, target.key))
}

// ---------------------------------------------------------------------------
// doFallback — порт bridge.do_fallback: cf_worker -> cf -> tcp.
// CF не "съедает" conn при провале: тот же conn уходит в TCP fallback.
// halves передаются дальше только в успешную ветвь: worker-ws и cf-ws
// добываются БЕЗ halves, затем halves уходят в bridge/tcp.
// ---------------------------------------------------------------------------

pub async fn do_fallback<R, W>(
    pools: &ProxyPools,
    conn_read: R,
    conn_write: W,
    relay_init: &[u8],
    label: String,
    dc: i32,
    is_test: bool,
    is_media: bool,
    splitter: Option<MsgSplitter>,
    clt_dec: &TrackedStream,
    clt_enc: &TrackedStream,
    tg_enc: &TrackedStream,
    tg_dec: &TrackedStream,
    cancel_token: CancellationToken,
) -> bool
where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    let m_tag = if is_media { " media" } else { "" };
    let fallback_dst = resolve_fallback_target(dc, is_media, is_test);
    let skip_cf = media_skips_cf(is_media);
    let use_cf = CFPROXY_ENABLED.load(Ordering::Relaxed) && !is_test && !skip_cf;
    let worker_domains = CF_WORKER_DOMAINS.read().clone();
    let ws_path = ws_path_for(is_test);
    let secure_port = if DISABLE_SECURE.load(Ordering::Relaxed) { 80 } else { 443 };
    let use_worker =
        !worker_domains.is_empty() && !fallback_dst.is_empty() && !is_test && !skip_cf;
    if skip_cf
        && !is_test
        && (CFPROXY_ENABLED.load(Ordering::Relaxed) || !worker_domains.is_empty())
    {
        linfo!(
            "[{}] DC{}{} -> CF пропущен (медиа через CF не проходят)",
            label, dc, m_tag
        );
    }

    // Шаг 1: worker-ws (без halves) — порт _cfproxy_worker_fallback.
    if use_worker {
        let pooled = pools
            .cf_worker
            .get(dc, fallback_dst.clone(), worker_domains.clone())
            .await;
        let worker_ws = if let Some((ws, worker_domain)) = pooled {
            linfo!(
                "[{}] DC{}{} -> CF worker pool hit via {} for {}",
                label, dc, m_tag, worker_domain, fallback_dst
            );
            Some(ws)
        } else {
            let query = format!("dst={}&dc={}", fallback_dst, dc);
            let path = format!("/apiws?{}", query);
            let candidates = pools.cf_worker.available_domains(worker_domains.clone()).await;
            linfo!(
                "[{}] DC{}{} -> trying CF worker ({} domain(s)) for {}",
                label, dc, m_tag, candidates.len(), fallback_dst
            );
            let targets: Vec<crate::cf_routes::Target> = candidates
                .into_iter()
                .map(|d| crate::cf_routes::Target { key: d.clone(), host: d })
                .collect();
            let what = format!("DC{}{} CF worker", dc, m_tag);
            crate::cf_routes::connect(
                &format!("worker:{}", path),
                &targets,
                &path,
                crate::cf_routes::GROUP_WORKER,
                &label,
                &what,
                false,
            )
            .await
            .map(|(ws, _, _)| ws)
        };
        if let Some(ws) = worker_ws {
            STATS.connections_cfproxy.fetch_add(1, Ordering::Relaxed);
            if ws.send(relay_init).await.is_ok() {
                bridge_ws(
                    conn_read,
                    conn_write,
                    ws,
                    label,
                    dc,
                    is_media,
                    None, // оригинал: splitter=None для worker
                    clt_dec.clone_state(),
                    clt_enc.clone_state(),
                    tg_enc.clone_state(),
                    tg_dec.clone_state(),
                cancel_token,
                )
                .await;
                return true;
            }
            ws.close().await;
            // send failed — падаем сквозь к CF/TCP на тех же halves.
        }
    }

    // Шаг 2: cf-ws (без halves).
    if use_cf {
        linfo!("[{}] DC{}{} -> trying CF proxy", label, dc, m_tag);
        if let Some((ws, _chosen_domain)) =
            cfproxy_acquire_ws(dc, is_media, ws_path, &label).await
        {
            STATS.connections_cfproxy.fetch_add(1, Ordering::Relaxed);
            linfo!(" DC{}{} подключен через CF", dc, m_tag);

            if ws.send(relay_init).await.is_ok() {
                bridge_ws(
                    conn_read,
                    conn_write,
                    ws,
                    label,
                    dc,
                    is_media,
                    splitter,
                    clt_dec.clone_state(),
                    clt_enc.clone_state(),
                    tg_enc.clone_state(),
                    tg_dec.clone_state(),
                    cancel_token,
                )
                .await;
                return true;
            }
            ws.close().await;
            // CF умер сразу после хендшейка — пробуем TCP на том же conn.
        }
        // CF не дал ws — halves НЕ тронуты, идём в TCP fallback ниже.
    }

    // Шаг 3: tcp.
    if !fallback_dst.is_empty() {
        linfo!(
            "[{}] DC{}{} -> TCP fallback to {}:{}",
            label, dc, m_tag, fallback_dst, secure_port
        );
        return tcp_fallback(
            conn_read,
            conn_write,
            &fallback_dst,
            secure_port,
            relay_init,
            label,
            (
                clt_dec.clone_state(),
                clt_enc.clone_state(),
                tg_enc.clone_state(),
                tg_dec.clone_state(),
            ),
            cancel_token,
        )
        .await;
    }

    false
}

// ---------------------------------------------------------------------------
// Client serving — порт tg_ws_proxy._handle_client (dd + ee/FakeTLS).
// ---------------------------------------------------------------------------

async fn read_proxy_protocol_line(conn: &mut TcpStream) -> Option<String> {
    let mut line = Vec::with_capacity(108);
    let mut byte = [0u8; 1];
    let res = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let n = conn.read(&mut byte).await.map_err(|_| ())?;
            if n == 0 {
                return Err(());
            }
            line.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
            if line.len() > 108 {
                break;
            }
        }
        Ok::<(), ()>(())
    })
    .await;
    match res {
        Ok(Ok(())) => Some(String::from_utf8_lossy(&line).to_string()),
        _ => None,
    }
}

pub async fn handle_client(
    pools: Arc<ProxyPools>,
    mut conn: TcpStream,
    cancel_token: CancellationToken,
) {
    STATS.connections_total.fetch_add(1, Ordering::Relaxed);
    STATS.connections_active.fetch_add(1, Ordering::Relaxed);
    let sid = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    struct ActiveGuard { sid: u64 }
    impl Drop for ActiveGuard {
        fn drop(&mut self) {
            ldebug!("RC3 SESSION id={} event=finished", self.sid);
            if STATS.connections_active.load(Ordering::Relaxed) > 0 {
                STATS.connections_active.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
    let _guard = ActiveGuard { sid };

    let peer = conn
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    let mut label = format!("s{} {}", sid, peer);
    ldebug!("RC3 SESSION id={} event=accepted", sid);

    let _ = conn.set_nodelay(true);

    let current_secret = PROXY_SECRET.read().clone();
    let secret_bytes = hex::decode(&current_secret).unwrap_or_default();

    // PROXY protocol (proxy_config.proxy_protocol в оригинале).
    if PROXY_PROTOCOL.load(Ordering::Relaxed) {
        match read_proxy_protocol_line(&mut conn).await {
            Some(line) => {
                let text = line.trim().to_string();
                if text.starts_with("PROXY ") {
                    let parts: Vec<&str> = text.split_whitespace().collect();
                    if parts.len() >= 6 {
                        label = format!("s{} {}:{}", sid, parts[2], parts[4]);
                    }
                    ldebug!("[{}] PROXY protocol: {}", label, text);
                } else {
                    ldebug!("[{}] expected PROXY header, got: {:?}", label, &text[..text.len().min(60)]);
                }
            }
            None => {
                ldebug!("[{}] disconnected during PROXY header", label);
                return;
            }
        }
    }

    // FakeTLS (ee-secret): первый байт решает всё — как _read_client_init.
    let masking = FAKE_TLS_DOMAIN.read().clone();
    if !masking.is_empty() {
        let mut first = [0u8; 1];
        match tokio::time::timeout(Duration::from_secs(10), conn.read_exact(&mut first)).await
        {
            Ok(Ok(_)) => {}
            _ => {
                ldebug!("[{}] client disconnected before handshake", label);
                return;
            }
        }
        if first[0] == faketls::TLS_RECORD_HANDSHAKE {
            match faketls::server_handshake(conn, first[0], &secret_bytes, &masking, &label).await
            {
                Some(plain) => {
                    serve_core(
                        &pools,
                        plain.read,
                        plain.write,
                        label,
                        secret_bytes,
                        cancel_token,
                    )
                    .await;
                }
                None => {}
            }
            return;
        } else {
            ldebug!("[{}] non-TLS byte 0x{:02X} -> HTTP redirect", label, first[0]);
            let redirect = format!(
                "HTTP/1.1 301 Moved Permanently\r\nLocation: https://{}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                masking
            );
            let _ = conn.write_all(redirect.as_bytes()).await;
            return;
        }
    }

    let (conn_read, conn_write) = tokio::io::split(conn);
    serve_core(
        &pools,
        conn_read,
        conn_write,
        label,
        secret_bytes,
        cancel_token,
    )
    .await;
}

/// Ядро обслуживания соединения: 64-байтный handshake → маршрут → bridge.
/// Generic над транспортом (TcpStream-halves или FakeTLS-duplex-halves).
async fn serve_core<R, W>(
    pools: &ProxyPools,
    mut conn_read: R,
    mut conn_write: W,
    label: String,
    secret_bytes: Vec<u8>,
    cancel_token: CancellationToken,
) where
    R: AsyncReadExt + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    // 64-байтный handshake
    let mut handshake = [0u8; 64];
    match tokio::time::timeout(Duration::from_secs(10), conn_read.read_exact(&mut handshake)).await
    {
        Ok(Ok(_)) => {}
        _ => {
            ldebug!("[{}] client disconnected before handshake", label);
            return;
        }
    }

    if is_http_transport(&handshake) {
        STATS.connections_http_reject.fetch_add(1, Ordering::Relaxed);
        let _ = conn_write
            .write_all(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n")
            .await;
        let _ = conn_write.shutdown().await;
        return;
    }

    // _try_handshake: key = SHA256(prekey + secret).
    let clt_dec_prekey = &handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN];
    let clt_dec_iv = &handshake[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];
    let mut hash_dec = Sha256::new();
    hash_dec.update(clt_dec_prekey);
    hash_dec.update(&secret_bytes);
    let mut clt_decryptor = new_aes_ctr(&hash_dec.finalize(), clt_dec_iv);

    let mut decrypted = handshake;
    clt_decryptor.xor(&mut decrypted);

    let proto_tag = &decrypted[PROTO_TAG_POS..PROTO_TAG_POS + 4];
    let proto = LittleEndian::read_u32(proto_tag);
    if !valid_proto(proto) {
        STATS.connections_bad.fetch_add(1, Ordering::Relaxed);
        note_bad_handshake(&label);
        // Клиент с чужим секретом переподключается без паузы (сотни раз в
        // секунду) и забивает лог и процессор. Держим отказ 2 с — это
        // замедляет его цикл в десятки раз и ничего не стоит.
        tokio::time::sleep(Duration::from_secs(2)).await;
        return;
    }

    let dc_raw = LittleEndian::read_u16(&decrypted[DC_IDX_POS..DC_IDX_POS + 2]) as i16;
    let mut dc = dc_raw as i32;
    if dc < 0 {
        dc = -dc;
    }
    let is_media = dc_raw < 0;

    // Test DC: proxy_config.force_test_dc или dc >= 10000.
    let mut is_test_dc = FORCE_TEST_DC.load(Ordering::Relaxed) || dc >= 10000;
    if dc >= 10000 {
        linfo!("[{}] test DC{} -> DC{}", label, dc, dc - 10000);
        dc -= 10000;
    }
    // force_test_dc тянет весь трафик на тестовые IP/путь.
    if FORCE_TEST_DC.load(Ordering::Relaxed) {
        is_test_dc = true;
    }
    let m_tag = if is_media { " media" } else { "" };

    let proto_int = proto; // u32 tag; MsgSplitter маппит через proto_tag_to_type
    let dc_idx = if is_media { -dc } else { dc };

    ldebug!(
        "[{}] handshake ok: DC{}{} proto=0x{:08X}{}",
        label,
        dc,
        m_tag,
        proto_int,
        if is_test_dc { " test" } else { "" }
    );

    // relayInit генерация (1-в-1 c Go + RESERVED из utils.py).
    let mut relay_init = [0u8; 64];
    loop {
        rand::thread_rng().fill_bytes(&mut relay_init);
        if relay_init[0] == RESERVED_FIRST_BYTE {
            continue;
        }
        if is_reserved_start(&relay_init[..4]) {
            continue;
        }
        if relay_init[4] == 0 && relay_init[5] == 0 && relay_init[6] == 0 && relay_init[7] == 0 {
            continue;
        }
        break;
    }

    let mut tg_dec_prekey_and_iv = [0u8; 48];
    for i in 0..48 {
        tg_dec_prekey_and_iv[i] = relay_init[8 + 47 - i];
    }

    let mut tg_encryptor = new_aes_ctr(&relay_init[8..40], &relay_init[40..56]);
    let tg_decryptor = new_aes_ctr(&tg_dec_prekey_and_iv[..32], &tg_dec_prekey_and_iv[32..]);

    let mut dc_bytes = [0u8; 2];
    LittleEndian::write_u16(&mut dc_bytes, dc_idx as u16);

    let mut tail_plain = [0u8; 8];
    tail_plain[0..4].copy_from_slice(proto_tag);
    tail_plain[4..6].copy_from_slice(&dc_bytes);
    rand::thread_rng().fill_bytes(&mut tail_plain[6..8]);

    let mut encrypted_full = relay_init;
    tg_encryptor.xor(&mut encrypted_full);

    let mut keystream_tail = [0u8; 8];
    for i in 0..8 {
        keystream_tail[i] = encrypted_full[56 + i] ^ relay_init[56 + i];
        relay_init[56 + i] = tail_plain[i] ^ keystream_tail[i];
    }

    // clt_encryptor: prekey/iv = reverse(client_dec_prekey_iv), key=SHA256+secret.
    let mut clt_enc_prekey_and_iv = [0u8; 48];
    for i in 0..48 {
        clt_enc_prekey_and_iv[i] = handshake[8 + 47 - i];
    }
    let mut hash_enc = Sha256::new();
    hash_enc.update(&clt_enc_prekey_and_iv[..32]);
    hash_enc.update(&secret_bytes);
    let clt_encryptor = new_aes_ctr(&hash_enc.finalize(), &clt_enc_prekey_and_iv[32..]);

    let dc_key = DcKey::new(dc, is_media, is_test_dc);
    let now = now_monotonic();
    let ws_path = ws_path_for(is_test_dc);

    let target_opt = resolve_configured_target(dc, is_media);
    let dc_configured = target_opt.is_some();
    let target = target_opt.unwrap_or_default();

    let blacklisted = WS_BLACKLIST.read().get(&dc_key).copied().unwrap_or(false);
    let ip_cooldown_active = if target.is_empty() {
        false
    } else {
        IP_FAIL_UNTIL.read().get(&target).map(|until| now < *until).unwrap_or(false)
    };
    let is_any_cf_fallback =
        CFPROXY_ENABLED.load(Ordering::Relaxed) || !CF_WORKER_DOMAINS.read().is_empty();
    // Медиа через CF не ходят — значит, и уводить их с прямого пути из-за
    // чёрного списка / cooldown некуда: пробуем прямой путь всегда.
    let media_direct_only = media_skips_cf(is_media) && is_any_cf_fallback;

    // Fallback если DC нет в конфиге, WS в чёрном списке или IP на cooldown —
    // порт ветки из _handle_client оригинала.
    let mut pooled_ws: Option<RawWebSocket> = None;
    let mut use_pooled_direct = false;
    if !dc_configured
        || (blacklisted && !media_direct_only)
        || (ip_cooldown_active && is_any_cf_fallback && !media_direct_only)
    {
        if !dc_configured {
            linfo!("[{}] DC{} not in config -> fallback", label, dc);
        } else {
            // Шанс пулу: и при таймауте, и при чёрном списке. Раньше при
            // blacklisted пул не спрашивали вовсе, и DC уходил в фолбэк, хотя
            // в пуле лежали готовые рабочие WS (WS pool refilled DC2: 4 ready).
            if !is_test_dc {
                let domains = ws_domains(dc, is_media);
                pooled_ws = pools
                    .ws
                    .get(dc, is_media, target.clone(), domains)
                    .await;
            }
            let why = if blacklisted { "blacklisted" } else { "timed out" };
            if pooled_ws.is_none() {
                linfo!(
                    "[{}] DC{}{} WS {} ({}) -> fallback",
                    label, dc, m_tag, why, target
                );
            } else {
                linfo!(
                    "[{}] DC{}{} WS {} ({}), but pool hit -> using WS",
                    label, dc, m_tag, why, target
                );
                use_pooled_direct = true;
            }
        }

        if !use_pooled_direct {
            let splitter = MsgSplitter::new(&relay_init, proto_int);
            let ok = do_fallback(
                pools,
                conn_read,
                conn_write,
                &relay_init,
                label.clone(),
                dc,
                is_test_dc,
                is_media,
                splitter,
                &clt_decryptor,
                &clt_encryptor,
                &tg_encryptor,
                &tg_decryptor,
                cancel_token,
            )
            .await;
            if !ok {
                lwarn!("[{}] DC{}{} no fallback available", label, dc, m_tag);
            }
            return;
        }
    }

    let fail_until = DC_FAIL_UNTIL.read().get(&dc_key).copied().unwrap_or(0.0);
    let ws_timeout = if now < fail_until {
        WS_FAIL_TIMEOUT
    } else {
        WS_DIRECT_TIMEOUT
    };

    let domains = ws_domains(dc, is_media);
    // pooled_ws уже может держать WS из cooldown-ветки.
    let mut ws_opt = pooled_ws;
    let mut ws_failed_redirect = false;
    let mut ws_timed_out = false;
    let mut all_redirects = true;

    if ws_opt.is_none() && !is_test_dc {
        ws_opt = pools
            .ws
            .get(dc, is_media, target.clone(), domains.clone())
            .await;
        if ws_opt.is_some() {
            linfo!("[{}] DC{}{} -> pool hit via {}", label, dc, m_tag, target);
        }
    }

    if ws_opt.is_none() {
        for domain in &domains {
            let url = format!("wss://{}{} via {}", domain, ws_path, target);
            linfo!("[{}] DC{}{} -> {}", label, dc, m_tag, url);
            match ws_connect_full_opts(&target, domain, ws_path, ws_timeout, None, None).await {
                Ok(ws) => {
                    all_redirects = false;
                    ws_opt = Some(ws);
                    break;
                }
                Err(WsError::Handshake(h)) if h.is_redirect() => {
                    STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                    ws_failed_redirect = true;
                    lwarn!(
                        "[{}] DC{}{} got {} from {} -> {}",
                        label,
                        dc,
                        m_tag,
                        h.status_code,
                        domain,
                        if h.location.is_empty() { "?" } else { &h.location }
                    );
                    continue;
                }
                Err(WsError::Handshake(h)) => {
                    STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                    all_redirects = false;
                    lwarn!(
                        "[{}] DC{}{} WS handshake: {}",
                        label, dc, m_tag, h.status_line
                    );
                    continue;
                }
                Err(WsError::Timeout) => {
                    STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                    ws_timed_out = true;
                    lwarn!(
                        "[{}] DC{}{} WS connect timed out via {}",
                        label, dc, m_tag, domain
                    );
                    break;
                }
                Err(exc) => {
                    STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                    all_redirects = false;
                    lwarn!(
                        "[{}] DC{}{} WS connect failed: {}",
                        label, dc, m_tag, exc.compact()
                    );
                    continue;
                }
            }
        }
    } else {
        all_redirects = false;
    }

    // WS failed -> fallback (порт оригинала 1-в-1).
    if ws_opt.is_none() {
        if ws_timed_out && !target.is_empty() {
            IP_FAIL_UNTIL
                .write()
                .insert(target.clone(), now + ip_fail_cooldown());
            linfo!(
                "[{}] DC{}{} WS connect to {} timed out, cooldown for {}s",
                label, dc, m_tag, target, ip_fail_cooldown() as i64
            );
        }

        if ws_failed_redirect && all_redirects {
            WS_BLACKLIST.write().insert(dc_key, true);
            lwarn!("[{}] DC{}{} blacklisted for WS (all 302)", label, dc, m_tag);
        } else if ws_failed_redirect {
            DC_FAIL_UNTIL.write().insert(dc_key, now + DC_FAIL_COOLDOWN);
        } else {
            DC_FAIL_UNTIL.write().insert(dc_key, now + DC_FAIL_COOLDOWN);
            linfo!(
                "[{}] DC{}{} WS failed for {}s",
                label, dc, m_tag, DC_FAIL_COOLDOWN as i64
            );
        }

        let splitter_fb = MsgSplitter::new(&relay_init, proto_int);
        let ok = do_fallback(
            pools,
            conn_read,
            conn_write,
            &relay_init,
            label.clone(),
            dc,
            is_test_dc,
            is_media,
            splitter_fb,
            &clt_decryptor,
            &clt_encryptor,
            &tg_encryptor,
            &tg_decryptor,
            cancel_token,
        )
        .await;
        if ok {
            linfo!("[{}] DC{}{} fallback closed", label, dc, m_tag);
        }
        return;
    }

    if !target.is_empty() {
        IP_FAIL_UNTIL.write().remove(&target);
    }
    pools.ws.report_success(dc, is_media).await;
    STATS.connections_ws.fetch_add(1, Ordering::Relaxed);

    let splitter = MsgSplitter::new(&relay_init, proto_int);
    if splitter.is_some() {
        ldebug!(
            "[{}] MsgSplitter activated for proto 0x{:08X}",
            label, proto_int
        );
    }

    // send direct init (с retry на свежий WS как мобильное улучшение).
    let mut ws = ws_opt.take().unwrap();
    let mut send_ok = ws.send(&relay_init).await.is_ok();
    if send_ok {
        ldebug!(" direct relayInit sent DC{}{}", dc, m_tag);
    } else {
        lwarn!(" direct relayInit write fail DC{}{}: closed", dc, m_tag);
        ws.close().await;
        pools.ws.drain(dc, is_media).await;

        DC_FAIL_UNTIL.write().insert(dc_key, now + DC_FAIL_COOLDOWN);

        lwarn!(" direct retry fresh ws DC{}{}", dc, m_tag);
        let (retry_ws, retry_failed_redirect, retry_all_redirects) =
            connect_direct_ws(&target, &domains, ws_timeout, ws_path).await;
        match retry_ws {
            None => {
                if retry_failed_redirect && retry_all_redirects {
                    WS_BLACKLIST.write().insert(dc_key, true);
                    lwarn!(" DC{}{} заблокирован (302)", dc, m_tag);
                }
                lwarn!(" direct fallback DC{}{}", dc, m_tag);
                let splitter_fb = MsgSplitter::new(&relay_init, proto_int);
                do_fallback(
                    pools,
                    conn_read,
                    conn_write,
                    &relay_init,
                    label,
                    dc,
                    is_test_dc,
                    is_media,
                    splitter_fb,
                    &clt_decryptor,
                    &clt_encryptor,
                    &tg_encryptor,
                    &tg_decryptor,
                    cancel_token,
                )
                .await;
                return;
            }
            Some(rws) => {
                if rws.send(&relay_init).await.is_err() {
                    lwarn!(" direct relayInit write fail DC{}{}: closed", dc, m_tag);
                    rws.close().await;
                    lwarn!(" direct fallback DC{}{}", dc, m_tag);
                    let splitter_fb = MsgSplitter::new(&relay_init, proto_int);
                    do_fallback(
                        pools,
                        conn_read,
                        conn_write,
                        &relay_init,
                        label,
                        dc,
                        is_test_dc,
                        is_media,
                        splitter_fb,
                        &clt_decryptor,
                        &clt_encryptor,
                        &tg_encryptor,
                        &tg_decryptor,
                        cancel_token,
                    )
                    .await;
                    return;
                }
                ws = rws;
                send_ok = true;
            }
        }
    }
    let _ = send_ok;

    DC_FAIL_UNTIL.write().remove(&dc_key);
    bridge_ws(
        conn_read,
        conn_write,
        ws,
        label,
        dc,
        is_media,
        splitter,
        clt_decryptor,
        clt_encryptor,
        tg_encryptor,
        tg_decryptor,
        cancel_token,
    )
    .await;
}

// connectDirectWS — прямой перебор доменов (тихий, для retry-пути).
pub async fn connect_direct_ws(
    target: &str,
    domains: &[String],
    timeout: f64,
    ws_path: &str,
) -> (Option<RawWebSocket>, bool, bool) {
    if domains.is_empty() {
        return (None, false, false);
    }
    let mut ws_failed_redirect = false;
    let mut all_redirects = true;

    for dom in domains {
        match ws_connect_full_opts(target, dom, ws_path, timeout, None, None).await {
            Ok(ws) => return (Some(ws), ws_failed_redirect, false),
            Err(WsError::Handshake(h)) => {
                STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                if h.is_redirect() {
                    ws_failed_redirect = true;
                } else {
                    all_redirects = false;
                }
            }
            Err(WsError::Timeout) => {
                // Как в оригинале: таймаут прерывает перебор, all_redirects не трогаем.
                STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                break;
            }
            Err(_) => {
                STATS.ws_errors.fetch_add(1, Ordering::Relaxed);
                all_redirects = false;
            }
        }
    }
    (None, ws_failed_redirect, all_redirects)
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

pub async fn run_proxy(
    pools: Arc<ProxyPools>,
    host: String,
    port: u16,
    dc_opt_map: HashMap<i32, String>,
    cancel_root: CancellationToken,
    listener: TcpListener,
) -> std::io::Result<()> {
    let (dc_opt_map, auto_direct) =
        auto_dc_defaults(dc_opt_map, CFPROXY_ENABLED.load(Ordering::Relaxed));
    AUTO_DIRECT_ACTIVE.store(auto_direct, Ordering::Relaxed);
    {
        let mut m = DC_OPT.write();
        *m = dc_opt_map.clone();
    }

    start_cfproxy_refresh();

    {
        let p = pools.clone();
        let map = dc_opt_map.clone();
        tokio::spawn(async move {
            p.warmup(&map).await;
        });
    }

    linfo!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    linfo!("  TG WS Proxy запущен");
    linfo!("  Адрес: {}:{}", host, port);
    linfo!("  Target DC IPs:");
    let mut dcs: Vec<i32> = dc_opt_map.keys().copied().collect();
    dcs.sort();
    for dc in dcs {
        if let Some(ip) = dc_opt_map.get(&dc) {
            linfo!("    DC{}: {}", dc, ip);
        }
    }
    if CFPROXY_ENABLED.load(Ordering::Relaxed) {
        linfo!("  CF proxy:      enabled");
    }
    if auto_direct {
        linfo!("  Авто-режим:    сначала прямой путь DC2/DC4, при отказе — CF");
    }
    if !CF_WORKER_DOMAINS.read().is_empty() {
        linfo!(
            "  CF worker:     enabled ({})",
            CF_WORKER_DOMAINS.read().join(", ")
        );
    }
    linfo!(
        "  CF режим:      {}{}",
        if DISABLE_SECURE.load(Ordering::Relaxed) { "порт 80" } else { "TLS 443" },
        if CF_AUTO_MODE.load(Ordering::Relaxed) { ", при отказе пробуется второй порт" } else { "" }
    );
    if CF_DPI_SPLIT.load(Ordering::Relaxed) {
        linfo!("  CF DPI split:  enabled");
    }
    if !FAKE_TLS_DOMAIN.read().is_empty() {
        linfo!("  Fake TLS:      {}", FAKE_TLS_DOMAIN.read().clone());
    }

    let cancel_stats = cancel_root.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await;
        loop {
            tokio::select! {
                _ = cancel_stats.cancelled() => return,
                _ = interval.tick() => {
                    linfo!(" {}", STATS.summary_ru());
                }
            }
        }
    });

    loop {
        tokio::select! {
            _ = cancel_root.cancelled() => {
                break;
            }
            accept = listener.accept() => {
                match accept {
                    Ok((conn, _)) => {
                        let p = pools.clone();
                        let cancel = cancel_root.child_token();
                        tokio::spawn(async move {
                            handle_client(p, conn, cancel).await;
                        });
                    }
                    Err(_) => {
                        continue;
                    }
                }
            }
        }
    }

    drop(listener);
    cancel_root.cancel();
    tokio::time::sleep(Duration::from_millis(100)).await;
    pools.close_all().await;
    Ok(())
}

pub fn parse_cidr_pool(cidrs_str: &str) -> HashMap<i32, String> {
    let mut result = HashMap::new();
    if cidrs_str.trim().is_empty() {
        return result;
    }
    for pair in cidrs_str.split(',') {
        let parts: Vec<&str> = pair.split(':').collect();
        if parts.len() == 2 {
            let dc_raw = parts[0].trim();
            let ip_raw = parts[1].trim();
            if let Ok(dc) = dc_raw.parse::<i32>() {
                if !ip_raw.is_empty() {
                    if let Ok(ip) = ip_raw.parse::<std::net::IpAddr>() {
                        result.insert(dc, ip.to_string());
                    }
                }
            }
        }
    }
    result
}

#[cfg(test)]
mod tcp_port_tests {
    use super::*;
    use tokio::net::TcpListener;

    static SERIAL: once_cell::sync::Lazy<tokio::sync::Mutex<()>> =
        once_cell::sync::Lazy::new(|| tokio::sync::Mutex::new(()));

    async fn listener() -> (TcpListener, u16) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        (l, p)
    }

    async fn closed_port() -> u16 {
        let (l, p) = listener().await;
        drop(l);
        p
    }

    fn map(p443: u16, p80: u16) {
        let mut m = TCP_TEST_PORT_MAP.lock();
        m.clear();
        m.insert(443, p443);
        m.insert(80, p80);
        reset_tcp_port_pref();
    }

    #[tokio::test]
    async fn closed_443_moves_to_80_immediately_and_remembers_it() {
        let _g = SERIAL.lock().await;
        let (l80, p80) = listener().await;
        map(closed_port().await, p80);
        let t0 = tokio::time::Instant::now();
        let s = tcp_connect_any_port("127.0.0.1", 443, "t").await.expect("порт 80 должен ответить");
        assert_eq!(s.peer_addr().unwrap().port(), p80);
        assert!(t0.elapsed() < TCP_SECOND_PORT_DELAY, "{:?}", t0.elapsed());
        assert_eq!(TCP_PORT_PREF.lock().get("127.0.0.1").copied(), Some(80));
        drop(l80);
    }

    #[tokio::test]
    async fn open_443_is_used_and_80_is_not_touched() {
        let _g = SERIAL.lock().await;
        let (l443, p443) = listener().await;
        let (l80, p80) = listener().await;
        map(p443, p80);
        let s = tcp_connect_any_port("127.0.0.1", 443, "t").await.unwrap();
        assert_eq!(s.peer_addr().unwrap().port(), p443);
        let touched = tokio::time::timeout(Duration::from_millis(250), l80.accept()).await;
        assert!(touched.is_err(), "к порту 80 не должны были подключаться");
        drop(l443);
    }

    #[tokio::test]
    async fn remembered_port_goes_first() {
        let _g = SERIAL.lock().await;
        let (l443, p443) = listener().await;
        let (_l80, p80) = listener().await;
        map(p443, p80);
        TCP_PORT_PREF.lock().insert("127.0.0.1".into(), 80);
        let s = tcp_connect_any_port("127.0.0.1", 443, "t").await.unwrap();
        assert_eq!(s.peer_addr().unwrap().port(), p80);
        let touched = tokio::time::timeout(Duration::from_millis(250), l443.accept()).await;
        assert!(touched.is_err(), "к 443 не должны были подключаться");
    }

    #[tokio::test]
    async fn both_closed_fails_fast() {
        let _g = SERIAL.lock().await;
        map(closed_port().await, closed_port().await);
        let t0 = tokio::time::Instant::now();
        assert!(tcp_connect_any_port("127.0.0.1", 80, "t").await.is_none());
        assert!(t0.elapsed() < TCP_SECOND_PORT_DELAY, "{:?}", t0.elapsed());
    }
}

// ---------------------------------------------------------------------------
// Отказы из-за неверного секрета: первая строка сразу, дальше сводка раз в 10 с.
// ---------------------------------------------------------------------------

static BAD_HS_LOG: once_cell::sync::Lazy<parking_lot::Mutex<(Option<std::time::Instant>, u64)>> =
    once_cell::sync::Lazy::new(|| parking_lot::Mutex::new((None, 0)));

fn note_bad_handshake(label: &str) {
    let now = std::time::Instant::now();
    let mut g = BAD_HS_LOG.lock();
    match g.0 {
        None => {
            g.0 = Some(now);
            g.1 = 0;
            lwarn!(
                "[{}] bad handshake (wrong secret or proto) — скорее всего, в Telegram \
                 выбран прокси с другим секретом; удалите старые записи прокси и \
                 добавьте заново по ссылке из приложения",
                label
            );
        }
        Some(since) => {
            g.1 += 1;
            if now.duration_since(since) >= Duration::from_secs(10) {
                lwarn!(
                    "bad handshake: ещё {} подключений с неверным секретом за {} с",
                    g.1,
                    now.duration_since(since).as_secs()
                );
                g.0 = Some(now);
                g.1 = 0;
            }
        }
    }
}


#[cfg(test)]
mod cf_worker_refill_regression {
    use super::*;

    #[tokio::test]
    async fn empty_worker_list_does_not_leave_refill_marked_running() {
        let pool = Arc::new(CfWorkerPool::new(CancellationToken::new()));
        pool.schedule_refill(2, "192.0.2.1".to_string(), vec![]).await;
        assert!(!pool.refilling.lock().await.contains(&2));
    }
}
