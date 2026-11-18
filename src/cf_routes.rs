//! Выбор рабочего маршрута до Cloudflare (CF-прокси и CF-worker).
//!
//! Было: первый домен пробовался отдельно, остальные по 2 параллельно, цикл
//! дожидался ВСЕХ попыток (даже после успеха), отказы кроме 429 не
//! запоминались, а режим был один (порт 80 на Android). Когда встроенные
//! домены заблокировали (16.11.2026), каждое соединение Telegram ждало
//! перебора всех 20 доменов (~100 с) и только потом уходило в TCP.
//!
//! Стало:
//!   * кандидаты стартуют «лесенкой»: следующий сразу после отказа
//!     предыдущего или через STAGGER, если тот молчит; первый успех
//!     побеждает, остальные попытки отменяются;
//!   * у всего перебора общий бюджет;
//!   * отказавший маршрут (домен + режим) уходит в паузу 20→300 с;
//!     HTTP-ответ означает проблему самого домена, и тогда в паузу уходят
//!     оба режима;
//!   * если основной режим молчит, через SECOND_MODE_DELAY пробуется второй
//!     (80 ↔ 443), победивший режим запоминается для группы;
//!   * если все маршруты недавно отказали, CF пропускается сразу, без ожидания.

use crate::config::*;
use crate::ws::{ws_connect_cf, RawWebSocket, WsError};
use crate::{ldebug, linfo, lwarn};
use once_cell::sync::Lazy;
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

pub const GROUP_CF: &str = "cf";
pub const GROUP_WORKER: &str = "worker";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// Ключ учёта отказов: базовый домен CF-прокси или домен воркера.
    pub key: String,
    /// Куда подключаемся (kwsN.<домен> или домен воркера).
    pub host: String,
}

#[derive(Clone, Copy, Debug)]
pub struct Timing {
    pub stagger: Duration,
    pub attempt: Duration,
    pub budget: Duration,
    pub second_mode_delay: Duration,
    pub max_parallel: usize,
    pub cooldown_initial: Duration,
    pub cooldown_max: Duration,
}

impl Timing {
    pub const DEFAULT: Timing = Timing {
        stagger: Duration::from_millis(700),
        attempt: Duration::from_secs(4),
        budget: Duration::from_secs(10),
        second_mode_delay: Duration::from_millis(1500),
        max_parallel: 3,
        cooldown_initial: Duration::from_secs(20),
        cooldown_max: Duration::from_secs(300),
    };
}

pub static TIMING: Lazy<RwLock<Timing>> = Lazy::new(|| RwLock::new(Timing::DEFAULT));

#[derive(Default)]
struct Health {
    // (key, secure) -> (число отказов подряд, до какого момента не пробовать)
    fails: HashMap<(String, bool), (u32, Instant)>,
    // группа -> режим, который отвечал последним (true = TLS 443)
    preferred: HashMap<&'static str, bool>,
}

static HEALTH: Lazy<Mutex<Health>> = Lazy::new(|| Mutex::new(Health::default()));

pub fn reset() {
    let mut h = HEALTH.lock();
    h.fails.clear();
    h.preferred.clear();
}

fn default_secure() -> bool {
    !DISABLE_SECURE.load(Ordering::Relaxed)
}

pub fn preferred_secure(group: &'static str) -> bool {
    HEALTH
        .lock()
        .preferred
        .get(group)
        .copied()
        .unwrap_or_else(default_secure)
}

fn usable(h: &Health, key: &str, secure: bool, now: Instant) -> bool {
    match h.fails.get(&(key.to_string(), secure)) {
        Some((_, until)) => now >= *until,
        None => true,
    }
}

fn mark_failed(key: &str, secure: bool, err: &WsError) {
    let t = *TIMING.read();
    let now = Instant::now();
    let mut h = HEALTH.lock();
    let mut modes = vec![secure];
    if let Some(h) = err.handshake() {
        // До Cloudflare дошли, но домен ответил ошибкой (404/403/429...):
        // другой порт вернёт то же самое. Исключение — редирект (обычно
        // 80 -> https при «Always Use HTTPS»): это проблема только порта 80.
        if !h.is_redirect() && !(300..400).contains(&h.status_code) {
            modes.push(!secure);
        }
    }
    for m in modes {
        let entry = h.fails.entry((key.to_string(), m)).or_insert((0, now));
        entry.0 = entry.0.saturating_add(1);
        let mut delay = t.cooldown_initial;
        for _ in 1..entry.0.min(8) {
            delay = delay.saturating_mul(2);
        }
        entry.1 = now + delay.min(t.cooldown_max);
    }
}

fn mark_ok(key: &str, secure: bool) {
    HEALTH.lock().fails.remove(&(key.to_string(), secure));
}

fn note_winner(group: &'static str, secure: bool, label: &str) {
    let prev = preferred_secure(group);
    HEALTH.lock().preferred.insert(group, secure);
    if prev != secure {
        linfo!(
            "[{}] CF {}: основной режим не отвечает, перешёл на {}",
            label,
            group,
            if secure { "TLS (443)" } else { "порт 80" }
        );
    }
}

async fn attempt(host: String, path: String, secure: bool, per_try: Duration) -> Result<RawWebSocket, WsError> {
    match ws_connect_cf(&host, &host, &path, per_try, secure).await {
        Ok(ws) => Ok(ws),
        Err(e) => {
            // HTTP-ответ: до CF дошли, другой IP не поможет.
            if e.handshake().is_some() || host.parse::<std::net::IpAddr>().is_ok() {
                return Err(e);
            }
            // Системный DNS мог вернуть заглушку — пробуем адрес из DoH.
            match crate::cfproxy::resolve_doh(&host).await {
                Some(ip) if !ip.is_empty() && ip != host => {
                    ldebug!(" CF DNS {} -> {}", host, ip);
                    ws_connect_cf(&ip, &host, &path, per_try, secure).await
                }
                _ => Err(e),
            }
        }
    }
}

/// Возвращает (ws, target, secure) первого ответившего маршрута либо None.
pub async fn race(
    targets: &[Target],
    path: &str,
    group: &'static str,
    label: &str,
    what: &str,
    quiet: bool,
) -> Option<(RawWebSocket, Target, bool)> {
    let t = *TIMING.read();
    let primary = preferred_secure(group);
    let auto = CF_AUTO_MODE.load(Ordering::Relaxed);

    let (mut q1, mut q2): (VecDeque<Target>, VecDeque<Target>) = {
        let now = Instant::now();
        let h = HEALTH.lock();
        let mut seen = std::collections::HashSet::new();
        let uniq: Vec<&Target> = targets.iter().filter(|x| seen.insert(x.key.clone())).collect();
        let q1 = uniq.iter().filter(|x| usable(&h, &x.key, primary, now)).map(|x| (*x).clone()).collect();
        let q2 = if auto {
            uniq.iter().filter(|x| usable(&h, &x.key, !primary, now)).map(|x| (*x).clone()).collect()
        } else {
            VecDeque::new()
        };
        (q1, q2)
    };

    if q1.is_empty() && q2.is_empty() {
        if !targets.is_empty() {
            ldebug!("[{}] {}: все маршруты недавно отказали, пропускаю", label, what);
        }
        return None;
    }

    let start = Instant::now();
    let deadline = start + t.budget;
    let second_at = if q1.is_empty() { start } else { start + t.second_mode_delay };
    let mut next_start = start;
    let mut set: JoinSet<(Target, bool, Result<RawWebSocket, WsError>)> = JoinSet::new();
    let mut running_primary = 0usize;
    let mut winner: Option<(RawWebSocket, Target, bool)> = None;

    while winner.is_none() {
        let now = Instant::now();
        if now >= deadline {
            break;
        }

        while set.len() < t.max_parallel && now >= next_start {
            let pick_second =
                !q2.is_empty() && (now >= second_at || (q1.is_empty() && running_primary == 0));
            let (target, secure) = if pick_second {
                (q2.pop_front().unwrap(), !primary)
            } else if let Some(x) = q1.pop_front() {
                (x, primary)
            } else {
                break;
            };
            if secure == primary {
                running_primary += 1;
            }
            let path = path.to_string();
            let per_try = t.attempt;
            set.spawn(async move {
                let host = target.host.clone();
                // Общий предел попытки: подключение по имени + повтор по DoH-адресу.
                let r = match tokio::time::timeout(per_try * 2, attempt(host, path, secure, per_try)).await {
                    Ok(r) => r,
                    Err(_) => Err(WsError::Timeout),
                };
                (target, secure, r)
            });
            next_start = now + t.stagger;
        }

        let queued = !q1.is_empty() || !q2.is_empty();
        if set.is_empty() && !queued {
            break;
        }

        let mut wake = deadline;
        if queued && set.len() < t.max_parallel {
            let mut gate = next_start;
            if q1.is_empty() && running_primary > 0 {
                gate = gate.max(second_at);
            }
            wake = wake.min(gate);
        }

        if set.is_empty() {
            tokio::time::sleep_until(tokio::time::Instant::from_std(wake)).await;
            continue;
        }

        tokio::select! {
            joined = set.join_next() => {
                let Some(joined) = joined else { continue };
                let Ok((target, secure, result)) = joined else { continue };
                if secure == primary {
                    running_primary = running_primary.saturating_sub(1);
                }
                match result {
                    Ok(ws) => {
                        mark_ok(&target.key, secure);
                        winner = Some((ws, target, secure));
                    }
                    Err(e) => {
                        mark_failed(&target.key, secure, &e);
                        if crate::ws::is_http_status_error(&e, 429) {
                            crate::cfproxy::mark_cfproxy_429_cooldown(&target.key, &e);
                        }
                        let msg = format!(
                            "[{}] {} не ответил через {} ({}): {}",
                            label, what, target.host,
                            if secure { "tls" } else { "порт 80" },
                            e.compact()
                        );
                        if quiet { ldebug!("{}", msg) } else { lwarn!("{}", msg) }
                        next_start = Instant::now();
                    }
                }
            }
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(wake)) => {}
        }
    }

    // Отменяем незавершённые попытки; уже открытые лишние сокеты закроются при drop.
    set.abort_all();
    while set.join_next().await.is_some() {}

    match winner {
        Some(w) => {
            note_winner(group, w.2, label);
            Some(w)
        }
        None => {
            let msg = format!(
                "[{}] {}: ни один маршрут не ответил за {:.0} с",
                label,
                what,
                start.elapsed().as_secs_f64()
            );
            if quiet { ldebug!("{}", msg) } else { lwarn!("{}", msg) }
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Разбор поля «свой CF-домен»: домены CF-прокси и CF-worker в одном поле.
// ---------------------------------------------------------------------------

/// Чистит ввод пользователя: схема, путь, порт, регистр, точка в конце.
pub fn clean_domain(raw: &str) -> String {
    let mut d = raw.trim();
    for scheme in ["https://", "http://", "wss://", "ws://"] {
        if d.len() >= scheme.len() && d[..scheme.len()].eq_ignore_ascii_case(scheme) {
            d = &d[scheme.len()..];
        }
    }
    let d = d.split(['/', '?', '#']).next().unwrap_or("");
    let d = d.split(':').next().unwrap_or("");
    d.trim().trim_end_matches('.').to_lowercase()
}

/// Делит список на (домены CF-прокси, домены CF-worker).
/// Воркер: домен *.workers.dev или запись с префиксом `worker:`.
pub fn split_user_domains(raw: &str) -> (Vec<String>, Vec<String>) {
    let mut proxies = Vec::new();
    let mut workers = Vec::new();
    for item in coerce_domain_list_str(raw) {
        let lower = item.trim().to_lowercase();
        let (is_worker, rest) = if let Some(r) = lower.strip_prefix("worker:") {
            (true, r.to_string())
        } else {
            (false, lower.clone())
        };
        let d = clean_domain(&rest);
        if !is_valid_domain(&d) {
            continue;
        }
        let list = if is_worker || d.ends_with(".workers.dev") {
            &mut workers
        } else {
            &mut proxies
        };
        if !list.contains(&d) {
            list.push(d);
        }
    }
    (proxies, workers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ws::{split_http_request, split_tls_record};
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // Тесты меняют глобальные порты/тайминги — гоняем их по одному.
    static SERIAL: Lazy<tokio::sync::Mutex<()>> = Lazy::new(|| tokio::sync::Mutex::new(()));

    fn fast_timing() -> Timing {
        Timing {
            stagger: Duration::from_millis(40),
            attempt: Duration::from_millis(300),
            budget: Duration::from_millis(1200),
            second_mode_delay: Duration::from_millis(120),
            max_parallel: 3,
            cooldown_initial: Duration::from_secs(20),
            cooldown_max: Duration::from_secs(300),
        }
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Mode {
        Ws,       // отвечает 101
        Hang,     // принимает соединение и молчит
        Http404,  // отвечает 404
        Redirect, // отвечает 301 на https (Always Use HTTPS)
    }

    struct Net {
        tls_port: u16,
        plain_port: u16,
        hits: Arc<Mutex<Vec<(String, bool)>>>,
        tls_handshakes: Arc<AtomicUsize>,
    }

    async fn ws_reply(
        mut s: tokio::net::TcpStream,
        mode: Mode,
        hits: Arc<Mutex<Vec<(String, bool)>>>,
    ) -> Option<String> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 2048];
        loop {
            let n = s.read(&mut tmp).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let req = String::from_utf8_lossy(&buf).to_string();
        let host = req
            .lines()
            .find(|l| l.to_lowercase().starts_with("host:"))
            .map(|l| l[5..].trim().to_string())
            .unwrap_or_default();
        hits.lock().push((host.clone(), false));
        match mode {
            Mode::Hang => {
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
            Mode::Http404 => {
                let _ = s.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await;
            }
            Mode::Redirect => {
                let _ = s.write_all(b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://x/apiws\r\nContent-Length: 0\r\n\r\n").await;
            }
            Mode::Ws => {
                let _ = s
                    .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                    .await;
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
        Some(host)
    }

    fn self_signed() -> (Vec<rustls_pki_types::CertificateDer<'static>>, rustls_pki_types::PrivateKeyDer<'static>) {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert = ck.cert.der().clone();
        let key = rustls_pki_types::PrivateKeyDer::Pkcs8(ck.key_pair.serialize_der().into());
        (vec![cert], key)
    }

    async fn start_net(tls_mode: Mode, plain_mode: Mode) -> Net {
        let tls_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let plain_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let net = Net {
            tls_port: tls_l.local_addr().unwrap().port(),
            plain_port: plain_l.local_addr().unwrap().port(),
            hits: Arc::new(Mutex::new(Vec::new())),
            tls_handshakes: Arc::new(AtomicUsize::new(0)),
        };
        let (certs, key) = self_signed();
        let cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let hits = net.hits.clone();
        let hs = net.tls_handshakes.clone();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = tls_l.accept().await else { return };
                let acceptor = acceptor.clone();
                let hits = hits.clone();
                let hs = hs.clone();
                tokio::spawn(async move {
                    if tls_mode == Mode::Hang {
                        // «DPI»: TCP принят, ClientHello съеден, ответа нет.
                        let mut s = s;
                        let mut b = [0u8; 4096];
                        while let Ok(n) = s.read(&mut b).await {
                            if n == 0 { break; }
                        }
                        return;
                    }
                    let Ok(mut tls) = acceptor.accept(s).await else { return };
                    hs.fetch_add(1, Ordering::SeqCst);
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 2048];
                    loop {
                        let Ok(n) = tls.read(&mut tmp).await else { return };
                        if n == 0 { return; }
                        buf.extend_from_slice(&tmp[..n]);
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") { break; }
                    }
                    let req = String::from_utf8_lossy(&buf).to_string();
                    let host = req.lines().find(|l| l.to_lowercase().starts_with("host:"))
                        .map(|l| l[5..].trim().to_string()).unwrap_or_default();
                    hits.lock().push((host, true));
                    match tls_mode {
                        Mode::Http404 => { let _ = tls.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await; }
                        _ => {
                            let _ = tls.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n").await;
                            tokio::time::sleep(Duration::from_secs(5)).await;
                        }
                    }
                });
            }
        });
        let hits = net.hits.clone();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = plain_l.accept().await else { return };
                let hits = hits.clone();
                tokio::spawn(async move {
                    let _ = ws_reply(s, plain_mode, hits).await;
                });
            }
        });
        TEST_PORT_TLS.store(net.tls_port, Ordering::SeqCst);
        TEST_PORT_PLAIN.store(net.plain_port, Ordering::SeqCst);
        net
    }

    fn targets(n: usize) -> Vec<Target> {
        (0..n)
            .map(|i| Target { key: format!("d{}.example", i), host: "127.0.0.1".to_string() })
            .collect()
    }

    fn setup(disable_secure: bool) {
        reset();
        *TIMING.write() = fast_timing();
        DISABLE_SECURE.store(disable_secure, Ordering::SeqCst);
        CF_AUTO_MODE.store(true, Ordering::SeqCst);
        CF_DPI_SPLIT.store(true, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn plain_ok_wins_immediately() {
        let _g = SERIAL.lock().await;
        setup(true);
        let net = start_net(Mode::Ws, Mode::Ws).await;
        let t0 = Instant::now();
        let r = race(&targets(5), "/apiws", GROUP_CF, "t", "CF", true).await;
        let (_, target, secure) = r.expect("должен подключиться");
        assert!(!secure);
        assert_eq!(target.key, "d0.example");
        assert!(t0.elapsed() < Duration::from_millis(200));
        assert_eq!(net.hits.lock().len(), 1);
    }

    #[tokio::test]
    async fn plain_blocked_falls_back_to_tls_and_remembers() {
        // Сценарий Android: порт 80 режется, TLS живой.
        let _g = SERIAL.lock().await;
        setup(true);
        let net = start_net(Mode::Ws, Mode::Hang).await;
        let r = race(&targets(5), "/apiws", GROUP_CF, "t", "CF", true).await;
        let (_, _, secure) = r.expect("должен уйти на TLS");
        assert!(secure);
        assert!(preferred_secure(GROUP_CF));
        // ClientHello резался на два рекорда, а rustls-сервер его принял.
        assert!(net.tls_handshakes.load(Ordering::SeqCst) >= 1);

        // Следующее соединение сразу идёт по TLS.
        let t0 = Instant::now();
        let r2 = race(&targets(5), "/apiws", GROUP_CF, "t", "CF", true).await;
        assert!(r2.unwrap().2);
        assert!(t0.elapsed() < Duration::from_millis(200));
    }

    #[tokio::test]
    async fn tls_blocked_falls_back_to_plain() {
        let _g = SERIAL.lock().await;
        setup(false);
        let _net = start_net(Mode::Hang, Mode::Ws).await;
        let r = race(&targets(5), "/apiws", GROUP_CF, "t", "CF", true).await;
        assert!(!r.expect("должен уйти на порт 80").2);
        assert!(!preferred_secure(GROUP_CF));
    }

    #[tokio::test]
    async fn everything_blocked_gives_up_in_budget_then_skips_instantly() {
        let _g = SERIAL.lock().await;
        setup(true);
        let _net = start_net(Mode::Hang, Mode::Hang).await;
        let tg = targets(20);
        let t0 = Instant::now();
        assert!(race(&tg, "/apiws", GROUP_CF, "t", "CF", true).await.is_none());
        let first = t0.elapsed();
        assert!(first <= fast_timing().budget + Duration::from_millis(300), "{:?}", first);

        // Без патча каждое следующее соединение снова ждало бы перебор.
        // Теперь те, что успели отказать, в паузе; оставшиеся — не больше бюджета.
        let t1 = Instant::now();
        let _ = race(&tg, "/apiws", GROUP_CF, "t", "CF", true).await;
        assert!(t1.elapsed() <= fast_timing().budget + Duration::from_millis(300));
        for _ in 0..4 {
            let _ = race(&tg, "/apiws", GROUP_CF, "t", "CF", true).await;
        }
        let t2 = Instant::now();
        assert!(race(&tg, "/apiws", GROUP_CF, "t", "CF", true).await.is_none());
        assert!(t2.elapsed() < Duration::from_millis(50), "{:?}", t2.elapsed());
    }

    #[tokio::test]
    async fn http_error_cools_down_both_modes() {
        let _g = SERIAL.lock().await;
        setup(true);
        let _net = start_net(Mode::Http404, Mode::Http404).await;
        assert!(race(&targets(1), "/apiws", GROUP_CF, "t", "CF", true).await.is_none());
        let now = Instant::now();
        let h = HEALTH.lock();
        assert!(!usable(&h, "d0.example", false, now));
        assert!(!usable(&h, "d0.example", true, now));
    }

    #[tokio::test]
    async fn redirect_on_port_80_still_tries_tls() {
        // workers.dev / свой домен с Always Use HTTPS: порт 80 отдаёт 301.
        let _g = SERIAL.lock().await;
        setup(true);
        let _net = start_net(Mode::Ws, Mode::Redirect).await;
        let r = race(&targets(1), "/apiws", GROUP_WORKER, "t", "worker", true).await;
        assert!(r.expect("TLS должен сработать после 301").2);
    }

    #[tokio::test]
    async fn auto_mode_off_keeps_single_mode() {
        let _g = SERIAL.lock().await;
        setup(true);
        CF_AUTO_MODE.store(false, Ordering::SeqCst);
        let net = start_net(Mode::Ws, Mode::Hang).await;
        assert!(race(&targets(2), "/apiws", GROUP_CF, "t", "CF", true).await.is_none());
        assert!(net.hits.lock().iter().all(|(_, secure)| !secure));
        CF_AUTO_MODE.store(true, Ordering::SeqCst);
    }

    #[tokio::test]
    async fn plain_request_is_split_but_host_arrives_intact() {
        let _g = SERIAL.lock().await;
        setup(true);
        let net = start_net(Mode::Hang, Mode::Ws).await;
        let tg = vec![Target { key: "mytgproxy.com".into(), host: "127.0.0.1".into() }];
        assert!(race(&tg, "/apiws", GROUP_CF, "t", "CF", true).await.is_some());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(net.hits.lock()[0].0, "127.0.0.1");
    }

    #[tokio::test]
    async fn client_hello_goes_out_split_on_the_wire() {
        let _g = SERIAL.lock().await;
        setup(true);
        // «DPI»: сырой TCP-сервер, который записывает всё, что пришло.
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        TEST_PORT_TLS.store(l.local_addr().unwrap().port(), Ordering::SeqCst);
        let got = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
        let g2 = got.clone();
        tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut b = [0u8; 8192];
            while let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(400), s.read(&mut b)).await {
                if n == 0 { break; }
                g2.lock().push(b[..n].to_vec());
            }
        });
        let sni = "kws2.mytgproxy.com";
        let _ = ws_connect_cf("127.0.0.1", sni, "/apiws", Duration::from_millis(500), true).await;
        let chunks = got.lock().clone();
        let all: Vec<u8> = chunks.concat();
        // Разбираем TLS-рекорды: должно быть минимум два handshake-рекорда,
        // и ни один не содержит имя целиком.
        let mut recs = Vec::new();
        let mut i = 0;
        while i + 5 <= all.len() {
            let l = ((all[i + 3] as usize) << 8) | all[i + 4] as usize;
            if i + 5 + l > all.len() { break; }
            recs.push((all[i], all[i + 5..i + 5 + l].to_vec()));
            i += 5 + l;
        }
        assert!(recs.len() >= 2, "рекордов: {}", recs.len());
        assert!(recs[0].0 == 0x16 && recs[1].0 == 0x16);
        assert!(recs.iter().all(|(_, p)| !p.windows(sni.len()).any(|w| w == sni.as_bytes())));
        let joined: Vec<u8> = recs[0].1.iter().chain(recs[1].1.iter()).copied().collect();
        assert!(joined.windows(sni.len()).any(|w| w == sni.as_bytes()), "SNI должен собраться из двух рекордов");
        // Сегменты на loopback склеиваются при чтении, поэтому их число здесь не проверяем.
    }

    #[tokio::test]
    async fn own_domain_and_worker_reach_the_core_unchanged() {
        let _g = SERIAL.lock().await;
        let raw = std::ffi::CString::new("MyTgProxy.com, https://pavel-tg.workers.dev/").unwrap();
        unsafe { crate::SetCfProxyConfig(1, 0, raw.as_ptr()) };
        crate::cfproxy::init_cfproxy_domains();
        let mut doms = crate::balancer::BALANCER.read().get_domains_for_dc(2);
        doms.sort();
        assert_eq!(doms, vec!["mytgproxy.com"]);
        assert_eq!(CF_WORKER_DOMAINS.read().clone(), vec!["pavel-tg.workers.dev"]);
        // Без своего домена — встроенный пул, воркеры очищаются.
        let empty = std::ffi::CString::new("").unwrap();
        unsafe { crate::SetCfProxyConfig(1, 0, empty.as_ptr()) };
        crate::cfproxy::init_cfproxy_domains();
        assert!(CF_WORKER_DOMAINS.read().is_empty());
        assert!(crate::balancer::BALANCER.read().get_domains_for_dc(2).len() >= 20);
    }

    #[test]
    fn tls_record_split_is_valid() {
        let sni = b"kws2.example.co.uk";
        let mut payload = vec![0x01, 0x00, 0x00, 0x40];
        payload.extend_from_slice(&[0xAA; 20]);
        payload.extend_from_slice(sni);
        payload.extend_from_slice(&[0xBB; 30]);
        let mut rec = vec![0x16, 0x03, 0x01, (payload.len() >> 8) as u8, payload.len() as u8];
        rec.extend_from_slice(&payload);
        rec.extend_from_slice(b"TAIL");
        let parts = split_tls_record(&rec, sni).unwrap();
        assert_eq!(parts.len(), 3);
        let mut joined = Vec::new();
        for p in &parts[..2] {
            assert_eq!(&p[..3], &[0x16, 0x03, 0x01]);
            let l = ((p[3] as usize) << 8) | p[4] as usize;
            assert_eq!(l, p.len() - 5);
            joined.extend_from_slice(&p[5..]);
        }
        assert_eq!(joined, payload);
        assert_eq!(parts[2], b"TAIL");
        // Имя хоста не попадает целиком ни в один рекорд.
        assert!(!parts[0].windows(sni.len()).any(|w| w == sni));
        assert!(!parts[1].windows(sni.len()).any(|w| w == sni));
        assert!(split_tls_record(b"GET / HTTP/1.1\r\n", sni).is_none());
    }

    #[test]
    fn http_split_point_is_inside_host() {
        let req = b"GET /apiws HTTP/1.1\r\nHost: kws2.example.co.uk\r\nUpgrade: websocket\r\n\r\n";
        let (cut, ok) = split_http_request(req);
        assert!(ok);
        let head = String::from_utf8_lossy(&req[..cut]);
        assert!(head.ends_with("Host: kw"));
    }

    #[test]
    fn user_domains_are_split_into_proxy_and_worker() {
        let (p, w) = split_user_domains(
            "MyTgProxy.com, https://pavel-tg.workers.dev/, worker:tg.example.net; example.ru. bad_domain",
        );
        assert_eq!(p, vec!["mytgproxy.com", "example.ru"]);
        assert_eq!(w, vec!["pavel-tg.workers.dev", "tg.example.net"]);
    }
}
