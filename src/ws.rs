use crate::config::*;
use crate::crypto::xor_mask_in_place;
use crate::{ldebug};
use base64::Engine;
use byteorder::{BigEndian, ByteOrder};
use rand::RngCore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use std::collections::HashMap;
use tokio::sync::Semaphore;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

// Diagnostic IDs, never logged together with protocol payloads or keys.
static NEXT_WS_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_DIAL_ID: AtomicU64 = AtomicU64::new(1);

// Global limit for fresh direct Telegram WebSocket dials (including pool warmup).
// CF/worker requests are intentionally not subject to this limiter.
const MAX_PARALLEL_DIRECT_WS: usize = 4;
const DIRECT_WS_QUEUE_TIMEOUT: Duration = Duration::from_millis(1000);
static DIRECT_WS_SLOTS: Lazy<Semaphore> = Lazy::new(|| Semaphore::new(MAX_PARALLEL_DIRECT_WS));

fn error_class(err: &WsError) -> String {
    match err {
        WsError::Io(e) => format!("io:{:?}:os={:?}", e.kind(), e.raw_os_error()),
        WsError::Handshake(h) => format!("http:{}", h.status_code),
        WsError::Timeout => "timeout".to_string(),
        WsError::Canceled => "canceled".to_string(),
        WsError::Other(_) => "other".to_string(),
        WsError::RemoteClose { code, reason_len } => format!("remote_close:code={:?}:reason_len={}", code, reason_len),
        WsError::Busy => "direct_dial_busy".to_string(),
    }
}
use std::sync::Arc;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

// ---------------------------------------------------------------------------
// WS opcodes — proxy/raw_websocket.py
// ---------------------------------------------------------------------------

pub const OP_CONT: u8 = 0x0;
pub const OP_TEXT: u8 = 0x1;
pub const OP_BINARY: u8 = 0x2;
pub const OP_CLOSE: u8 = 0x8;
pub const OP_PING: u8 = 0x9;
pub const OP_PONG: u8 = 0xA;

pub const MAX_MESSAGE_LEN: u64 = 16 * 1024 * 1024;
const MAX_FRAME_PAYLOAD: u64 = 16 * 1024 * 1024;

// ---------------------------------------------------------------------------
// TLS config: InsecureSkipVerify + session cache (как в Go)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

use once_cell::sync::Lazy;

// Глобальный TLS-конфиг с session resumption cache (аналог tls.NewLRUClientSessionCache(100))
static TLS_CONFIG: Lazy<Arc<ClientConfig>> = Lazy::new(|| {
    let mut cfg = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    cfg.resumption = rustls::client::Resumption::in_memory_sessions(100);
    Arc::new(cfg)
});

// Отдельный контекст для fronting (check_hostname=False в оригинале).
// На практике оба контекста NoVerify; разделение сохранено для паритета.
static TLS_CONFIG_FRONTING: Lazy<Arc<ClientConfig>> = Lazy::new(|| TLS_CONFIG.clone());

// ---------------------------------------------------------------------------
// DpiStream: TCP-поток, который режет первый TLS-рекорд (ClientHello) на два
// рекорда посередине SNI и отправляет их отдельными сегментами. Обычный DPI
// разбирает только первый рекорд/сегмент и не видит имя целиком. Для сервера
// это штатная фрагментация TLS (RFC 8446 §5.1), Cloudflare её принимает.
// Включается только для CF-маршрутов; прямые соединения к Telegram не трогаем.
// ---------------------------------------------------------------------------

pub struct DpiStream {
    inner: TcpStream,
    split_sni: Option<Vec<u8>>,
    queue: std::collections::VecDeque<(Vec<u8>, usize)>,
}

impl DpiStream {
    pub fn new(inner: TcpStream, split_sni: Option<&str>) -> Self {
        DpiStream {
            inner,
            split_sni: split_sni.map(|s| s.as_bytes().to_vec()),
            queue: std::collections::VecDeque::new(),
        }
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while let Some((chunk, off)) = self.queue.front_mut() {
            while *off < chunk.len() {
                match Pin::new(&mut self.inner).poll_write(cx, &chunk[*off..]) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()))
                    }
                    Poll::Ready(Ok(n)) => *off += n,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            self.queue.pop_front();
        }
        Poll::Ready(Ok(()))
    }
}

/// Делит первый TLS handshake-рекорд из `buf` на два рекорда.
/// Возвращает None, если в начале буфера нет целого handshake-рекорда.
pub fn split_tls_record(buf: &[u8], sni: &[u8]) -> Option<Vec<Vec<u8>>> {
    if buf.len() < 6 || buf[0] != 0x16 || buf[1] != 0x03 {
        return None;
    }
    let len = ((buf[3] as usize) << 8) | buf[4] as usize;
    if len < 2 || buf.len() < 5 + len {
        return None;
    }
    let payload = &buf[5..5 + len];
    let at = if sni.is_empty() {
        None
    } else {
        payload.windows(sni.len()).position(|w| w == sni)
    };
    let k = match at {
        Some(pos) => pos + 1 + sni.len() / 2,
        None => 1,
    }
    .clamp(1, len - 1);
    let rec = |part: &[u8]| {
        let mut v = Vec::with_capacity(5 + part.len());
        v.extend_from_slice(&[buf[0], buf[1], buf[2], (part.len() >> 8) as u8, part.len() as u8]);
        v.extend_from_slice(part);
        v
    };
    let mut out = vec![rec(&payload[..k]), rec(&payload[k..])];
    if buf.len() > 5 + len {
        out.push(buf[5 + len..].to_vec());
    }
    Some(out)
}

impl AsyncRead for DpiStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // Хвост ClientHello должен уйти раньше, чем мы начнём ждать ответ.
        if !this.queue.is_empty() {
            if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
                return Poll::Ready(Err(e));
            }
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for DpiStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        if let Some(sni) = this.split_sni.take() {
            if let Some(parts) = split_tls_record(buf, &sni) {
                for part in parts {
                    this.queue.push_back((part, 0));
                }
                if let Poll::Ready(Err(e)) = this.poll_drain(cx) {
                    return Poll::Ready(Err(e));
                }
                return Poll::Ready(Ok(buf.len()));
            }
        }
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

/// Делит HTTP-запрос на два куска посередине значения Host.
pub fn split_http_request(req: &[u8]) -> (usize, bool) {
    let needle = b"\r\nHost: ";
    match req.windows(needle.len()).position(|w| w == needle) {
        Some(pos) => (pos + needle.len() + 2, true),
        None => (0, false),
    }
}

// ---------------------------------------------------------------------------
// WsHandshakeError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct WsHandshakeError {
    pub status_code: i32,
    pub status_line: String,
    pub headers: HashMap<String, String>,
    pub location: String,
}

impl WsHandshakeError {
    pub fn is_redirect(&self) -> bool {
        matches!(self.status_code, 301 | 302 | 303 | 307 | 308)
    }
}

#[derive(Debug)]
pub enum WsError {
    Io(std::io::Error),
    Handshake(WsHandshakeError),
    Timeout,
    Canceled,
    RemoteClose { code: Option<u16>, reason_len: usize },
    Busy,
    Other(String),
}

impl WsError {
    pub fn compact(&self) -> String {
        match self {
            WsError::Canceled => "canceled".to_string(),
            WsError::Timeout => "timeout".to_string(),
            WsError::Handshake(h) => format!("http {}", h.status_code),
            WsError::Io(e) => {
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock
                {
                    "timeout".to_string()
                } else {
                    e.to_string()
                }
            }
            WsError::Other(s) => s.clone(),
            WsError::RemoteClose { code, reason_len } => format!("remote close code={:?} reason_len={}", code, reason_len),
            WsError::Busy => "direct dial queue saturated".to_string(),
        }
    }
    pub fn handshake_status(&self) -> Option<i32> {
        if let WsError::Handshake(h) = self {
            Some(h.status_code)
        } else {
            None
        }
    }
    pub fn handshake(&self) -> Option<&WsHandshakeError> {
        if let WsError::Handshake(h) = self {
            Some(h)
        } else {
            None
        }
    }
}

pub fn is_http_status_error(err: &WsError, code: i32) -> bool {
    err.handshake_status() == Some(code)
}

impl From<std::io::Error> for WsError {
    fn from(e: std::io::Error) -> Self {
        WsError::Io(e)
    }
}

// ---------------------------------------------------------------------------
// RawWebSocket — порт proxy/raw_websocket.py
// Поддерживает TLS (443) и plain (80, disable_secure), SNI-fronting,
// фрагментацию (CONT/TEXT/BINARY reassembly), close reasons.
// ---------------------------------------------------------------------------

enum WsReader {
    Tls(BufReader<tokio::io::ReadHalf<TlsStream<DpiStream>>>),
    Plain(BufReader<tokio::io::ReadHalf<TcpStream>>),
}

enum WsWriter {
    Tls(tokio::io::WriteHalf<TlsStream<DpiStream>>),
    Plain(tokio::io::WriteHalf<TcpStream>),
}

pub struct RawWebSocket {
    id: u64,
    reader: tokio::sync::Mutex<WsReader>,
    writer: tokio::sync::Mutex<WsWriter>,
    frag: tokio::sync::Mutex<Vec<u8>>,
    pub closed: AtomicBool,
    pub secure: bool,
}

impl RawWebSocket {
    pub fn diagnostic_id(&self) -> u64 {
        self.id
    }
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    /// Совместимость: закрыт ли транспорт (аналог writer.transport.is_closing()).
    pub fn transport_closing(&self) -> bool {
        self.is_closed()
    }

    pub async fn send(&self, data: &[u8]) -> Result<(), WsError> {
        if self.is_closed() {
            return Err(WsError::Other("WebSocket closed".to_string()));
        }
        let frame = build_frame(OP_BINARY, data, true);
        self.write_frame(&frame, WS_WRITE_TIMEOUT).await
    }

    pub async fn send_batch(&self, parts: &[Vec<u8>]) -> Result<(), WsError> {
        if self.is_closed() {
            return Err(WsError::Other("WebSocket closed".to_string()));
        }
        let mut writer = self.writer.lock().await;
        for part in parts {
            let frame = build_frame(OP_BINARY, part, true);
            let res = tokio::time::timeout(WS_WRITE_TIMEOUT, write_all_match(&mut writer, &frame)).await;
            match res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    ldebug!("RC3 WS id={} event=batch_write_error kind={:?} os={:?}", self.id, e.kind(), e.raw_os_error());
                    self.closed.store(true, Ordering::Relaxed);
                    return Err(WsError::Io(e));
                }
                Err(_) => {
                    ldebug!("RC3 WS id={} event=batch_write_timeout", self.id);
                    self.closed.store(true, Ordering::Relaxed);
                    return Err(WsError::Timeout);
                }
            }
        }
        Ok(())
    }

    pub async fn send_ping(&self) -> Result<(), WsError> {
        if self.is_closed() {
            return Err(WsError::Other("WebSocket closed".to_string()));
        }
        let frame = build_frame(OP_PING, &[], true);
        self.write_frame(&frame, WS_CONTROL_TIMEOUT).await
    }

    async fn write_frame(&self, frame: &[u8], timeout: Duration) -> Result<(), WsError> {
        let mut writer = self.writer.lock().await;
        let res = if timeout > Duration::ZERO {
            tokio::time::timeout(timeout, write_all_match(&mut writer, frame)).await
        } else {
            Ok(write_all_match(&mut writer, frame).await)
        };
        match res {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => {
                ldebug!("RC3 WS id={} event=write_error kind={:?} os={:?}", self.id, e.kind(), e.raw_os_error());
                self.closed.store(true, Ordering::Relaxed);
                Err(WsError::Io(e))
            }
            Err(_) => {
                ldebug!("RC3 WS id={} event=write_timeout", self.id);
                self.closed.store(true, Ordering::Relaxed);
                Err(WsError::Timeout)
            }
        }
    }

    // Recv с реассемблированием фрагментов (как Go/Python Recv).
    pub async fn recv(&self) -> Result<Vec<u8>, WsError> {
        loop {
            if self.is_closed() {
                return Err(WsError::Canceled);
            }
            let (opcode, payload, fin) = match self.read_frame().await {
                Ok(v) => v,
                Err(e) => {
                    ldebug!("RC3 WS id={} event=read_error class={}", self.id, error_class(&e));
                    self.closed.store(true, Ordering::Relaxed);
                    return Err(e);
                }
            };
            match opcode {
                OP_CLOSE => {
                    self.closed.store(true, Ordering::Relaxed);
                    let (code, _) = parse_close(&payload);
                    let reason_len = payload.len().saturating_sub(2);
                    ldebug!("RC3 WS id={} event=remote_close code={:?} reason_len={}", self.id, code, reason_len);
                    let mut close_payload = payload;
                    if close_payload.len() > 2 {
                        close_payload.truncate(2);
                    }
                    let reply = build_frame(OP_CLOSE, &close_payload, true);
                    let _ = self.write_frame(&reply, WS_CONTROL_TIMEOUT).await;
                    return Err(WsError::RemoteClose { code, reason_len });
                }
                OP_PING => {
                    let pong = build_frame(OP_PONG, &payload, true);
                    let _ = self.write_frame(&pong, WS_CONTROL_TIMEOUT).await;
                    continue;
                }
                OP_PONG => continue,
                OP_CONT | OP_TEXT | OP_BINARY => {
                    let mut frag = self.frag.lock().await;
                    if fin && frag.is_empty() {
                        return Ok(payload);
                    }
                    if frag.len() + payload.len() > MAX_MESSAGE_LEN as usize {
                        frag.clear();
                        return Err(WsError::Other(format!(
                            "WS message too large: {} bytes",
                            frag.len() + payload.len()
                        )));
                    }
                    frag.extend_from_slice(&payload);
                    if !fin {
                        continue;
                    }
                    let msg = std::mem::take(&mut *frag);
                    return Ok(msg);
                }
                _ => continue,
            }
        }
    }

    pub async fn close(&self) {
        if self.closed.swap(true, Ordering::Relaxed) {
            ldebug!("RC3 WS id={} event=close_already_marked", self.id);
            return;
        }
        ldebug!("RC3 WS id={} event=local_close", self.id);
        // Best-effort close frame + shutdown транспорта.
        let frame = build_frame(OP_CLOSE, &[], true);
        let _ = self.write_frame(&frame, WS_CONTROL_TIMEOUT).await;
        let mut writer = self.writer.lock().await;
        let _ = shutdown_match(&mut writer).await;
    }

    // recv с дедлайном чтения (для bridge).
    // ВАЖНО: таймаут оборачивает только чтение ОДНОГО фрейма целиком под
    // удержанием lock, чтобы НЕ дропать future посреди read_exact (иначе
    // теряются уже прочитанные байты BufReader → рассинхрон потока).
    pub async fn recv_with_timeout(&self, dur: Duration) -> Result<Vec<u8>, WsError> {
        loop {
            if self.is_closed() {
                return Err(WsError::Canceled);
            }
            let frame = {
                let mut reader = self.reader.lock().await;
                match tokio::time::timeout(dur, read_frame_match(&mut reader)).await {
                    Ok(Ok(v)) => v,
                    Ok(Err(e)) => {
                        ldebug!("RC4 WS id={} event=frame_read_error class={}", self.id, error_class(&e));
                        self.closed.store(true, Ordering::Relaxed);
                        return Err(e);
                    }
                    Err(_) => {
                        ldebug!("RC4 WS id={} event=frame_read_timeout", self.id);
                        return Err(WsError::Timeout);
                    },
                }
            };
            let (opcode, payload, fin) = frame;
            match opcode {
                OP_CLOSE => {
                    self.closed.store(true, Ordering::Relaxed);
                    let (code, _) = parse_close(&payload);
                    let reason_len = payload.len().saturating_sub(2);
                    ldebug!("RC4 WS id={} event=remote_close code={:?} reason_len={}", self.id, code, reason_len);
                    let mut close_payload = payload;
                    if close_payload.len() > 2 {
                        close_payload.truncate(2);
                    }
                    let reply = build_frame(OP_CLOSE, &close_payload, true);
                    let _ = self.write_frame(&reply, WS_CONTROL_TIMEOUT).await;
                    return Err(WsError::RemoteClose { code, reason_len });
                }
                OP_PING => {
                    let pong = build_frame(OP_PONG, &payload, true);
                    let _ = self.write_frame(&pong, WS_CONTROL_TIMEOUT).await;
                    continue;
                }
                OP_PONG => continue,
                OP_CONT | OP_TEXT | OP_BINARY => {
                    let mut frag = self.frag.lock().await;
                    if fin && frag.is_empty() {
                        return Ok(payload);
                    }
                    if frag.len() + payload.len() > MAX_MESSAGE_LEN as usize {
                        frag.clear();
                        return Err(WsError::Other("WS message too large".to_string()));
                    }
                    frag.extend_from_slice(&payload);
                    if !fin {
                        continue;
                    }
                    let msg = std::mem::take(&mut *frag);
                    return Ok(msg);
                }
                _ => continue,
            }
        }
    }

    async fn read_frame(&self) -> Result<(u8, Vec<u8>, bool), WsError> {
        let mut reader = self.reader.lock().await;
        read_frame_match(&mut reader).await
    }
}

async fn write_all_match(writer: &mut WsWriter, frame: &[u8]) -> std::io::Result<()> {
    match writer {
        WsWriter::Tls(w) => w.write_all(frame).await,
        WsWriter::Plain(w) => w.write_all(frame).await,
    }
}

async fn shutdown_match(writer: &mut WsWriter) -> std::io::Result<()> {
    match writer {
        WsWriter::Tls(w) => w.shutdown().await,
        WsWriter::Plain(w) => w.shutdown().await,
    }
}

async fn read_frame_match(reader: &mut WsReader) -> Result<(u8, Vec<u8>, bool), WsError> {
    match reader {
        WsReader::Tls(r) => read_frame_generic(r).await,
        WsReader::Plain(r) => read_frame_generic(r).await,
    }
}

// Чтение одного фрейма (generic над TLS/plain reader).
async fn read_frame_generic<R>(reader: &mut BufReader<R>) -> Result<(u8, Vec<u8>, bool), WsError>
where
    R: AsyncReadExt + Unpin,
{
    let mut hdr = [0u8; 2];
    reader.read_exact(&mut hdr).await?;

    let fin = (hdr[0] & 0x80) != 0;
    let opcode = hdr[0] & 0x0F;
    let mut length = (hdr[1] & 0x7F) as u64;

    if length == 126 {
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf).await?;
        length = BigEndian::read_u16(&buf) as u64;
    } else if length == 127 {
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf).await?;
        length = BigEndian::read_u64(&buf);
    }

    let has_mask = (hdr[1] & 0x80) != 0;
    let mut mask_key = [0u8; 4];
    if has_mask {
        reader.read_exact(&mut mask_key).await?;
    }

    if length > MAX_FRAME_PAYLOAD {
        return Err(WsError::Other(format!("frame too large: {} bytes", length)));
    }
    let mut payload = vec![0u8; length as usize];
    if length > 0 {
        reader.read_exact(&mut payload).await?;
    }
    if has_mask {
        xor_mask_in_place(&mut payload, &mask_key);
    }
    Ok((opcode, payload, fin))
}

fn parse_close(payload: &[u8]) -> (Option<u16>, String) {
    if payload.len() < 2 {
        return (None, String::new());
    }
    let code = BigEndian::read_u16(&payload[..2]);
    let text = String::from_utf8_lossy(&payload[2..]).to_string();
    let name = match code {
        1000 => "normal",
        1001 => "going_away",
        1002 => "protocol_error",
        1003 => "unsupported_data",
        1006 => "abnormal",
        1007 => "bad_data",
        1008 => "policy_violation",
        1009 => "too_big",
        1010 => "missing_extension",
        1011 => "internal_error",
        _ => "",
    };
    if name.is_empty() {
        (Some(code), text)
    } else if text.is_empty() {
        (Some(code), name.to_string())
    } else {
        (Some(code), format!("{} ({})", text, name))
    }
}

// ---------------------------------------------------------------------------
// Frame builder (mask=true всегда для клиента)
// ---------------------------------------------------------------------------

pub fn build_frame(opcode: u8, data: &[u8], mask: bool) -> Vec<u8> {
    let length = data.len();
    let fb = 0x80 | opcode;

    let mut header_size = 2;
    if mask {
        header_size += 4;
    }
    if length >= 126 && length < 65536 {
        header_size += 2;
    } else if length >= 65536 {
        header_size += 8;
    }

    let total_size = header_size + length;
    let mut result = vec![0u8; total_size];

    let mut pos = 0;
    result[pos] = fb;
    pos += 1;

    let mut mask_key = [0u8; 4];
    if mask {
        rand::thread_rng().fill_bytes(&mut mask_key);
    }

    if length < 126 {
        let mut lb = length as u8;
        if mask {
            lb |= 0x80;
        }
        result[pos] = lb;
        pos += 1;
    } else if length < 65536 {
        let mut lb = 126u8;
        if mask {
            lb |= 0x80;
        }
        result[pos] = lb;
        pos += 1;
        BigEndian::write_u16(&mut result[pos..], length as u16);
        pos += 2;
    } else {
        let mut lb = 127u8;
        if mask {
            lb |= 0x80;
        }
        result[pos] = lb;
        pos += 1;
        BigEndian::write_u64(&mut result[pos..], length as u64);
        pos += 8;
    }

    if mask {
        result[pos..pos + 4].copy_from_slice(&mask_key);
        pos += 4;
        result[pos..pos + length].copy_from_slice(data);
        xor_mask_in_place(&mut result[pos..pos + length], &mask_key);
    } else {
        result[pos..pos + length].copy_from_slice(data);
    }
    result
}

// ---------------------------------------------------------------------------
// Connection helpers — порт RawWebSocket.connect(host, domain, timeout,
// path, sni, secure) из proxy/raw_websocket.py
// ---------------------------------------------------------------------------

fn set_sock_opts(stream: &TcpStream) {
    if TCP_NODELAY {
        let _ = stream.set_nodelay(true);
    }
    // Аналог Go/Python: keepalive 30s — детект мёртвых соединений на мобиле.
    let sock = socket2::SockRef::from(stream);
    let ka = socket2::TcpKeepalive::new().with_time(Duration::from_secs(30));
    let _ = sock.set_tcp_keepalive(&ka);
    // proxy/raw_websocket.py::set_sock_opts — buffer_size из конфига.
    let buf = BUFFER_SIZE.load(std::sync::atomic::Ordering::Relaxed);
    if buf > 0 {
        let b = buf as usize;
        let _ = sock.set_recv_buffer_size(b);
        let _ = sock.set_send_buffer_size(b);
    }
}

pub fn ws_connect_timeout(timeout: f64) -> Duration {
    if timeout <= 0.0 {
        Duration::from_secs(5)
    } else {
        Duration::from_secs_f64(timeout)
    }
}

pub fn ws_handshake_timeout(total: Duration) -> Duration {
    if total <= Duration::ZERO {
        Duration::from_secs(3)
    } else if total > Duration::from_secs(3) {
        Duration::from_secs(3)
    } else {
        total
    }
}

fn server_name(domain: &str) -> ServerName<'static> {
    ServerName::try_from(domain.to_string())
        .unwrap_or_else(|_| ServerName::IpAddress("127.0.0.1".parse::<IpAddr>().unwrap().into()))
}

// Типизированный handshake: возвращает готовый RawWebSocket без type-erasure.
async fn handshake_tls(
    read_half: tokio::io::ReadHalf<TlsStream<DpiStream>>,
    mut write_half: tokio::io::WriteHalf<TlsStream<DpiStream>>,
    domain: &str,
    path: &str,
    timeout: Duration,
) -> Result<RawWebSocket, WsError> {
    let mut ws_key_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut ws_key_bytes);
    let ws_key = base64::engine::general_purpose::STANDARD.encode(ws_key_bytes);
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: binary\r\n\r\n",
        path, domain, ws_key
    );
    match tokio::time::timeout(timeout, write_half.write_all(req.as_bytes())).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(WsError::Io(e)),
        Err(_) => return Err(WsError::Timeout),
    }
    let mut bufreader = BufReader::with_capacity(4096, read_half);
    let (status_code, first_line, headers) =
        read_http_response(&mut bufreader, timeout).await?;
    if status_code == 101 {
        return Ok(RawWebSocket {
            id: NEXT_WS_ID.fetch_add(1, Ordering::Relaxed),
            reader: tokio::sync::Mutex::new(WsReader::Tls(bufreader)),
            writer: tokio::sync::Mutex::new(WsWriter::Tls(write_half)),
            frag: tokio::sync::Mutex::new(Vec::new()),
            closed: AtomicBool::new(false),
            secure: true,
        });
    }
    let location = headers.get("location").cloned().unwrap_or_default();
    Err(WsError::Handshake(WsHandshakeError {
        status_code,
        status_line: first_line,
        headers,
        location,
    }))
}

async fn handshake_plain(
    read_half: tokio::io::ReadHalf<TcpStream>,
    mut write_half: tokio::io::WriteHalf<TcpStream>,
    domain: &str,
    path: &str,
    timeout: Duration,
    split: bool,
) -> Result<RawWebSocket, WsError> {
    let mut ws_key_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut ws_key_bytes);
    let ws_key = base64::engine::general_purpose::STANDARD.encode(ws_key_bytes);
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: binary\r\n\r\n",
        path, domain, ws_key
    );
    let bytes = req.as_bytes();
    let (cut, do_split) = if split { split_http_request(bytes) } else { (0, false) };
    let write = async {
        if do_split && cut > 0 && cut < bytes.len() {
            // Два отдельных сегмента (TCP_NODELAY): Host не попадает в первый целиком.
            write_half.write_all(&bytes[..cut]).await?;
            write_half.flush().await?;
            tokio::time::sleep(Duration::from_millis(5)).await;
            write_half.write_all(&bytes[cut..]).await
        } else {
            write_half.write_all(bytes).await
        }
    };
    match tokio::time::timeout(timeout, write).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(WsError::Io(e)),
        Err(_) => return Err(WsError::Timeout),
    }
    let mut bufreader = BufReader::with_capacity(4096, read_half);
    let (status_code, first_line, headers) =
        read_http_response(&mut bufreader, timeout).await?;
    if status_code == 101 {
        return Ok(RawWebSocket {
            id: NEXT_WS_ID.fetch_add(1, Ordering::Relaxed),
            reader: tokio::sync::Mutex::new(WsReader::Plain(bufreader)),
            writer: tokio::sync::Mutex::new(WsWriter::Plain(write_half)),
            frag: tokio::sync::Mutex::new(Vec::new()),
            closed: AtomicBool::new(false),
            secure: false,
        });
    }
    let location = headers.get("location").cloned().unwrap_or_default();
    Err(WsError::Handshake(WsHandshakeError {
        status_code,
        status_line: first_line,
        headers,
        location,
    }))
}

async fn read_http_response<R: AsyncReadExt + Unpin>(
    bufreader: &mut BufReader<R>,
    timeout: Duration,
) -> Result<(i32, String, HashMap<String, String>), WsError> {
    let mut response_lines: Vec<String> = Vec::new();
    let read_result = tokio::time::timeout(timeout, async {
        loop {
            let line = read_line(bufreader).await?;
            let line = line.trim_end_matches(['\r', '\n']).to_string();
            if line.is_empty() {
                break;
            }
            response_lines.push(line);
            if response_lines.len() > 100 {
                return Err(WsError::Other("too many HTTP headers".to_string()));
            }
        }
        Ok::<(), WsError>(())
    })
    .await;
    match read_result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(WsError::Timeout),
    }
    if response_lines.is_empty() {
        return Err(WsError::Handshake(WsHandshakeError {
            status_code: 0,
            status_line: "empty response".to_string(),
            headers: HashMap::new(),
            location: String::new(),
        }));
    }
    let first_line = response_lines[0].clone();
    let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
    let mut status_code = 0;
    if parts.len() >= 2 {
        status_code = parts[1].parse::<i32>().unwrap_or(0);
    }
    let mut headers = HashMap::new();
    for hl in &response_lines[1..] {
        if let Some(idx) = hl.find(':') {
            headers.insert(
                hl[..idx].trim().to_lowercase(),
                hl[idx + 1..].trim().to_string(),
            );
        }
    }
    Ok((status_code, first_line, headers))
}

async fn read_line<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<String, WsError> {
    let mut buf = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            return Err(WsError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "EOF",
            )));
        }
        buf.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
        if buf.len() > 16384 {
            return Err(WsError::Other("header line too long".to_string()));
        }
    }
    Ok(String::from_utf8_lossy(&buf).to_string())
}

// wsConnectOnce — заголовки 1-в-1 как в Python raw_websocket.py (без User-Agent).
pub async fn ws_connect_once(
    dial_addr: &str,
    domain: &str,
    path: &str,
    timeout: Duration,
) -> Result<RawWebSocket, WsError> {
    let secure = !DISABLE_SECURE.load(Ordering::Relaxed);
    ws_connect_once_full(dial_addr, domain, path, timeout, None, secure).await
}

pub async fn ws_connect_once_full(
    dial_addr: &str,
    domain: &str,
    path: &str,
    timeout: Duration,
    sni: Option<&str>,
    secure: bool,
) -> Result<RawWebSocket, WsError> {
    ws_connect_inner(dial_addr, domain, path, timeout, sni, secure, false).await
}

/// Подключение для CF-прокси / CF-worker: явный режим (443 TLS или 80) и,
/// если включено CF_DPI_SPLIT, разбиение первого пакета.
pub async fn ws_connect_cf(
    dial_addr: &str,
    domain: &str,
    path: &str,
    timeout: Duration,
    secure: bool,
) -> Result<RawWebSocket, WsError> {
    let dpi = CF_DPI_SPLIT.load(Ordering::Relaxed);
    ws_connect_inner(dial_addr, domain, path, timeout, None, secure, dpi).await
}

async fn ws_connect_inner(
    dial_addr: &str,
    domain: &str,
    path: &str,
    timeout: Duration,
    sni: Option<&str>,
    secure: bool,
    dpi: bool,
) -> Result<RawWebSocket, WsError> {
    if dial_addr.is_empty() {
        return Err(WsError::Other("empty dial address".to_string()));
    }
    let path = if path.is_empty() { WS_PATH } else { path };
    let port = ws_port(secure);
    let target_addr = match dial_addr.parse::<std::net::Ipv6Addr>() {
        Ok(_) => format!("[{}]:{}", dial_addr, port),
        Err(_) => format!("{}:{}", dial_addr, port),
    };

    let dial_id = NEXT_DIAL_ID.fetch_add(1, Ordering::Relaxed);
    ldebug!("RC3 DIAL id={} event=start transport={} timeout_ms={}", dial_id,
        if secure { "tls" } else { "plain" }, timeout.as_millis());
    let started = std::time::Instant::now();
    let raw_conn = match tokio::time::timeout(timeout, TcpStream::connect(&target_addr)).await {
        Ok(Ok(c)) => {
            ldebug!("RC3 DIAL id={} stage=tcp result=ok elapsed_ms={}", dial_id, started.elapsed().as_millis());
            c
        }
        Ok(Err(e)) => {
            ldebug!("RC3 DIAL id={} stage=tcp result=io_error elapsed_ms={} kind={:?} os={:?}", dial_id, started.elapsed().as_millis(), e.kind(), e.raw_os_error());
            return Err(WsError::Io(e));
        }
        Err(_) => {
            ldebug!("RC3 DIAL id={} stage=tcp result=timeout elapsed_ms={}", dial_id, started.elapsed().as_millis());
            return Err(WsError::Timeout);
        }
    };
    set_sock_opts(&raw_conn);

    if !secure {
        let (read_half, write_half) = tokio::io::split(raw_conn);
        let started = std::time::Instant::now();
        let result = handshake_plain(read_half, write_half, domain, path, timeout, dpi).await;
        ldebug!("RC3 DIAL id={} stage=ws result={} elapsed_ms={} ws_id={:?} error={:?}", dial_id, if result.is_ok() { "ok" } else { "error" }, started.elapsed().as_millis(), result.as_ref().ok().map(|w| w.diagnostic_id()), result.as_ref().err().map(error_class));
        return result;
    }

    let sni_name = sni.unwrap_or(domain);
    let use_fronting = sni.is_some();
    let cfg = if use_fronting {
        TLS_CONFIG_FRONTING.clone()
    } else {
        TLS_CONFIG.clone()
    };
    let connector = TlsConnector::from(cfg);
    let sni_server = server_name(sni_name);
    let raw_conn = DpiStream::new(raw_conn, if dpi { Some(sni_name) } else { None });

    let handshake_timeout = ws_handshake_timeout(timeout);
    let started = std::time::Instant::now();
    let tls_conn =
        match tokio::time::timeout(handshake_timeout, connector.connect(sni_server, raw_conn)).await {
            Ok(Ok(c)) => {
                ldebug!("RC3 DIAL id={} stage=tls result=ok elapsed_ms={}", dial_id, started.elapsed().as_millis());
                c
            }
            Ok(Err(e)) => {
                ldebug!("RC3 DIAL id={} stage=tls result=io_error elapsed_ms={} kind={:?} os={:?}", dial_id, started.elapsed().as_millis(), e.kind(), e.raw_os_error());
                if e.kind() != std::io::ErrorKind::ConnectionReset {
                    ldebug!(" ws tls fail {} via {}: {}", domain, dial_addr, e);
                }
                return Err(WsError::Io(e));
            }
            Err(_) => {
                ldebug!("RC3 DIAL id={} stage=tls result=timeout elapsed_ms={}", dial_id, started.elapsed().as_millis());
                ldebug!(" ws tls fail {} via {}: timeout", domain, dial_addr);
                return Err(WsError::Timeout);
            }
        };

    let (read_half, write_half) = tokio::io::split(tls_conn);
    let started = std::time::Instant::now();
    let result = handshake_tls(read_half, write_half, domain, path, timeout).await;
    ldebug!("RC3 DIAL id={} stage=ws result={} elapsed_ms={} ws_id={:?} error={:?}", dial_id, if result.is_ok() { "ok" } else { "error" }, started.elapsed().as_millis(), result.as_ref().ok().map(|w| w.diagnostic_id()), result.as_ref().err().map(error_class));
    result
}

// All direct connections (new client, retries and WS pool) use one transport.
// Global backpressure prevents a failed network from spawning dozens of TCP dials.
pub async fn ws_connect_direct_limited(
    ip: &str, domain: &str, path: &str, timeout: f64, sni: Option<&str>,
) -> Result<RawWebSocket, WsError> {
    let queued_at = std::time::Instant::now();
    let _permit = match tokio::time::timeout(
        DIRECT_WS_QUEUE_TIMEOUT, DIRECT_WS_SLOTS.acquire()
    ).await {
        Ok(Ok(p)) => p,
        Ok(Err(_)) => return Err(WsError::Canceled),
        Err(_) => {
            ldebug!("RC4 DIRECT event=backpressure max_inflight={} queued_ms={}",
                MAX_PARALLEL_DIRECT_WS, queued_at.elapsed().as_millis());
            return Err(WsError::Busy);
        }
    };
    ldebug!("RC4 DIRECT event=slot_acquired max_inflight={} queued_ms={}",
        MAX_PARALLEL_DIRECT_WS, queued_at.elapsed().as_millis());
    // Keep explicit TLS regardless of the CF mode's DISABLE_SECURE setting.
    ws_connect_full_opts(ip, domain, path, timeout, sni, Some(true)).await
}

// wsConnect: пытается ip, при необходимости резолвит DoH
pub async fn ws_connect(
    ip: &str,
    domain: &str,
    path: &str,
    timeout: f64,
) -> Result<RawWebSocket, WsError> {
    ws_connect_full_opts(ip, domain, path, timeout, None, None).await
}

pub async fn ws_connect_full_opts(
    ip: &str,
    domain: &str,
    path: &str,
    timeout: f64,
    sni: Option<&str>,
    secure_opt: Option<bool>,
) -> Result<RawWebSocket, WsError> {
    let path = if path.is_empty() { WS_PATH } else { path };
    let attempt_timeout = ws_connect_timeout(timeout);
    let secure = secure_opt.unwrap_or(!DISABLE_SECURE.load(Ordering::Relaxed));

    let primary_addr = if ip.trim().is_empty() {
        domain.to_string()
    } else {
        ip.trim().to_string()
    };

    match ws_connect_once_full(&primary_addr, domain, path, attempt_timeout, sni, secure).await {
        Ok(ws) => return Ok(ws),
        Err(e) => {
            if primary_addr == domain && primary_addr.parse::<IpAddr>().is_err() {
                if let Some(resolved) = crate::cfproxy::resolve_doh(domain).await {
                    if !resolved.is_empty() && resolved != primary_addr {
                        return ws_connect_once_full(
                            &resolved,
                            domain,
                            path,
                            attempt_timeout,
                            sni,
                            secure,
                        )
                        .await;
                    }
                }
            }
            Err(e)
        }
    }
}

// connectOneWS: перебор доменов (pool refill path, fronting-first как в оригинале)
pub async fn connect_one_ws(ip: &str, domains: &[String]) -> Option<RawWebSocket> {
    connect_one_ws_full(ip, domains, WS_PATH, WS_POOL_CONNECT_TIMEOUT).await
}

pub async fn connect_one_ws_full(
    ip: &str,
    domains: &[String],
    path: &str,
    timeout: f64,
) -> Option<RawWebSocket> {
    // Поведение pool._connect_one: сначала fronting (sni=sprinthost.ru),
    // затем обычное соединение; Timeout/Reset → fronting fallback.
    let fronting_first = crate::proxy::ws_pool_fronting_first();
    for d in domains {
        if fronting_first {
            if let Some(ws) = connect_fronted(ip, d, path).await {
                return Some(ws);
            }
        }
        match ws_connect_direct_limited(ip, d, path, timeout, None).await {
            Ok(ws) => {
                crate::proxy::set_ws_pool_fronting_first(false);
                return Some(ws);
            }
            Err(WsError::Timeout) | Err(WsError::Io(_)) => {
                if fronting_first {
                    // как в оригинале: при fronting-first таймаут → сразу fronted
                    return connect_fronted(ip, d, path).await;
                }
                if let Some(ws) = connect_fronted(ip, d, path).await {
                    return Some(ws);
                }
            }
            Err(WsError::Handshake(h)) => {
                if h.is_redirect() {
                    continue;
                }
                return None;
            }
            Err(_) => return None,
        }
    }
    None
}

pub async fn connect_fronted(ip: &str, domain: &str, path: &str) -> Option<RawWebSocket> {
    let path = if path.is_empty() { WS_PATH } else { path };
    match ws_connect_direct_limited(ip, domain, path, WS_POOL_FRONTING_TIMEOUT, Some(FRONTING_SNI)).await {
        Ok(ws) => {
            STATS.connections_fronting.fetch_add(1, Ordering::Relaxed);
            crate::proxy::set_ws_pool_fronting_first(true);
            Some(ws)
        }
        Err(_) => None,
    }
}


#[cfg(test)]
mod rc4_diagnostics_tests {
    use super::*;

    #[test]
    fn remote_close_is_distinct_from_transport_eof() {
        let close = WsError::RemoteClose { code: Some(1000), reason_len: 0 };
        let eof = WsError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        assert_eq!(error_class(&close), "remote_close:code=Some(1000):reason_len=0");
        assert!(error_class(&eof).starts_with("io:UnexpectedEof:"));
    }

    #[test]
    fn direct_backpressure_has_own_error_class() {
        assert_eq!(error_class(&WsError::Busy), "direct_dial_busy");
        assert_eq!(MAX_PARALLEL_DIRECT_WS, 4);
    }
}
