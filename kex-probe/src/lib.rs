//! Loopback-only TLS lab probe.
//!
//! The probe completes one TLS handshake with a peer on a loopback address and
//! reports what was negotiated: protocol version, cipher suite, key-exchange
//! group and the peer's leaf certificate. Python's `ssl` module cannot report
//! the key-exchange group; rustls can, which is the reason this crate exists.
//!
//! Boundaries:
//! * Targets must be IP literals on a loopback address. Hostnames and
//!   non-loopback addresses are rejected before any socket is opened.
//! * The peer certificate is not validated against any trust store. The
//!   handshake signature is still verified against the presented certificate,
//!   so the peer must hold the matching private key. Output is labelled
//!   `peer_verification: "unverified"`.
//! * A failed handshake is an error. The probe never reports a group it did
//!   not observe.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{aws_lc_rs, CryptoProvider, SupportedKxGroup, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, NamedGroup, ProtocolVersion,
    ServerConfig, ServerConnection, SignatureScheme, SupportedProtocolVersion,
};
use serde_json::{json, Value};

pub const COLLECTOR_ID: &str = "kex-probe";
pub const COLLECTOR_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const ENVELOPE_SCHEMA_VERSION: &str = "1.0";
const MAX_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HANDSHAKE_BYTES: usize = 1 << 20;

#[derive(Debug)]
pub enum ProbeError {
    /// Input rejected before any network activity.
    Rejected(String),
    /// Network or TLS failure; nothing was observed.
    Failed(String),
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeError::Rejected(m) => write!(f, "rejected: {m}"),
            ProbeError::Failed(m) => write!(f, "failed: {m}"),
        }
    }
}

impl std::error::Error for ProbeError {}

/// Key-exchange groups the probe can offer or serve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    X25519Mlkem768,
    X25519,
    Secp256r1,
    Secp384r1,
}

impl Group {
    pub fn parse(value: &str) -> Result<Self, ProbeError> {
        match value.to_ascii_lowercase().as_str() {
            "x25519mlkem768" => Ok(Group::X25519Mlkem768),
            "x25519" => Ok(Group::X25519),
            "secp256r1" => Ok(Group::Secp256r1),
            "secp384r1" => Ok(Group::Secp384r1),
            other => Err(ProbeError::Rejected(format!("unsupported group: {other}"))),
        }
    }

    pub fn parse_list(value: &str) -> Result<Vec<Self>, ProbeError> {
        let groups: Vec<Group> = value
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(Group::parse)
            .collect::<Result<_, _>>()?;
        if groups.is_empty() {
            return Err(ProbeError::Rejected(
                "at least one group is required".into(),
            ));
        }
        Ok(groups)
    }

    fn kx(self) -> &'static dyn SupportedKxGroup {
        match self {
            Group::X25519Mlkem768 => aws_lc_rs::kx_group::X25519MLKEM768,
            Group::X25519 => aws_lc_rs::kx_group::X25519,
            Group::Secp256r1 => aws_lc_rs::kx_group::SECP256R1,
            Group::Secp384r1 => aws_lc_rs::kx_group::SECP384R1,
        }
    }

    fn name(self) -> &'static str {
        group_name(self.kx().name()).0
    }
}

/// Default offer: what a current PQC-capable client sends.
pub const DEFAULT_CLIENT_GROUPS: [Group; 2] = [Group::X25519Mlkem768, Group::X25519];

/// IANA TLS Supported Groups registry name and quantum-exposure family.
fn group_name(group: NamedGroup) -> (&'static str, &'static str) {
    match group {
        NamedGroup::X25519MLKEM768 => ("X25519MLKEM768", "hybrid"),
        NamedGroup::X25519 => ("x25519", "elliptic-curve"),
        NamedGroup::X448 => ("x448", "elliptic-curve"),
        NamedGroup::secp256r1 => ("secp256r1", "elliptic-curve"),
        NamedGroup::secp384r1 => ("secp384r1", "elliptic-curve"),
        NamedGroup::secp521r1 => ("secp521r1", "elliptic-curve"),
        NamedGroup::FFDHE2048
        | NamedGroup::FFDHE3072
        | NamedGroup::FFDHE4096
        | NamedGroup::FFDHE6144
        | NamedGroup::FFDHE8192 => ("ffdhe", "finite-field-dh"),
        _ => ("unknown", "unknown"),
    }
}

fn provider(groups: &[Group]) -> CryptoProvider {
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = groups.iter().map(|g| g.kx()).collect();
    provider
}

static TLS12_ONLY: [&SupportedProtocolVersion; 1] = [&rustls::version::TLS12];

fn versions(tls12_only: bool) -> &'static [&'static SupportedProtocolVersion] {
    if tls12_only {
        &TLS12_ONLY
    } else {
        rustls::DEFAULT_VERSIONS
    }
}

#[derive(Clone, Debug)]
pub struct ProbeRequest {
    pub host: String,
    pub port: u16,
    pub server_name: String,
    pub groups: Vec<Group>,
    pub timeout: Duration,
}

impl ProbeRequest {
    pub fn new(host: &str, port: u16) -> Self {
        ProbeRequest {
            host: host.to_string(),
            port,
            server_name: "localhost".to_string(),
            groups: DEFAULT_CLIENT_GROUPS.to_vec(),
            timeout: Duration::from_secs(2),
        }
    }
}

/// Validate the target. Called before any socket is created.
pub fn loopback_target(host: &str, port: u16) -> Result<SocketAddr, ProbeError> {
    let ip: IpAddr = host
        .parse()
        .map_err(|_| ProbeError::Rejected("target must be an IP address literal".into()))?;
    if !ip.is_loopback() {
        return Err(ProbeError::Rejected(
            "target must be a loopback address".into(),
        ));
    }
    if port == 0 {
        return Err(ProbeError::Rejected("port must be 1 to 65535".into()));
    }
    Ok(SocketAddr::new(ip, port))
}

/// Accepts any presented certificate but still checks the handshake
/// signature, so the peer must possess the certificate's private key.
#[derive(Debug)]
struct LabVerifier {
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for LabVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

fn drive<C, S>(conn: &mut C, sock: &mut TcpStream) -> Result<(), ProbeError>
where
    C: std::ops::DerefMut<Target = rustls::ConnectionCommon<S>>,
{
    let mut moved = 0usize;
    while conn.is_handshaking() {
        let (read, written) = conn
            .complete_io(sock)
            .map_err(|e| ProbeError::Failed(format!("handshake: {e}")))?;
        moved = moved.saturating_add(read + written);
        if moved > MAX_HANDSHAKE_BYTES {
            return Err(ProbeError::Failed("handshake exceeded size limit".into()));
        }
        if read == 0 && written == 0 && conn.is_handshaking() {
            return Err(ProbeError::Failed("peer closed during handshake".into()));
        }
    }
    Ok(())
}

fn protocol_name(version: Option<ProtocolVersion>) -> Result<&'static str, ProbeError> {
    match version {
        Some(ProtocolVersion::TLSv1_3) => Ok("TLSv1.3"),
        Some(ProtocolVersion::TLSv1_2) => Ok("TLSv1.2"),
        _ => Err(ProbeError::Failed("no protocol version negotiated".into())),
    }
}

/// Run one handshake and return the observation envelope.
pub fn probe(request: &ProbeRequest) -> Result<Value, ProbeError> {
    let target = loopback_target(&request.host, request.port)?;
    if request.timeout.is_zero() || request.timeout > MAX_TIMEOUT {
        return Err(ProbeError::Rejected("timeout must be 1 ms to 10 s".into()));
    }
    if request.groups.is_empty() {
        return Err(ProbeError::Rejected(
            "at least one group is required".into(),
        ));
    }
    let server_name = ServerName::try_from(request.server_name.clone())
        .map_err(|_| ProbeError::Rejected("invalid server name".into()))?;

    let provider = Arc::new(provider(&request.groups));
    let verifier = Arc::new(LabVerifier {
        algorithms: provider.signature_verification_algorithms,
    });
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions(false))
        .map_err(|e| ProbeError::Failed(format!("config: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let mut conn = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| ProbeError::Failed(format!("client: {e}")))?;
    let mut sock = TcpStream::connect_timeout(&target, request.timeout)
        .map_err(|e| ProbeError::Failed(format!("connect: {e}")))?;
    sock.set_read_timeout(Some(request.timeout)).ok();
    sock.set_write_timeout(Some(request.timeout)).ok();
    drive(&mut conn, &mut sock)?;

    let version = protocol_name(conn.protocol_version())?;
    let suite = conn
        .negotiated_cipher_suite()
        .ok_or_else(|| ProbeError::Failed("no cipher suite negotiated".into()))?;
    let suite_name = format!("{:?}", suite.suite()).replacen("TLS13_", "TLS_", 1);
    let group = conn
        .negotiated_key_exchange_group()
        .ok_or_else(|| ProbeError::Failed("no key-exchange group negotiated".into()))?
        .name();
    let (group_label, family) = group_name(group);
    let leaf = conn
        .peer_certificates()
        .and_then(|c| c.first())
        .map(|c| base64::engine::general_purpose::STANDARD.encode(c.as_ref()))
        .ok_or_else(|| ProbeError::Failed("peer presented no certificate".into()))?;

    conn.send_close_notify();
    let _ = conn.complete_io(&mut sock);

    Ok(json!({
        "schema_version": ENVELOPE_SCHEMA_VERSION,
        "collector_id": COLLECTOR_ID,
        "collector_version": COLLECTOR_VERSION,
        "transport": {
            "protocol": "tls",
            "tls_version": version,
            "cipher_suite": suite_name,
            "peer_host": request.host,
            "peer_port": request.port,
            "peer_verification": "unverified",
            "negotiated_key_establishment": group_label,
        },
        "key_establishment": {
            "group": group_label,
            "group_id": u16::from(group),
            "family": family,
            "offered_groups": request.groups.iter().map(|g| g.name()).collect::<Vec<_>>(),
        },
        "peer_certificate_der_base64": leaf,
    }))
}

/// Lab server configuration. Binds to 127.0.0.1 only.
#[derive(Clone, Debug)]
pub struct LabServer {
    pub groups: Vec<Group>,
    pub tls12_only: bool,
    pub dns_name: String,
}

impl LabServer {
    pub fn bind(&self, port: u16) -> Result<(TcpListener, Arc<ServerConfig>), ProbeError> {
        let issued = rcgen::generate_simple_self_signed(vec![self.dns_name.clone()])
            .map_err(|e| ProbeError::Failed(format!("certificate: {e}")))?;
        let cert = issued.cert.der().clone();
        let key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(issued.signing_key.serialize_der()));
        let config = ServerConfig::builder_with_provider(Arc::new(provider(&self.groups)))
            .with_protocol_versions(versions(self.tls12_only))
            .map_err(|e| ProbeError::Failed(format!("config: {e}")))?
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(|e| ProbeError::Failed(format!("server cert: {e}")))?;
        let listener = TcpListener::bind(("127.0.0.1", port))
            .map_err(|e| ProbeError::Failed(format!("bind: {e}")))?;
        Ok((listener, Arc::new(config)))
    }
}

/// Serve `connections` handshakes. A failed client handshake is not fatal to
/// the server, so negative tests can run against it.
pub fn serve(listener: &TcpListener, config: Arc<ServerConfig>, connections: u32) {
    for _ in 0..connections {
        let Ok((mut sock, _)) = listener.accept() else {
            continue;
        };
        sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let Ok(mut conn) = ServerConnection::new(config.clone()) else {
            continue;
        };
        if drive(&mut conn, &mut sock).is_ok() {
            conn.send_close_notify();
            let _ = conn.complete_io(&mut sock);
            let mut sink = [0u8; 64];
            let _ = sock.read(&mut sink);
        }
        let _ = sock.flush();
    }
}
