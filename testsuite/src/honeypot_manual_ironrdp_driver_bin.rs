#![allow(
    clippy::print_stderr,
    reason = "test utility binary reports operational progress on stderr"
)]
#![allow(
    clippy::print_stdout,
    reason = "test utility binary supports a simple --version stdout path"
)]

#[cfg(not(unix))]
fn main() {
    eprintln!("honeypot-manual-irondrdp-driver is only supported on unix hosts");
    std::process::exit(1);
}

#[cfg(unix)]
fn main() {
    match real_main() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("{error:#}");
            std::process::exit(1);
        }
    }
}

#[cfg(unix)]
use std::io::Write as _;
#[cfg(unix)]
use std::net::{TcpStream, ToSocketAddrs as _};
#[cfg(unix)]
use std::time::{Duration, Instant};

#[cfg(unix)]
use anyhow::{Context as _, bail};
#[cfg(unix)]
use ironrdp_blocking::Framed;
#[cfg(unix)]
use ironrdp_connector::{self as connector, Credentials};
#[cfg(unix)]
use ironrdp_core::encode_vec;
#[cfg(unix)]
use ironrdp_graphics::image_processing::PixelFormat;
#[cfg(unix)]
use ironrdp_pdu::gcc::KeyboardType;
#[cfg(unix)]
use ironrdp_pdu::pcb::{PcbVersion, PreconnectionBlob};
#[cfg(unix)]
use ironrdp_pdu::rdp::capability_sets::MajorPlatformType;
#[cfg(unix)]
use ironrdp_pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};
#[cfg(unix)]
use ironrdp_session::image::DecodedImage;
#[cfg(unix)]
use ironrdp_session::{ActiveStage, ActiveStageOutput};
#[cfg(unix)]
use sspi::network_client::reqwest_network_client::ReqwestNetworkClient;
#[cfg(unix)]
use testsuite::honeypot_manual_ironrdp_rdpgfx::{
    ManualLabIronRdpRdpgfxProbe, ManualLabIronRdpRdpgfxProbeSummary, manual_lab_ironrdp_rdpgfx_dvc_client,
};
#[cfg(unix)]
use tokio_rustls::rustls;
#[cfg(unix)]
use x509_cert::der::Decode as _;

#[cfg(unix)]
#[derive(Debug)]
struct Args {
    host: String,
    proxy_port: u16,
    username: String,
    password: String,
    domain: Option<String>,
    association_token: String,
    session_id: String,
    lifetime_secs: u64,
    security: Option<String>,
    rdpgfx: bool,
}

#[cfg(unix)]
fn real_main() -> anyhow::Result<i32> {
    let args = parse_args()?;
    if let Some(version_flag) = args {
        println!("{version_flag}");
        return Ok(0);
    }

    let args = parse_run_args()?;
    run(args)?;
    Ok(0)
}

#[cfg(unix)]
fn parse_args() -> anyhow::Result<Option<String>> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None => Ok(None),
        Some("--version") => Ok(Some(format!(
            "honeypot-manual-irondrdp-driver {}",
            env!("CARGO_PKG_VERSION")
        ))),
        Some(_) => Ok(None),
    }
}

#[cfg(unix)]
fn parse_run_args() -> anyhow::Result<Args> {
    let mut args = std::env::args().skip(1);
    let mut host = None;
    let mut proxy_port = None;
    let mut username = None;
    let mut password = None;
    let mut domain = None;
    let mut association_token = None;
    let mut session_id = None;
    let mut lifetime_secs = 300u64;
    let mut security = None;
    let mut rdpgfx = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--host" => host = Some(args.next().context("missing value for --host")?),
            "--proxy-port" => {
                proxy_port = Some(
                    args.next()
                        .context("missing value for --proxy-port")?
                        .parse::<u16>()
                        .context("parse --proxy-port")?,
                );
            }
            "--username" => username = Some(args.next().context("missing value for --username")?),
            "--password" => password = Some(args.next().context("missing value for --password")?),
            "--domain" => domain = Some(args.next().context("missing value for --domain")?),
            "--association-token" => {
                association_token = Some(args.next().context("missing value for --association-token")?)
            }
            "--session-id" => session_id = Some(args.next().context("missing value for --session-id")?),
            "--lifetime-secs" => {
                lifetime_secs = args
                    .next()
                    .context("missing value for --lifetime-secs")?
                    .parse::<u64>()
                    .context("parse --lifetime-secs")?;
            }
            "--security" => security = Some(args.next().context("missing value for --security")?),
            "--rdpgfx" => rdpgfx = true,
            "--version" => {
                println!("honeypot-manual-irondrdp-driver {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other => bail!("unknown argument for honeypot-manual-irondrdp-driver: {other}"),
        }
    }

    Ok(Args {
        host: host.context("missing --host")?,
        proxy_port: proxy_port.context("missing --proxy-port")?,
        username: username.context("missing --username")?,
        password: password.context("missing --password")?,
        domain,
        association_token: association_token.context("missing --association-token")?,
        session_id: session_id.context("missing --session-id")?,
        lifetime_secs,
        security,
        rdpgfx,
    })
}

#[cfg(unix)]
fn run(args: Args) -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    if let Some(security) = args.security.as_deref()
        && !security.eq_ignore_ascii_case("nla")
    {
        bail!("unsupported IronRDP security mode {security:?}; expected nla or unset");
    }

    let server_addr = (args.host.as_str(), args.proxy_port)
        .to_socket_addrs()
        .context("resolve proxy host")?
        .next()
        .context("no socket address resolved for proxy host")?;

    eprintln!(
        "ironrdp driver phase=tcp.connect session_id={} target={}",
        args.session_id, server_addr
    );

    let mut tcp_stream = TcpStream::connect(server_addr).context("TCP connect")?;

    let pcb = PreconnectionBlob {
        version: PcbVersion::V2,
        id: 0,
        v2_payload: Some(args.association_token.clone()),
    };
    let pcb_bytes = encode_vec(&pcb).context("encode preconnection blob")?;
    tcp_stream.write_all(&pcb_bytes).context("write preconnection blob")?;
    tcp_stream.flush().context("flush preconnection blob")?;

    let client_addr = tcp_stream.local_addr().context("get local socket address")?;
    let config = build_connector_config(&args);

    let mut framed = Framed::new(tcp_stream);
    let mut connector = connector::ClientConnector::new(config, client_addr);
    if args.rdpgfx {
        connector.attach_static_channel(manual_lab_ironrdp_rdpgfx_dvc_client());
    }

    eprintln!(
        "ironrdp driver phase=connect.begin session_id={} no_rdpgfx_client={}",
        args.session_id, !args.rdpgfx
    );
    let should_upgrade = ironrdp_blocking::connect_begin(&mut framed, &mut connector).context("begin connection")?;
    let initial_stream = framed.into_inner_no_leftover();
    let (upgraded_stream, server_public_key) = tls_upgrade(initial_stream, args.host.clone()).context("TLS upgrade")?;
    let upgraded = ironrdp_blocking::mark_as_upgraded(should_upgrade, &mut connector);

    let mut upgraded_framed = Framed::new(upgraded_stream);
    let mut network_client = ReqwestNetworkClient;
    let connection_result = ironrdp_blocking::connect_finalize(
        upgraded,
        connector,
        &mut upgraded_framed,
        &mut network_client,
        args.host.clone().into(),
        server_public_key,
        None,
    )
    .context("finalize connection")?;

    eprintln!(
        "ironrdp driver phase=connect.ready session_id={} width={} height={}",
        args.session_id, connection_result.desktop_size.width, connection_result.desktop_size.height
    );

    let mut image = DecodedImage::new(
        PixelFormat::RgbA32,
        connection_result.desktop_size.width,
        connection_result.desktop_size.height,
    );
    let mut active_stage = ActiveStage::new(connection_result);
    let session_started_at = Instant::now();
    let session_lifetime = Duration::from_secs(args.lifetime_secs);
    let mut graphics_update_count = 0u64;
    let mut received_frames = 0u64;

    while session_started_at.elapsed() < session_lifetime {
        let (action, payload) = match upgraded_framed.read_pdu() {
            Ok((action, payload)) => (action, payload),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(error) => return Err(anyhow::Error::new(error).context("read frame")),
        };

        received_frames += 1;
        let outputs = active_stage
            .process(&mut image, action, &payload)
            .context("process active stage frame")?;

        for output in outputs {
            match output {
                ActiveStageOutput::ResponseFrame(frame) => {
                    upgraded_framed
                        .write_all(&frame)
                        .context("write active stage response")?;
                }
                ActiveStageOutput::GraphicsUpdate(_) => {
                    graphics_update_count += 1;
                }
                ActiveStageOutput::Terminate(reason) => {
                    let rdpgfx_summary = active_stage_rdpgfx_summary(&mut active_stage);
                    eprintln!(
                        "ironrdp driver phase=terminate session_id={} received_frames={} graphics_updates={} reason={reason:?} rdpgfx_caps_advertise={} rdpgfx_caps_confirm={} rdpgfx_start_frame={} rdpgfx_end_frame={} rdpgfx_frame_ack={} rdpgfx_wire_to_surface1={} rdpgfx_wire_to_surface2={}",
                        args.session_id,
                        received_frames,
                        graphics_update_count,
                        rdpgfx_summary.capabilities_advertise_count,
                        rdpgfx_summary.capabilities_confirm_count,
                        rdpgfx_summary.start_frame_count,
                        rdpgfx_summary.end_frame_count,
                        rdpgfx_summary.frame_ack_count,
                        rdpgfx_summary.wire_to_surface1_count,
                        rdpgfx_summary.wire_to_surface2_count
                    );
                    return Ok(());
                }
                ActiveStageOutput::PointerDefault
                | ActiveStageOutput::PointerHidden
                | ActiveStageOutput::PointerPosition { .. }
                | ActiveStageOutput::PointerBitmap(_) => {}
                ActiveStageOutput::DeactivateAll(_) => {
                    let rdpgfx_summary = active_stage_rdpgfx_summary(&mut active_stage);
                    eprintln!(
                        "ironrdp driver phase=deactivate-all session_id={} received_frames={} graphics_updates={} rdpgfx_caps_advertise={} rdpgfx_caps_confirm={} rdpgfx_start_frame={} rdpgfx_end_frame={} rdpgfx_frame_ack={} rdpgfx_wire_to_surface1={} rdpgfx_wire_to_surface2={}",
                        args.session_id,
                        received_frames,
                        graphics_update_count,
                        rdpgfx_summary.capabilities_advertise_count,
                        rdpgfx_summary.capabilities_confirm_count,
                        rdpgfx_summary.start_frame_count,
                        rdpgfx_summary.end_frame_count,
                        rdpgfx_summary.frame_ack_count,
                        rdpgfx_summary.wire_to_surface1_count,
                        rdpgfx_summary.wire_to_surface2_count
                    );
                    return Ok(());
                }
            }
        }
    }

    let rdpgfx_summary = active_stage_rdpgfx_summary(&mut active_stage);
    eprintln!(
        "ironrdp driver phase=lifetime.exit session_id={} received_frames={} graphics_updates={} lifetime_secs={} rdpgfx_caps_advertise={} rdpgfx_caps_confirm={} rdpgfx_start_frame={} rdpgfx_end_frame={} rdpgfx_frame_ack={} rdpgfx_wire_to_surface1={} rdpgfx_wire_to_surface2={}",
        args.session_id,
        received_frames,
        graphics_update_count,
        args.lifetime_secs,
        rdpgfx_summary.capabilities_advertise_count,
        rdpgfx_summary.capabilities_confirm_count,
        rdpgfx_summary.start_frame_count,
        rdpgfx_summary.end_frame_count,
        rdpgfx_summary.frame_ack_count,
        rdpgfx_summary.wire_to_surface1_count,
        rdpgfx_summary.wire_to_surface2_count
    );

    Ok(())
}

#[cfg(unix)]
fn active_stage_rdpgfx_summary(active_stage: &mut ActiveStage) -> ManualLabIronRdpRdpgfxProbeSummary {
    active_stage
        .get_dvc::<ManualLabIronRdpRdpgfxProbe>()
        .and_then(|dvc| dvc.channel_processor_downcast_ref::<ManualLabIronRdpRdpgfxProbe>())
        .map(ManualLabIronRdpRdpgfxProbe::summary)
        .unwrap_or_default()
}

#[cfg(unix)]
fn build_connector_config(args: &Args) -> connector::Config {
    connector::Config {
        credentials: Credentials::UsernamePassword {
            username: args.username.clone(),
            password: args.password.clone(),
        },
        domain: args.domain.clone(),
        enable_tls: false,
        enable_credssp: true,
        keyboard_type: KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_layout: 0,
        keyboard_functional_keys_count: 12,
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        desktop_size: connector::DesktopSize {
            width: 1280,
            height: 1024,
        },
        bitmap: None,
        client_build: 0,
        client_name: "ironrdp-manual".to_owned(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_owned(),
        platform: platform_type(),
        enable_server_pointer: false,
        request_data: None,
        autologon: false,
        enable_audio_playback: false,
        pointer_software_rendering: true,
        performance_flags: PerformanceFlags::default(),
        desktop_scale_factor: 0,
        hardware_id: None,
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
    }
}

#[cfg(unix)]
fn platform_type() -> MajorPlatformType {
    #[cfg(windows)]
    {
        return MajorPlatformType::WINDOWS;
    }
    #[cfg(target_os = "macos")]
    {
        return MajorPlatformType::MACINTOSH;
    }
    #[cfg(target_os = "ios")]
    {
        return MajorPlatformType::IOS;
    }
    #[cfg(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        return MajorPlatformType::UNIX;
    }
    #[cfg(target_os = "android")]
    {
        return MajorPlatformType::ANDROID;
    }
    #[allow(unreachable_code)]
    MajorPlatformType::UNSPECIFIED
}

#[cfg(unix)]
fn tls_upgrade(
    stream: TcpStream,
    server_name: String,
) -> anyhow::Result<(rustls::StreamOwned<rustls::ClientConnection, TcpStream>, Vec<u8>)> {
    let mut config = rustls::client::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(danger::NoCertificateVerification))
        .with_no_client_auth();
    config.key_log = std::sync::Arc::new(rustls::KeyLogFile::new());
    config.resumption = rustls::client::Resumption::disabled();

    let config = std::sync::Arc::new(config);
    let server_name = server_name.try_into().context("parse TLS server name")?;
    let client = rustls::ClientConnection::new(config, server_name).context("create TLS client")?;

    let mut tls_stream = rustls::StreamOwned::new(client, stream);
    tls_stream.flush().context("advance TLS handshake")?;

    let cert = tls_stream
        .conn
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .context("peer certificate is missing")?;
    let server_public_key = extract_tls_server_public_key(cert).context("extract server public key")?;

    Ok((tls_stream, server_public_key))
}

#[cfg(unix)]
fn extract_tls_server_public_key(cert: &[u8]) -> anyhow::Result<Vec<u8>> {
    let cert = x509_cert::Certificate::from_der(cert).context("decode peer certificate")?;
    let server_public_key = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .context("subject public key BIT STRING is not aligned")?
        .to_owned();
    Ok(server_public_key)
}

#[cfg(unix)]
mod danger {
    use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use tokio_rustls::rustls::{DigitallySignedStruct, Error, SignatureScheme, pki_types};

    #[derive(Debug)]
    pub(super) struct NoCertificateVerification;

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _: &pki_types::CertificateDer<'_>,
            _: &[pki_types::CertificateDer<'_>],
            _: &pki_types::ServerName<'_>,
            _: &[u8],
            _: pki_types::UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &pki_types::CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &pki_types::CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA1,
                SignatureScheme::ECDSA_SHA1_Legacy,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
            ]
        }
    }
}
