//! Preflight API security tests.
//!
//! These tests verify that the preflight API properly redacts sensitive data
//! (passwords) when logging debug information for provision-credentials requests.

use anyhow::Context as _;
use testsuite::cli::{dgw_tokio_cmd, wait_for_tcp_port};
use testsuite::dgw_config::{DgwConfig, DgwConfigHandle, VerbosityProfile};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Child;

/// Test scope token with gateway.preflight scope.
///
/// Token validation is disabled in tests, so the signature is fake.
/// - Header: `{"typ":"JWT","alg":"RS256"}`
/// - Payload: `{"type":"scope","jti":"...","scope":"gateway.preflight",...}`
const PREFLIGHT_SCOPE_TOKEN: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ0eXBlIjoic2NvcGUiLCJqdGkiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDIiLCJpYXQiOjE3MzM2Njk5OTksImV4cCI6MzMzMTU1MzU5OSwibmJmIjoxNzMzNjY5OTk5LCJzY29wZSI6ImdhdGV3YXkucHJlZmxpZ2h0In0.aW52YWxpZC1zaWduYXR1cmUtYnV0LXZhbGlkYXRpb24tZGlzYWJsZWQ";

/// Starts a gateway instance and returns the process and a handle to collect stdout.
///
/// The gateway is configured with DEBUG logging enabled to capture preflight operation logs.
/// Stdout is collected in a background task and returned when the handle is awaited.
async fn start_gateway_with_logs(
    config_handle: &DgwConfigHandle,
) -> anyhow::Result<(Child, tokio::task::JoinHandle<Vec<String>>)> {
    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .env("RUST_LOG", "devolutions_gateway=debug")
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to start Devolutions Gateway")?;

    let stdout = process.stdout.take().context("failed to take stdout")?;
    let stdout_handle = tokio::spawn(async move {
        let mut stdout_reader = BufReader::new(stdout);
        let mut lines = Vec::new();
        let mut line_buf = String::new();
        loop {
            match stdout_reader.read_line(&mut line_buf).await {
                Ok(0) => break,
                Ok(_) => {
                    lines.push(line_buf.clone());
                    line_buf.clear();
                }
                Err(_) => break,
            }
        }
        lines
    });

    wait_for_tcp_port(config_handle.http_port()).await?;

    Ok((process, stdout_handle))
}

/// Sends a preflight request and returns the raw HTTP response.
///
async fn send_preflight_request(http_port: u16, request_body: serde_json::Value) -> anyhow::Result<String> {
    let body = request_body.to_string();
    let http_request = format!(
        "POST /jet/preflight HTTP/1.1\r\n\
         Host: 127.0.0.1:{http_port}\r\n\
         Content-Type: application/json\r\n\
         Authorization: Bearer {PREFLIGHT_SCOPE_TOKEN}\r\n\
         Connection: close\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {}",
        body.len(),
        body
    );

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", http_port))
        .await
        .context("failed to connect to gateway")?;

    stream
        .write_all(http_request.as_bytes())
        .await
        .context("failed to send HTTP request")?;

    stream.flush().await.context("failed to flush stream")?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .context("failed to read HTTP response")?;

    String::from_utf8(response).context("response is not valid utf-8")
}

/// Sends a provision-credentials preflight request containing the given passwords.
async fn send_provision_credentials_request(
    http_port: u16,
    proxy_password: &str,
    target_password: &str,
    time_to_live: u32,
) -> anyhow::Result<String> {
    let request_body = serde_json::json!([{
        "id": "00000000-0000-0000-0000-000000000001",
        "kind": "provision-credentials",
        "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJqdGkiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDEiLCJpYXQiOjE3MzM2Njk5OTksImV4cCI6MzMzMTU1MzU5OSwibmJmIjoxNzMzNjY5OTk5LCJzY29wZSI6ImdhdGV3YXkucHJlZmxpZ2h0In0.invalid-signature",
        "proxy_credential": {
            "kind": "username-password",
            "username": "proxy-user",
            "password": proxy_password
        },
        "target_credential": {
            "kind": "username-password",
            "username": "target-user",
            "password": target_password
        },
        "time_to_live": time_to_live
    }]);

    send_preflight_request(http_port, request_body).await
}

fn assert_passwords_are_redacted(output: &str, passwords: &[&str]) {
    assert!(
        output.contains("Preflight operations"),
        "expected preflight logging to occur"
    );

    for password in passwords {
        assert!(
            !output.contains(password),
            "password '{password}' found in logs (should be redacted)"
        );
    }

    assert!(
        output.contains("***REDACTED***"),
        "expected '***REDACTED***' to appear in logs"
    );
}

/// Test that passwords in provision-credentials requests are redacted in logs.
///
/// This test:
/// 1. Starts the gateway with DEBUG logging enabled
/// 2. Sends a provision-credentials request with a test password
/// 3. Stops the gateway and collects logs
/// 4. Verifies the password does not appear in cleartext
/// 5. Verifies "***REDACTED***" appears instead
#[tokio::test]
async fn provision_credentials_passwords_not_logged() -> anyhow::Result<()> {
    const TEST_PASSWORD: &str = "super-secret-test-password-12345";

    // 1) Start the gateway with DEBUG logging.
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .verbosity_profile(VerbosityProfile::DEBUG)
        .build()
        .init()
        .context("init config")?;

    let (mut process, stdout_handle) = start_gateway_with_logs(&config_handle).await?;

    // 2) Send the preflight request with test password.
    let response = send_provision_credentials_request(config_handle.http_port(), TEST_PASSWORD, TEST_PASSWORD, 300)
        .await
        .context("send provision credentials request")?;
    assert!(response.contains("200 OK"), "{response}");

    // Allow time for the request to be logged.
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // 3) Stop the gateway and collect logs.
    let _ = process.start_kill();
    let stdout_lines = tokio::time::timeout(tokio::time::Duration::from_secs(5), stdout_handle)
        .await
        .context("timeout waiting for stdout")?
        .context("wait for stdout collection")?;
    let _ = process.wait().await;

    let stdout_output = stdout_lines.join("");

    assert_passwords_are_redacted(&stdout_output, &[TEST_PASSWORD]);

    Ok(())
}

/// Test that failure-path preflight validation still keeps passwords redacted in logs.
///
/// This exercises a request that is valid enough to reach the debug logging path but
/// invalid enough to return an `invalid-parameters` alert because the TTL exceeds the
/// configured maximum.
#[tokio::test]
async fn provision_credentials_passwords_not_logged_when_request_fails_validation() -> anyhow::Result<()> {
    const PROXY_PASSWORD: &str = "proxy-negative-secret-12345";
    const TARGET_PASSWORD: &str = "target-negative-secret-67890";

    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .verbosity_profile(VerbosityProfile::DEBUG)
        .build()
        .init()
        .context("init config")?;

    let (mut process, stdout_handle) = start_gateway_with_logs(&config_handle).await?;

    let response =
        send_provision_credentials_request(config_handle.http_port(), PROXY_PASSWORD, TARGET_PASSWORD, 7_201)
            .await
            .context("send invalid provision credentials request")?;

    assert!(response.contains("200 OK"), "{response}");
    assert!(
        response.contains("\"alert_status\":\"invalid-parameters\""),
        "{response}"
    );
    assert!(response.contains("exceeding the maximum TTL duration"), "{response}");
    assert!(!response.contains(PROXY_PASSWORD), "{response}");
    assert!(!response.contains(TARGET_PASSWORD), "{response}");

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let _ = process.start_kill();
    let stdout_lines = tokio::time::timeout(tokio::time::Duration::from_secs(5), stdout_handle)
        .await
        .context("timeout waiting for stdout")?
        .context("wait for stdout collection")?;
    let _ = process.wait().await;

    let stdout_output = stdout_lines.join("");

    assert_passwords_are_redacted(&stdout_output, &[PROXY_PASSWORD, TARGET_PASSWORD]);

    Ok(())
}
