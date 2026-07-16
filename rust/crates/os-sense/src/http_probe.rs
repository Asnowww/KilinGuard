use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::error::{OsSenseError, Result};
use crate::model::{
    DnsResolutionSource, DnsResolutionStatus, HttpProbeErrorKind, HttpProbeResult, HttpProbeStage,
    HttpProbeStatus,
};
use crate::network::{
    interleave_and_limit_addresses, literal_dns_resolution, probe_ip_allowed, validate_dns_target,
    DnsResolver, SystemDnsResolver,
};
use crate::redaction::redact_sensitive_text;

const MAX_HTTP_URL_BYTES: usize = 2_048;
const MAX_HTTP_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_HTTP_TIMEOUT_MS: u64 = 1_000;
const MAX_HTTP_ERROR_CHARS: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpProbeRequest {
    pub url: String,
    pub timeout_ms: Option<u64>,
    pub expected_status_min: Option<u16>,
    pub expected_status_max: Option<u16>,
}

#[derive(Debug, Clone)]
struct ValidatedHttpProbe {
    url: Url,
    host: String,
    port: u16,
    timeout: Duration,
    status_min: u16,
    status_max: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpTransportErrorKind {
    Timeout,
    Connect,
    Tls,
    Http,
}

#[derive(Debug)]
struct HttpTransportError {
    kind: HttpTransportErrorKind,
    message: String,
}

trait HttpTransport {
    fn get_status(
        &self,
        url: &Url,
        host: &str,
        address: SocketAddr,
        timeout: Duration,
    ) -> std::result::Result<u16, HttpTransportError>;
}

struct ReqwestHttpTransport;

impl HttpTransport for ReqwestHttpTransport {
    fn get_status(
        &self,
        url: &Url,
        host: &str,
        address: SocketAddr,
        timeout: Duration,
    ) -> std::result::Result<u16, HttpTransportError> {
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .timeout(timeout)
            .connect_timeout(timeout)
            .resolve(host, address)
            .build()
            .map_err(classify_reqwest_error)?;
        client
            .get(url.clone())
            .send()
            .map(|response| response.status().as_u16())
            .map_err(classify_reqwest_error)
    }
}

fn classify_reqwest_error(error: reqwest::Error) -> HttpTransportError {
    let text = error.to_string();
    let lower = text.to_ascii_lowercase();
    let kind = if error.is_timeout() {
        HttpTransportErrorKind::Timeout
    } else if error.is_connect() {
        HttpTransportErrorKind::Connect
    } else if lower.contains("tls") || lower.contains("certificate") || lower.contains("handshake")
    {
        HttpTransportErrorKind::Tls
    } else {
        HttpTransportErrorKind::Http
    };
    HttpTransportError {
        kind,
        message: bounded_http_error(&text),
    }
}

pub(crate) fn validate_http_probe_request(request: &HttpProbeRequest) -> Result<()> {
    validate_request(request).map(|_| ())
}

pub(crate) fn probe_http(request: &HttpProbeRequest) -> HttpProbeResult {
    probe_http_with(
        request,
        &SystemDnsResolver,
        &ReqwestHttpTransport,
        &SystemHttpClock::new(),
    )
}

trait HttpClock {
    fn elapsed(&self) -> Duration;
}

struct SystemHttpClock {
    started: Instant,
}

impl SystemHttpClock {
    fn new() -> Self {
        Self {
            started: Instant::now(),
        }
    }
}

impl HttpClock for SystemHttpClock {
    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

fn probe_http_with(
    request: &HttpProbeRequest,
    resolver: &dyn DnsResolver,
    transport: &dyn HttpTransport,
    clock: &dyn HttpClock,
) -> HttpProbeResult {
    let started = clock.elapsed();
    let validated = match validate_request(request) {
        Ok(validated) => validated,
        Err(error) => {
            return empty_result(request, 200, 399, started, clock).with_error(
                HttpProbeStatus::InvalidTarget,
                HttpProbeStage::Validation,
                HttpProbeErrorKind::InvalidUrl,
                &error.to_string(),
            );
        }
    };
    let deadline = started.saturating_add(validated.timeout);
    let mut result = empty_result(
        request,
        validated.status_min,
        validated.status_max,
        started,
        clock,
    );
    let resolution = if let Ok(address) = validated.host.parse::<IpAddr>() {
        literal_dns_resolution(address)
    } else {
        let remaining = deadline.saturating_sub(clock.elapsed());
        if remaining.is_zero() {
            return timeout_result(result, HttpProbeStage::Resolution, started, clock);
        }
        resolver.resolve(&validated.host, remaining)
    };
    let (addresses, additional_omitted) = interleave_and_limit_addresses(resolution.addresses);
    result.resolution_status =
        if additional_omitted > 0 && resolution.status == DnsResolutionStatus::Resolved {
            DnsResolutionStatus::Partial
        } else {
            resolution.status
        };
    result.resolution_source = resolution.source;
    result.resolved_addrs = addresses.iter().map(ToString::to_string).collect();
    result.omitted_address_count = resolution
        .omitted_address_count
        .saturating_add(additional_omitted);
    result.truncated |= resolution.truncated || additional_omitted > 0;
    if clock.elapsed() >= deadline {
        return timeout_result(result, HttpProbeStage::Resolution, started, clock);
    }
    if addresses.is_empty() {
        let kind = match resolution.status {
            DnsResolutionStatus::ResolverUnavailable => HttpProbeErrorKind::ResolverUnavailable,
            DnsResolutionStatus::TimedOut => HttpProbeErrorKind::ResolutionTimedOut,
            DnsResolutionStatus::NoAddresses => HttpProbeErrorKind::NoAddresses,
            _ => HttpProbeErrorKind::ResolutionFailed,
        };
        return result.with_error(
            if kind == HttpProbeErrorKind::ResolutionTimedOut {
                HttpProbeStatus::TimedOut
            } else {
                HttpProbeStatus::ResolutionFailed
            },
            HttpProbeStage::Resolution,
            kind,
            resolution
                .error
                .as_deref()
                .unwrap_or("HTTP probe host resolution failed"),
        );
    }
    let allowed = addresses
        .into_iter()
        .filter(|address| probe_ip_allowed(*address))
        .collect::<Vec<_>>();
    if allowed.is_empty() {
        return result.with_error(
            HttpProbeStatus::PolicyDenied,
            HttpProbeStage::Policy,
            HttpProbeErrorKind::PolicyDenied,
            "HTTP probe target is outside the allowed local/private address policy",
        );
    }

    let mut last_error = None;
    for (index, address) in allowed.iter().enumerate() {
        if clock.elapsed() >= deadline {
            return timeout_result(result, HttpProbeStage::Connect, started, clock);
        }
        let socket = SocketAddr::new(*address, validated.port);
        result.attempted_addrs.push(socket.to_string());
        let remaining = deadline.saturating_sub(clock.elapsed());
        let attempts_left = allowed.len().saturating_sub(index).max(1) as u32;
        let attempt_timeout = per_attempt_timeout(remaining, attempts_left);
        let response =
            transport.get_status(&validated.url, &validated.host, socket, attempt_timeout);
        if clock.elapsed() >= deadline {
            return timeout_result(result, HttpProbeStage::Http, started, clock);
        }
        match response {
            Ok(status) => {
                result.latency_ms = Some(clock.elapsed().saturating_sub(started).as_millis());
                result.selected_addr = Some(socket.to_string());
                result.status_code = Some(status);
                if (validated.status_min..=validated.status_max).contains(&status) {
                    result.ok = true;
                    result.status = HttpProbeStatus::Healthy;
                    result.stage = HttpProbeStage::Complete;
                    return result;
                }
                return result.with_error(
                    HttpProbeStatus::UnexpectedStatus,
                    HttpProbeStage::Status,
                    HttpProbeErrorKind::UnexpectedStatus,
                    &format!("HTTP status {status} is outside the expected range"),
                );
            }
            Err(error) => last_error = Some(error),
        }
    }
    result.latency_ms = Some(clock.elapsed().saturating_sub(started).as_millis());
    let error = last_error.unwrap_or(HttpTransportError {
        kind: HttpTransportErrorKind::Http,
        message: "HTTP request failed".to_string(),
    });
    let (status, stage, kind) = match error.kind {
        HttpTransportErrorKind::Timeout => (
            HttpProbeStatus::TimedOut,
            HttpProbeStage::Http,
            HttpProbeErrorKind::DeadlineExceeded,
        ),
        HttpTransportErrorKind::Connect => (
            HttpProbeStatus::Failed,
            HttpProbeStage::Connect,
            HttpProbeErrorKind::ConnectFailed,
        ),
        HttpTransportErrorKind::Tls => (
            HttpProbeStatus::Failed,
            HttpProbeStage::Tls,
            HttpProbeErrorKind::TlsFailed,
        ),
        HttpTransportErrorKind::Http => (
            HttpProbeStatus::Failed,
            HttpProbeStage::Http,
            HttpProbeErrorKind::HttpFailed,
        ),
    };
    result.with_error(status, stage, kind, &error.message)
}

fn validate_request(request: &HttpProbeRequest) -> Result<ValidatedHttpProbe> {
    if request.url.is_empty()
        || request.url.len() > MAX_HTTP_URL_BYTES
        || request.url.contains('\0')
    {
        return Err(configuration("HTTP probe URL must be 1..=2048 bytes"));
    }
    let url = Url::parse(&request.url)
        .map_err(|_| configuration("HTTP probe URL is not a valid absolute URL"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(configuration("HTTP probe URL scheme must be http or https"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(configuration(
            "HTTP probe URL must not contain user information",
        ));
    }
    if url.fragment().is_some() {
        return Err(configuration("HTTP probe URL must not contain a fragment"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| configuration("HTTP probe URL must contain a host"))?
        .to_string();
    validate_dns_target("http_probes host", &host)?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| configuration("HTTP probe URL must contain a valid port"))?;
    if port == 0 {
        return Err(configuration(
            "HTTP probe URL port must be between 1 and 65535",
        ));
    }
    let timeout_ms = request.timeout_ms.unwrap_or(DEFAULT_HTTP_TIMEOUT_MS);
    if !(1..=MAX_HTTP_TIMEOUT_MS).contains(&timeout_ms) {
        return Err(configuration(
            "HTTP probe timeout_ms must be between 1 and 5000",
        ));
    }
    let status_min = request.expected_status_min.unwrap_or(200);
    let status_max = request.expected_status_max.unwrap_or(399);
    if !(100..=599).contains(&status_min)
        || !(100..=599).contains(&status_max)
        || status_min > status_max
    {
        return Err(configuration(
            "HTTP probe expected status range must be ordered within 100..=599",
        ));
    }
    Ok(ValidatedHttpProbe {
        url,
        host,
        port,
        timeout: Duration::from_millis(timeout_ms),
        status_min,
        status_max,
    })
}

fn configuration(message: &str) -> OsSenseError {
    OsSenseError::Configuration(message.to_string())
}

fn empty_result(
    request: &HttpProbeRequest,
    status_min: u16,
    status_max: u16,
    started: Duration,
    clock: &dyn HttpClock,
) -> HttpProbeResult {
    HttpProbeResult {
        target: sanitize_http_target(&request.url),
        ok: false,
        latency_ms: Some(clock.elapsed().saturating_sub(started).as_millis()),
        status: HttpProbeStatus::Unknown,
        stage: HttpProbeStage::Validation,
        error_kind: None,
        status_code: None,
        expected_status_min: status_min,
        expected_status_max: status_max,
        resolution_status: DnsResolutionStatus::NoAddresses,
        resolution_source: DnsResolutionSource::Unknown,
        resolved_addrs: Vec::new(),
        attempted_addrs: Vec::new(),
        selected_addr: None,
        truncated: request.url.chars().count() > MAX_HTTP_ERROR_CHARS,
        omitted_address_count: 0,
        error: None,
    }
}

fn timeout_result(
    mut result: HttpProbeResult,
    stage: HttpProbeStage,
    started: Duration,
    clock: &dyn HttpClock,
) -> HttpProbeResult {
    result.latency_ms = Some(clock.elapsed().saturating_sub(started).as_millis());
    result.with_error(
        HttpProbeStatus::TimedOut,
        stage,
        HttpProbeErrorKind::DeadlineExceeded,
        "HTTP probe deadline exceeded",
    )
}

fn bounded_http_error(error: &str) -> String {
    let url_sanitized = sanitize_urls_in_text(error);
    let tokens = url_sanitized.split_whitespace().collect::<Vec<_>>();
    let mut sanitized = Vec::with_capacity(tokens.len());
    let mut index = 0usize;
    while index < tokens.len() {
        let token = tokens[index];
        let authorization_value = token.split_once(':').and_then(|(key, value)| {
            let key = key
                .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
                .to_ascii_lowercase();
            (key == "authorization").then_some(value)
        });
        if let Some(value) = authorization_value {
            sanitized.push("Authorization:[REDACTED]");
            index = index.saturating_add(1);
            let value = value
                .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
                .to_ascii_lowercase();
            if matches!(value.as_str(), "bearer" | "basic") {
                index = index.saturating_add(1);
            } else if value.is_empty()
                && tokens.get(index).is_some_and(|scheme| {
                    matches!(
                        scheme
                            .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
                            .to_ascii_lowercase()
                            .as_str(),
                        "bearer" | "basic"
                    )
                })
            {
                index = index.saturating_add(2);
            }
            continue;
        }
        sanitized.push(token);
        index = index.saturating_add(1);
    }
    redact_sensitive_text(&sanitized.join(" "), MAX_HTTP_ERROR_CHARS)
}

fn sanitize_http_target(value: &str) -> String {
    let Ok(mut url) = Url::parse(value) else {
        return "[invalid-http-target]".to_string();
    };
    if !matches!(url.scheme(), "http" | "https") {
        return "[invalid-http-target]".to_string();
    }
    if !url.username().is_empty() || url.password().is_some() {
        let _ = url.set_username("");
        let _ = url.set_password(None);
    }
    url.set_query(None);
    url.set_fragment(None);
    url.as_str().chars().take(MAX_HTTP_ERROR_CHARS).collect()
}

fn sanitize_urls_in_text(input: &str) -> String {
    let mut output = String::with_capacity(input.len().min(MAX_HTTP_ERROR_CHARS));
    let mut remaining = input;
    while let Some(start) = find_url_start(remaining) {
        output.push_str(&remaining[..start]);
        let candidate = &remaining[start..];
        let end = candidate
            .char_indices()
            .find_map(|(index, ch)| {
                (index > 0
                    && (ch.is_whitespace()
                        || matches!(ch, '\'' | '"' | '<' | '>' | '(' | ')' | '{' | '}')))
                .then_some(index)
            })
            .unwrap_or(candidate.len());
        let raw_url = &candidate[..end];
        output.push_str(&sanitize_http_target(raw_url));
        remaining = &candidate[end..];
        if output.chars().count() >= MAX_HTTP_ERROR_CHARS {
            break;
        }
    }
    if output.chars().count() < MAX_HTTP_ERROR_CHARS {
        output.push_str(remaining);
    }
    output
}

fn find_url_start(value: &str) -> Option<usize> {
    let lower = value.to_ascii_lowercase();
    [lower.find("http://"), lower.find("https://")]
        .into_iter()
        .flatten()
        .min()
}

fn per_attempt_timeout(remaining: Duration, attempts_left: u32) -> Duration {
    let divided = remaining / attempts_left.max(1);
    if divided.is_zero() && !remaining.is_zero() {
        remaining
    } else {
        divided
    }
}

trait HttpProbeResultExt {
    fn with_error(
        self,
        status: HttpProbeStatus,
        stage: HttpProbeStage,
        kind: HttpProbeErrorKind,
        error: &str,
    ) -> Self;
}

impl HttpProbeResultExt for HttpProbeResult {
    fn with_error(
        mut self,
        status: HttpProbeStatus,
        stage: HttpProbeStage,
        kind: HttpProbeErrorKind,
        error: &str,
    ) -> Self {
        self.status = status;
        self.stage = stage;
        self.error_kind = Some(kind);
        self.error = Some(bounded_http_error(error));
        self
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use super::*;
    use crate::network::DnsResolution;

    struct Resolver(Vec<IpAddr>);

    impl DnsResolver for Resolver {
        fn resolve(&self, _name: &str, _timeout: Duration) -> DnsResolution {
            DnsResolution {
                addresses: self.0.clone(),
                status: DnsResolutionStatus::Resolved,
                latency_ms: Some(0),
                source: DnsResolutionSource::GetentAhosts,
                truncated: false,
                omitted_address_count: 0,
                parse_failure_count: 0,
                error: None,
            }
        }
    }

    struct Transport {
        status: std::result::Result<u16, HttpTransportErrorKind>,
        calls: Cell<usize>,
    }

    impl HttpTransport for Transport {
        fn get_status(
            &self,
            _url: &Url,
            _host: &str,
            _address: SocketAddr,
            _timeout: Duration,
        ) -> std::result::Result<u16, HttpTransportError> {
            self.calls.set(self.calls.get() + 1);
            self.status.map_err(|kind| HttpTransportError {
                kind,
                message: "Authorization: Bearer topsecret".to_string(),
            })
        }
    }

    struct Clock;

    impl HttpClock for Clock {
        fn elapsed(&self) -> Duration {
            Duration::ZERO
        }
    }

    struct MutableClock(Rc<Cell<Duration>>);

    impl HttpClock for MutableClock {
        fn elapsed(&self) -> Duration {
            self.0.get()
        }
    }

    struct AdvancingTransport {
        clock: Rc<Cell<Duration>>,
        elapsed_after_request: Duration,
    }

    impl HttpTransport for AdvancingTransport {
        fn get_status(
            &self,
            _url: &Url,
            _host: &str,
            _address: SocketAddr,
            timeout: Duration,
        ) -> std::result::Result<u16, HttpTransportError> {
            assert!(!timeout.is_zero());
            self.clock.set(self.elapsed_after_request);
            Ok(200)
        }
    }

    fn request(url: &str) -> HttpProbeRequest {
        HttpProbeRequest {
            url: url.to_string(),
            timeout_ms: Some(100),
            expected_status_min: None,
            expected_status_max: None,
        }
    }

    #[test]
    fn validates_url_and_status_boundaries() {
        assert!(validate_http_probe_request(&request("http://localhost:8080/health")).is_ok());
        assert!(validate_http_probe_request(&request("ftp://localhost/a")).is_err());
        assert!(validate_http_probe_request(&request("http://u:p@localhost/a")).is_err());
        assert!(validate_http_probe_request(&request("http://localhost/a#secret")).is_err());
        assert!(validate_http_probe_request(&request("http://localhost:0/a")).is_err());
        let mut invalid = request("http://localhost/a");
        invalid.expected_status_min = Some(400);
        invalid.expected_status_max = Some(399);
        assert!(validate_http_probe_request(&invalid).is_err());
    }

    #[test]
    fn pins_allowed_dns_address_and_checks_status_without_network() {
        let transport = Transport {
            status: Ok(399),
            calls: Cell::new(0),
        };
        let result = probe_http_with(
            &request("http://example.local/health"),
            &Resolver(vec!["127.0.0.1".parse().unwrap()]),
            &transport,
            &Clock,
        );
        assert!(result.ok);
        assert_eq!(result.status_code, Some(399));
        assert_eq!(result.selected_addr.as_deref(), Some("127.0.0.1:80"));
        assert_eq!(transport.calls.get(), 1);
        let query = probe_http_with(
            &request(
                "http://example.local/health?X-Amz-Signature=secret&X-Amz-Credential=credential",
            ),
            &Resolver(vec!["127.0.0.1".parse().unwrap()]),
            &transport,
            &Clock,
        );
        assert_eq!(query.target, "http://example.local/health");
        assert!(!query.target.contains('?'));
    }

    #[test]
    fn denies_public_dns_results_before_transport() {
        let transport = Transport {
            status: Ok(200),
            calls: Cell::new(0),
        };
        let result = probe_http_with(
            &request("http://example.com/health"),
            &Resolver(vec!["203.0.113.10".parse().unwrap()]),
            &transport,
            &Clock,
        );
        assert_eq!(result.status, HttpProbeStatus::PolicyDenied);
        assert_eq!(transport.calls.get(), 0);
    }

    #[test]
    fn returns_redirect_status_without_following_and_classifies_timeout() {
        let redirect = Transport {
            status: Ok(302),
            calls: Cell::new(0),
        };
        let redirected = probe_http_with(
            &request("http://localhost/redirect"),
            &Resolver(vec!["127.0.0.1".parse().unwrap()]),
            &redirect,
            &Clock,
        );
        assert!(redirected.ok);
        assert_eq!(redirected.status_code, Some(302));
        assert_eq!(redirect.calls.get(), 1);

        let timeout = Transport {
            status: Err(HttpTransportErrorKind::Timeout),
            calls: Cell::new(0),
        };
        let timed_out = probe_http_with(
            &request("http://localhost/slow"),
            &Resolver(vec!["127.0.0.1".parse().unwrap()]),
            &timeout,
            &Clock,
        );
        assert_eq!(timed_out.status, HttpProbeStatus::TimedOut);
        assert_eq!(
            timed_out.error_kind,
            Some(HttpProbeErrorKind::DeadlineExceeded)
        );

        assert_eq!(
            per_attempt_timeout(Duration::from_nanos(1), 8),
            Duration::from_nanos(1)
        );
        let clock_value = Rc::new(Cell::new(Duration::ZERO));
        let deadline_result = probe_http_with(
            &request("http://localhost/deadline"),
            &Resolver(vec!["127.0.0.1".parse().unwrap()]),
            &AdvancingTransport {
                clock: Rc::clone(&clock_value),
                elapsed_after_request: Duration::from_millis(100),
            },
            &MutableClock(clock_value),
        );
        assert_eq!(deadline_result.status, HttpProbeStatus::TimedOut);
        assert_eq!(deadline_result.stage, HttpProbeStage::Http);
    }

    #[test]
    fn classifies_transport_failure_and_redacts_error() {
        let transport = Transport {
            status: Err(HttpTransportErrorKind::Tls),
            calls: Cell::new(0),
        };
        let result = probe_http_with(
            &request("https://localhost/health"),
            &Resolver(vec!["127.0.0.1".parse().unwrap()]),
            &transport,
            &Clock,
        );
        assert_eq!(result.stage, HttpProbeStage::Tls);
        assert!(!result.error.as_deref().unwrap().contains("topsecret"));
        for sensitive in [
            "Authorization: Basic YmFzaWM= tail",
            "\"Authorization\":\"Bearer jsonsecret\" tail",
            "request http://localhost/?api_key=urlsecret&password=urlpass failed",
            "request https://s3.local/object?X-Amz-Signature=awssecret&X-Amz-Credential=awscredential failed",
            "request HTTPS://s3.local/object?X-Amz-Signature=uppersecret&X-Amz-Credential=uppercredential failed",
            "request http://[::1]/health?X-Amz-Signature=ipv6secret failed",
        ] {
            let redacted = bounded_http_error(sensitive);
            assert!(!redacted.contains("YmFzaWM="), "{redacted}");
            assert!(!redacted.contains("jsonsecret"), "{redacted}");
            assert!(!redacted.contains("urlsecret"), "{redacted}");
            assert!(!redacted.contains("urlpass"), "{redacted}");
            assert!(!redacted.contains("awssecret"), "{redacted}");
            assert!(!redacted.contains("awscredential"), "{redacted}");
            assert!(!redacted.contains("uppersecret"), "{redacted}");
            assert!(!redacted.contains("uppercredential"), "{redacted}");
            assert!(!redacted.contains("ipv6secret"), "{redacted}");
            assert!(!redacted.contains('?'), "{redacted}");
        }
    }
}
