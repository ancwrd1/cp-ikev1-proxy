use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use http::{Request, Version};
use http_body_util::{BodyExt, Full};
use httparse::Status;
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use isakmp::{
    certs::{ClientCertificate, Pkcs8Certificate},
    rfc1751::key_to_english,
};
use native_tls::{Identity, TlsAcceptor, TlsConnector};
use tokio::io::AsyncRead;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use tracing::{debug, warn};

use crate::{
    assets::{KEYSTORE, KEYSTORE_PASSWORD},
    params::ProxyParams,
    sexpr::SExpression,
    util::snx_encrypt,
};

pub struct HttpsProxy {
    upstream_tls: tokio_native_tls::TlsStream<TcpStream>,
    downstream_sender: SendRequest<Full<Bytes>>,
}

impl HttpsProxy {
    pub async fn new(
        params: Arc<ProxyParams>,
        upstream: TcpStream,
        downstream: TcpStream,
    ) -> anyhow::Result<Self> {
        let tls_identity = Identity::from_pkcs12(KEYSTORE, KEYSTORE_PASSWORD)?;
        let tls_acceptor = TlsAcceptor::new(tls_identity)?;
        let tls_acceptor = tokio_native_tls::TlsAcceptor::from(tls_acceptor);

        let upstream_tls = tls_acceptor.accept(upstream).await?;

        debug!("<<< Upstream TLS connection accepted");

        // We don't care about downstream certificates.
        let tls_connector = TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true)
            .build()?;
        let tls_connector = tokio_native_tls::TlsConnector::from(tls_connector);

        let downstream_tls = tls_connector
            .connect(&params.server_address, downstream)
            .await?;

        debug!(">>> Downstream TLS connection succeeded");

        let downstream_io = TokioIo::new(downstream_tls);

        let (sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(downstream_io)
            .await?;

        tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                warn!("Connection failed: {}", err);
            }
        });

        Ok(Self {
            upstream_tls,
            downstream_sender: sender,
        })
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        // For some reason using Hyper HTTP server does not work together with Check Point Windows client.
        // We parse the request manually using httparse crate.
        let request = parse_http_request(&mut self.upstream_tls).await?;

        debug!("<<< Upstream HTTP request: {:#?}", request);

        let downstream_req = Request::builder()
            .version(request.version())
            .header("connection", "close")
            .uri(request.uri())
            .body(Full::new(request.body().clone()))?;

        let res = self.downstream_sender.send_request(downstream_req).await?;

        debug!(">>> Downstream response headers: {:#?}", res);

        let status = res.status();
        let data = res.collect().await?.to_bytes();

        debug!(
            ">>> Downstream response data: {}",
            String::from_utf8_lossy(&data)
        );

        let new_data = if status.is_success() {
            // "internal_ca_fingerprint" is used to verify the validity of the IKE certificate during IDPROT exchange.
            // We need to replace it with our own otherwise the client will show an "Invalid certificate" error.
            self.replace_ca_fingerprint(&data)?
        } else {
            data
        };

        let headers = format!(
            "HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
            new_data.len()
        );

        debug!("<<< Upstream HTTP response: {}", headers);

        self.upstream_tls.write_all(headers.as_bytes()).await?;
        self.upstream_tls.write_all(&new_data).await?;
        self.upstream_tls.flush().await?;
        self.upstream_tls.shutdown().await?;

        Ok(())
    }

    fn replace_ca_fingerprint(&self, data: &[u8]) -> anyhow::Result<Bytes> {
        let mut sexpr: SExpression = String::from_utf8_lossy(data).parse()?;

        let sub_expr = sexpr
            .get_mut("CCCserverResponse:ResponseData:connectivity_info:internal_ca_fingerprint");

        if let Some(SExpression::Object(_, map)) = sub_expr {
            let pkcs8 = Pkcs8Certificate::from_pkcs12(KEYSTORE, KEYSTORE_PASSWORD)?;
            let fingerprint = pkcs8.fingerprint();
            let words = key_to_english(&fingerprint[0..16])?.join(" ");
            let encoded = snx_encrypt(words.as_bytes());

            debug!("Replacing internal_ca_fingerprint with: {}", words);

            map.insert("1".to_string(), SExpression::Value(encoded));
        }

        Ok(Bytes::from(sexpr.to_string()))
    }
}

async fn parse_http_request(
    stream: &mut tokio_native_tls::TlsStream<TcpStream>,
) -> anyhow::Result<Request<Bytes>> {
    let mut reader = BufReader::new(stream);

    let mut message = String::new();
    reader.read_line(&mut message).await?;
    debug!("HTTP: request: {}", message);

    let mut header_count = 0;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await? > 0 {
            message.push_str(&line);
            if line.trim().is_empty() {
                debug!("HTTP: no more headers");
                break;
            } else {
                debug!("HTTP: header: {}", line);
                header_count += 1;
                if header_count > 64 {
                    anyhow::bail!("Too many headers".to_owned());
                }
            }
        } else {
            debug!("HTTP: no more data");
            break;
        }
    }

    let mut headers = vec![httparse::EMPTY_HEADER; header_count];
    let mut parsed_req = httparse::Request::new(&mut headers[..]);

    let parse_status = parsed_req.parse(message.as_bytes())?;

    let Status::Complete(_) = parse_status else {
        anyhow::bail!("Incomplete request");
    };

    let content_length = parsed_req
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-length"));

    let transfer_encoding = parsed_req
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("transfer-encoding"));

    let body = if let Some(content_length) = content_length {
        let len: usize = String::from_utf8_lossy(content_length.value).parse()?;

        let mut buf = vec![0; len];
        reader.read_exact(&mut buf).await?;

        buf.into()
    } else if let Some(encoding) = transfer_encoding {
        if encoding.value == b"chunked" {
            read_chunked_body(&mut reader).await?
        } else {
            anyhow::bail!("Unsupported transfer encoding");
        }
    } else if parsed_req.version == Some(0) {
        // HTTP 1.0: reading until the end of stream

        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await?;

        buf.into()
    } else {
        Bytes::new()
    };

    let version = match parsed_req.version {
        Some(0) => Version::HTTP_10,
        Some(1) => Version::HTTP_11,
        _ => anyhow::bail!("Invalid HTTP version"),
    };

    let builder = parsed_req
        .headers
        .iter()
        .fold(http::Request::builder().version(version), |builder, h| {
            builder.header(h.name, h.value)
        });

    let request = builder
        .uri(parsed_req.path.unwrap_or_default())
        .body(body)?;

    Ok(request)
}

async fn read_chunked_body<S: AsyncRead + Unpin>(
    reader: &mut BufReader<S>,
) -> anyhow::Result<Bytes> {
    let mut buffer = BytesMut::new();

    loop {
        let mut size_line = String::new();
        reader.read_line(&mut size_line).await?;

        // Parse chunk size (hex string)
        let size = usize::from_str_radix(size_line.trim(), 16)?;

        if size == 0 {
            let mut crlf = [0u8; 2];
            reader.read_exact(&mut crlf).await?;
            if crlf != [b'\r', b'\n'] {
                anyhow::bail!("Invalid chunk ending");
            }
            break;
        }

        // Read chunk data
        let mut chunk = vec![0u8; size];
        reader.read_exact(&mut chunk).await?;
        buffer.extend_from_slice(&chunk);

        // Consume trailing CRLF
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await?;
        if crlf != [b'\r', b'\n'] {
            anyhow::bail!("Invalid chunk ending");
        }
    }

    Ok(buffer.freeze())
}
