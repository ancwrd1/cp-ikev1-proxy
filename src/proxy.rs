use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

use crate::{ProxyParams, https::HttpsProxy, tcpt::TcptProxy};

pub struct Ikev1Proxy {
    params: Arc<ProxyParams>,
}

impl Ikev1Proxy {
    pub fn new(params: Arc<ProxyParams>) -> Ikev1Proxy {
        Self { params }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let listener = TcpListener::bind("[::]:443").await?;

        debug!("Proxy started on port 443");

        while let Ok((upstream, address)) = listener.accept().await {
            debug!("Accepted connection from {}", address);

            let params = self.params.clone();
            tokio::spawn(async move {
                handle_new_connection(params, upstream)
                    .await
                    .inspect_err(|e| warn!("{}", e))
            });
        }
        Ok(())
    }
}

async fn handle_new_connection(
    params: Arc<ProxyParams>,
    upstream: TcpStream,
) -> anyhow::Result<()> {
    debug!("Connecting to {}", params.server_address);

    let downstream = TcpStream::connect(&format!("{}:443", params.server_address)).await?;

    debug!("Connected to {}", params.server_address);

    let mut buf = [0u8; 1];
    let size = upstream.peek(&mut buf[0..1]).await?;
    if size == 1 && buf[0] == 0 {
        debug!("Proxying TCPT connection to {}", params.server_address);

        TcptProxy::new(params, upstream, downstream)
            .await?
            .run()
            .await
    } else {
        debug!("Proxying HTTPS connection to {}", params.server_address);

        HttpsProxy::new(params, upstream, downstream)
            .await?
            .run()
            .await
    }
}
