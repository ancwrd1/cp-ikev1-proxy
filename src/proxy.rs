use crate::https::HttpsProxy;
use crate::tcpt::TcptProxy;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

pub struct Ikev1Proxy {
    address: String,
}

impl Ikev1Proxy {
    pub fn new<S: AsRef<str>>(address: S) -> Ikev1Proxy {
        Self {
            address: address.as_ref().to_string(),
        }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let listener = TcpListener::bind("[::]:443").await?;

        debug!("Proxy started on port 443");

        while let Ok((upstream, address)) = listener.accept().await {
            debug!("Accepted connection from {}", address);

            let downstream_address = self.address.clone();
            tokio::spawn(async move {
                handle_new_connection(downstream_address, upstream)
                    .await
                    .inspect_err(|e| warn!("{}", e))
            });
        }
        Ok(())
    }
}

async fn handle_new_connection(
    downstream_address: String,
    upstream: TcpStream,
) -> anyhow::Result<()> {
    debug!("Connecting to {}", downstream_address);

    let downstream = TcpStream::connect(&format!("{}:443", downstream_address)).await?;

    debug!("Connected to {}", downstream_address);

    let mut buf = [0u8; 1];
    let size = upstream.peek(&mut buf[0..1]).await?;
    if size == 1 && buf[0] == 0 {
        debug!("Proxying TCPT connection to {}", downstream_address);

        TcptProxy::new(upstream, downstream).await?.run().await
    } else {
        debug!("Proxying HTTPS connection to {}", downstream_address);

        HttpsProxy::new(&downstream_address, upstream, downstream)
            .await?
            .run()
            .await
    }
}
