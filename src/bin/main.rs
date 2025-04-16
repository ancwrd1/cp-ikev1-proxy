use std::sync::Arc;

use clap::Parser;
use cp_ikev1_proxy::{ProxyParams, proxy::Ikev1Proxy};
use tracing::metadata::LevelFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let params = ProxyParams::parse();

    let args = std::env::args().collect::<Vec<_>>();
    if args.len() < 2 {
        anyhow::bail!("usage: {} <address>", args[0]);
    }

    if std::env::var("RUST_LOG").is_err() {
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(LevelFilter::DEBUG)
            .finish();
        tracing::subscriber::set_global_default(subscriber)?;
    } else {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish();
        tracing::subscriber::set_global_default(subscriber)?;
    }

    let proxy = Ikev1Proxy::new(Arc::new(params));
    proxy.run().await?;

    Ok(())
}
