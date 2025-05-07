use std::sync::Arc;

use clap::Parser;
use cp_ikev1_proxy::{params::ProxyParams, proxy::CheckPointProxy};
use tracing::metadata::LevelFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let params = ProxyParams::parse();

    init_logging()?;

    let proxy = CheckPointProxy::new(Arc::new(params));
    proxy.run().await?;

    Ok(())
}

fn init_logging() -> anyhow::Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        let subscriber = tracing_subscriber::fmt().with_max_level(LevelFilter::DEBUG).finish();
        tracing::subscriber::set_global_default(subscriber)?;
    } else {
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .finish();
        tracing::subscriber::set_global_default(subscriber)?;
    }
    Ok(())
}
