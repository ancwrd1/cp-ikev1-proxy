use crate::proxy::Ikev1Proxy;
use tracing::metadata::LevelFilter;

mod assets;
mod https;
mod proxy;
mod session;
mod sexpr;
mod tcpt;
mod util;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() < 2 {
        anyhow::bail!("usage: {} <address>", args[0]);
    }

    let subscriber = tracing_subscriber::fmt()
        .with_max_level(LevelFilter::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let proxy = Ikev1Proxy::new(&args[1]);
    proxy.run().await?;

    Ok(())
}
