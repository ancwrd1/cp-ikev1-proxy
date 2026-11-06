use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use isakmp::transport::IsakmpTransport;
use tokio::sync::Mutex;

type BoxedTransport<M> = Box<dyn IsakmpTransport<M> + Send + Sync>;

/// A cloneable handle to an ISAKMP transport.
/// It allows the proxy to share a single downstream connection between the `Ikev1Service`
/// and the code that relays raw messages which the service does not support (e.g. Quick Mode).
pub struct SharedTransport<M>(Arc<Mutex<BoxedTransport<M>>>);

impl<M> SharedTransport<M> {
    pub fn new(transport: BoxedTransport<M>) -> Self {
        Self(Arc::new(Mutex::new(transport)))
    }
}

impl<M> Clone for SharedTransport<M> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[async_trait]
impl<M: Send + Sync> IsakmpTransport<M> for SharedTransport<M> {
    async fn send(&mut self, message: &M) -> anyhow::Result<()> {
        self.0.lock().await.send(message).await
    }

    async fn receive(&mut self, timeout: Duration) -> anyhow::Result<M> {
        self.0.lock().await.receive(timeout).await
    }

    async fn send_receive(&mut self, message: &M, timeout: Duration) -> anyhow::Result<M>
    where
        M: Sync,
    {
        self.0.lock().await.send_receive(message, timeout).await
    }

    fn enable_keepalive(&mut self) {
        if let Ok(mut transport) = self.0.try_lock() {
            transport.enable_keepalive();
        }
    }

    fn disconnect(&mut self) {
        if let Ok(mut transport) = self.0.try_lock() {
            transport.disconnect();
        }
    }
}
