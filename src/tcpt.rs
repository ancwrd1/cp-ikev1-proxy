use futures_util::{SinkExt, stream::StreamExt};
use isakmp::{
    ikev1::{codec::Ikev1Codec, service::Ikev1Service, session::Ikev1Session},
    model::Identity,
    session::SessionType,
    transport::{TcptDataType, TcptTransport, tcpt::TcptTransportCodec},
};
use tokio::net::TcpStream;
use tokio_util::codec::Decoder;

use crate::session::Ikev1SessionHandler;

pub struct TcptProxy {
    upstream: TcpStream,
    handler: Ikev1SessionHandler,
}

impl TcptProxy {
    pub async fn new(mut upstream: TcpStream, mut downstream: TcpStream) -> anyhow::Result<Self> {
        let mut hs_upstream = TcptTransportCodec::new(TcptDataType::Cmd).framed(&mut upstream);

        let mut hs_downstream = TcptTransportCodec::new(TcptDataType::Cmd).framed(&mut downstream);

        let upstream_data = hs_upstream
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("upstream closed unexpectedly"))??;

        hs_downstream.send(upstream_data).await?;

        let downstream_data = hs_downstream
            .next()
            .await
            .ok_or_else(|| anyhow::anyhow!("downstream closed unexpectedly"))??;

        hs_upstream.send(downstream_data).await?;

        let session = Ikev1Session::new(Identity::None, SessionType::Initiator)?;
        let codec = Ikev1Codec::new(Box::new(session.clone()));
        let service = Ikev1Service::new(
            Box::new(TcptTransport::with_stream(
                TcptDataType::Ike,
                downstream,
                Box::new(codec),
            )),
            Box::new(session),
        )?;

        let session_handler = Ikev1SessionHandler::new(service)?;

        Ok(Self {
            upstream,
            handler: session_handler,
        })
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        let mut upstream_framed =
            TcptTransportCodec::new(TcptDataType::Ike).framed(&mut self.upstream);

        while let Some(Ok(msg)) = upstream_framed.next().await {
            for data in self.handler.on_upstream_message(msg).await? {
                if !data.is_empty() {
                    upstream_framed.send(data).await?;
                }
            }
        }

        Ok(())
    }
}
