use std::{net::Ipv4Addr, time::Duration};

use anyhow::Context;
use bytes::{BufMut, Bytes, BytesMut};
use isakmp::model::AttributesPayloadType;
use isakmp::{
    certs::{ClientCertificate, Pkcs8Certificate},
    ikev1::{service::Ikev1Service, session::Ikev1Session},
    message::{IsakmpMessage, IsakmpMessageCodec},
    model::{
        CertificateType, ExchangeType, Identity, IdentityRequest, IdentityType, IsakmpFlags,
        NotifyMessageType, PayloadType, ProtocolId,
    },
    payload::{
        AttributesPayload, BasicPayload, CertificatePayload, IdentificationPayload, Payload,
        PayloadLike,
    },
    session::{IsakmpSession, SessionType},
};
use tracing::debug;

use crate::assets::{KEYSTORE, KEYSTORE_PASSWORD};

pub struct Ikev1SessionHandler {
    upstream_session: Ikev1Session,
    upstream_codec: Box<dyn IsakmpMessageCodec + Send + Sync>,
    downstream_service: Ikev1Service,
    downstream_message_id: u32,
}

impl Ikev1SessionHandler {
    pub fn new(service: Ikev1Service) -> anyhow::Result<Self> {
        let upstream_session = Ikev1Session::new(Identity::None, SessionType::Responder).unwrap();
        let upstream_codec = upstream_session.new_codec();

        Ok(Self {
            upstream_session,
            upstream_codec,
            downstream_service: service,
            downstream_message_id: 0,
        })
    }

    // message from the client
    pub async fn on_upstream_message(&mut self, data: Bytes) -> anyhow::Result<Vec<Bytes>> {
        let msg = self
            .upstream_codec
            .decode(&data)?
            .ok_or_else(|| anyhow::anyhow!("Invalid message"))?;

        if msg
            .payloads
            .iter()
            .any(|p| matches!(p, Payload::SecurityAssociation(_)))
        {
            debug!("<<< Upstream SA request");
            if msg.exchange_type == ExchangeType::IdentityProtection {
                return Ok(vec![self.handle_sa(msg).await?]);
            } else {
                return Ok(vec![self.handle_esp_sa(msg).await?]);
            }
        }

        if msg
            .payloads
            .iter()
            .any(|p| matches!(p, Payload::KeyExchange(_)))
        {
            debug!("<<< Upstream KE request");
            return Ok(vec![self.handle_ke(msg).await?]);
        }

        if msg
            .payloads
            .iter()
            .any(|p| matches!(p, Payload::Identification(_)))
        {
            debug!("<<< Upstream IDPROT request");
            return self.handle_id(msg).await;
        }

        if msg
            .payloads
            .iter()
            .any(|p| matches!(p, Payload::Attributes(_)))
        {
            debug!("<<< Upstream ATTR request");
            return Ok(vec![self.handle_attributes(msg).await?]);
        }

        Ok(Vec::new())
    }

    async fn handle_sa(&mut self, message: IsakmpMessage) -> anyhow::Result<Bytes> {
        let (proposal, response) = self.downstream_service.send_sa_proposal(message).await?;

        debug!(">>> Downstream SA response: {:#?}", response);

        self.downstream_service
            .session()
            .init_from_sa(proposal.clone())?;

        self.upstream_session.init_from_sa(proposal)?;

        Ok(self.upstream_codec.encode(&response))
    }

    async fn handle_esp_sa(&mut self, message: IsakmpMessage) -> anyhow::Result<Bytes> {
        debug!("<<< Upstream ESP SA request: {:?}", message);

        let attrs = self
            .downstream_service
            .do_esp_proposal(Ipv4Addr::new(127, 0, 0, 1), Duration::from_secs(3600))
            .await?;

        debug!(">>> Downstream ESP SA attributes response: {:#?}", attrs);

        Ok(Bytes::new())
    }

    async fn handle_ke(&mut self, message: IsakmpMessage) -> anyhow::Result<Bytes> {
        debug!("<<< Upstream KE request: {:#?}", message);

        self.downstream_service
            .do_key_exchange(Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED)
            .await?;

        let public_key_r = message
            .payloads
            .iter()
            .find_map(|p| match p {
                Payload::KeyExchange(ke) => Some(ke.data.clone()),
                _ => None,
            })
            .context("No KE in request!")?;

        let nonce_r = message
            .payloads
            .iter()
            .find_map(|p| match p {
                Payload::Nonce(ke) => Some(ke.data.clone()),
                _ => None,
            })
            .context("No nonce in request!")?;

        self.upstream_session.init_from_ke(public_key_r, nonce_r)?;

        self.build_ke_response()
    }

    async fn handle_id(&mut self, message: IsakmpMessage) -> anyhow::Result<Vec<Bytes>> {
        debug!("<<< Upstream IDPROT request: {:#?}", message);

        let Some(data) = message.payloads.iter().find_map(|payload| match payload {
            Payload::Notification(notify)
                if NotifyMessageType::from(notify.message_type) == NotifyMessageType::CccAuth =>
            {
                Some(notify.data.clone())
            }
            _ => None,
        }) else {
            anyhow::bail!("No auth blob");
        };

        debug!("Auth data: {}", String::from_utf8_lossy(&data));

        let request = IdentityRequest {
            auth_blob: String::from_utf8_lossy(&data).into_owned(),
            verify_certs: false,
            ca_certs: vec![],
            with_mfa: true,
        };

        let (response, message_id) = self
            .downstream_service
            .do_identity_protection(request)
            .await?;

        let mut result = Vec::new();

        result.push(self.build_id_response()?);

        if let Some(attributes) = response {
            result.push(self.build_attrs_response(attributes, message_id)?);
        }

        Ok(result)
    }

    async fn handle_attributes(&mut self, message: IsakmpMessage) -> anyhow::Result<Bytes> {
        debug!("<<< Upstream ATTR request: {:#?}", message);

        self.downstream_message_id = message.message_id;

        let Some(data) = message.payloads.iter().find_map(|p| match p {
            Payload::Attributes(data) => Some(data.clone()),
            _ => None,
        }) else {
            anyhow::bail!("No attributes payload");
        };

        if data.attributes_payload_type == AttributesPayloadType::Ack {
            self.downstream_service
                .send_ack_response(data.identifier, self.downstream_message_id)
                .await?;
            Ok(Bytes::new())
        } else {
            let attrs_payload = Payload::Attributes(data);

            let hash_payload = self
                .downstream_service
                .make_hash_from_payloads(self.downstream_message_id, &[&attrs_payload])?;

            let msg = IsakmpMessage {
                cookie_i: self.upstream_session.cookie_i(),
                cookie_r: self.upstream_session.cookie_r(),
                version: 0x10,
                exchange_type: ExchangeType::Transaction,
                flags: IsakmpFlags::ENCRYPTION,
                message_id: message.message_id,
                payloads: vec![hash_payload, attrs_payload],
            };

            debug!(">>> Downstream ATTR request: {:#?}", msg);

            let (attrs, message_id) = self
                .downstream_service
                .send_attribute_message(msg, Some(Duration::from_secs(5)))
                .await?;

            Ok(self.build_attrs_response(attrs, message_id)?)
        }
    }

    fn build_ke_response(&mut self) -> anyhow::Result<Bytes> {
        let ke = Payload::KeyExchange(self.upstream_session.responder().public_key.as_ref().into());
        let nonce = Payload::Nonce(self.upstream_session.responder().nonce.as_ref().into());

        let remote_ip: u32 = 0;

        let hash_r = self.upstream_session.hash(&[
            self.upstream_session.cookie_i().to_be_bytes().as_slice(),
            self.upstream_session.cookie_r().to_be_bytes().as_slice(),
            remote_ip.to_be_bytes().as_slice(),
            4500u16.to_be_bytes().as_slice(),
        ])?;

        let natd_r_payload = Payload::Natd(BasicPayload::new(hash_r));

        let local_ip: u32 = 0;

        let hash_i = self.upstream_session.hash(&[
            self.upstream_session.cookie_i().to_be_bytes().as_slice(),
            self.upstream_session.cookie_r().to_be_bytes().as_slice(),
            local_ip.to_be_bytes().as_slice(),
            &[0, 0],
        ])?;

        let natd_i_payload = Payload::Natd(BasicPayload::new(hash_i));

        let cert = Pkcs8Certificate::from_pkcs12(KEYSTORE, KEYSTORE_PASSWORD)?;

        let cert_payload = Payload::CertificateRequest(CertificatePayload {
            certificate_type: CertificateType::X509ForSignature,
            data: cert.issuer(),
        });

        let empty_cert_payload = Payload::CertificateRequest(CertificatePayload {
            certificate_type: CertificateType::X509ForSignature,
            data: Bytes::new(),
        });

        let payloads = vec![
            ke,
            nonce,
            cert_payload,
            empty_cert_payload,
            natd_r_payload,
            natd_i_payload,
        ];

        let msg = IsakmpMessage {
            cookie_i: self.upstream_session.cookie_i(),
            cookie_r: self.upstream_session.cookie_r(),
            version: 0x10,
            exchange_type: ExchangeType::IdentityProtection,
            flags: IsakmpFlags::empty(),
            message_id: 0,
            payloads,
        };

        Ok(self.upstream_codec.encode(&msg))
    }

    fn build_id_response(&mut self) -> anyhow::Result<Bytes> {
        // identification, signature, certs
        let cert = Pkcs8Certificate::from_pkcs12(KEYSTORE, KEYSTORE_PASSWORD)?;

        let id_payload = IdentificationPayload {
            id_type: IdentityType::Ipv4Address.into(),
            protocol_id: ProtocolId::Isakmp.into(),
            port: 0,
            data: Bytes::from_static(&[127, 0, 0, 1]),
        };

        let data = id_payload.to_bytes();
        let hash = self.upstream_session.hash_id_r(&data)?;
        let signature = cert.sign(&hash)?;

        let mut payloads = vec![Payload::Identification(id_payload)];
        for c in cert.certs() {
            payloads.push(Payload::Certificate(CertificatePayload {
                certificate_type: CertificateType::X509ForSignature,
                data: c,
            }));
        }
        payloads.push(Payload::Signature(BasicPayload { data: signature }));

        let msg = IsakmpMessage {
            cookie_i: self.upstream_session.cookie_i(),
            cookie_r: self.upstream_session.cookie_r(),
            version: 0x10,
            exchange_type: ExchangeType::IdentityProtection,
            flags: IsakmpFlags::ENCRYPTION,
            message_id: self.downstream_message_id,
            payloads,
        };

        Ok(self.upstream_codec.encode(&msg))
    }

    fn build_attrs_response(
        &mut self,
        attributes: AttributesPayload,
        message_id: u32,
    ) -> anyhow::Result<Bytes> {
        let attr_payload = Payload::Attributes(attributes);
        let hash_payload = self.make_hash_from_payloads(message_id, &[&attr_payload])?;

        let msg = IsakmpMessage {
            cookie_i: self.upstream_session.cookie_i(),
            cookie_r: self.upstream_session.cookie_r(),
            version: 0x10,
            exchange_type: ExchangeType::Transaction,
            flags: IsakmpFlags::ENCRYPTION,
            message_id,
            payloads: vec![hash_payload, attr_payload],
        };

        debug!("<<< Upstream ATTR response: {:#?}", msg);

        Ok(self.upstream_codec.encode(&msg))
    }

    fn make_hash_from_payloads(
        &self,
        message_id: u32,
        payloads: &[&Payload],
    ) -> anyhow::Result<Payload> {
        let mut buf = BytesMut::new();
        for (i, payload) in payloads.iter().enumerate() {
            let data = payload.to_bytes();
            let next_payload = payloads
                .get(i + 1)
                .map_or(PayloadType::None, |p| p.as_payload_type());
            buf.put_u8(next_payload.into());
            buf.put_u8(0);
            buf.put_u16(4 + data.len() as u16);
            buf.put_slice(&data);
        }
        let data = buf.freeze();

        let hash = self.upstream_session.prf(
            &self.upstream_session.session_keys().skeyid_a,
            &[message_id.to_be_bytes().as_slice(), &data],
        )?;

        Ok(Payload::Hash(BasicPayload::new(hash)))
    }
}
