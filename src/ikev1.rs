use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use anyhow::Context;
use bytes::{BufMut, Bytes, BytesMut};
use isakmp::ikev1::message::Ikev1Message;
use isakmp::ikev1::model::{
    AttributesPayloadType, CertificateType, EspAttributeType, EspAuthAlgorithm, EspProposal, ExchangeType,
    IdentityRequest, IdentityType, IsakmpFlags, NotifyMessageType, PayloadType, ProtocolId, TransformId,
};
use isakmp::ikev1::payload::{AttributesPayload, CertificatePayload, IdentificationPayload, Payload};
use isakmp::{
    certs::{ClientCertificate, Pkcs8Certificate},
    ikev1::{service::Ikev1Service, session::Ikev1Session},
    message::IsakmpMessageCodec,
    model::Identity,
    payload::{BasicPayload, PayloadLike},
    session::{IsakmpSession, SessionType},
    transport::IsakmpTransport,
};
use tracing::{debug, warn};

use crate::{
    assets::{KEYSTORE, KEYSTORE_PASSWORD},
    params::ProxyParams,
    transport::SharedTransport,
};

const QUICK_MODE_TIMEOUT: Duration = Duration::from_secs(10);

/// State of the ESP SA (Quick Mode) exchange which is in progress
struct QuickModeState {
    message_id: u32,
    spi_i: u32,
    nonce_i: Bytes,
    spi_r: u32,
    nonce_r: Bytes,
    transform_id: TransformId,
    auth_alg: EspAuthAlgorithm,
    key_len: usize,
}

impl QuickModeState {
    fn to_esp_proposal(&self) -> EspProposal {
        EspProposal {
            spi_i: self.spi_i,
            nonce_i: self.nonce_i.clone(),
            spi_r: self.spi_r,
            nonce_r: self.nonce_r.clone(),
            transform_id: self.transform_id,
            auth_alg: self.auth_alg,
            key_len: self.key_len,
        }
    }
}

pub struct Ikev1SessionHandler {
    upstream_session: Ikev1Session,
    upstream_codec: Box<dyn IsakmpMessageCodec<Ikev1Message> + Send + Sync>,
    downstream_service: Ikev1Service,
    downstream_session: Ikev1Session,
    downstream_transport: SharedTransport<Ikev1Message>,
    downstream_message_id: u32,
    quick_mode: Option<QuickModeState>,
    params: Arc<ProxyParams>,
}

impl Ikev1SessionHandler {
    pub fn new(
        params: Arc<ProxyParams>,
        mut service: Ikev1Service,
        downstream_transport: SharedTransport<Ikev1Message>,
    ) -> anyhow::Result<Self> {
        let upstream_session = Ikev1Session::new(Identity::None, SessionType::Responder).unwrap();
        let upstream_codec = upstream_session.new_codec();

        Ok(Self {
            upstream_session,
            upstream_codec,
            downstream_session: service.session().clone(),
            downstream_service: service,
            downstream_transport,
            downstream_message_id: 0,
            quick_mode: None,
            params,
        })
    }

    // message from the client
    pub async fn on_upstream_message(&mut self, data: Bytes) -> anyhow::Result<Vec<Bytes>> {
        let msg = self
            .upstream_codec
            .decode(&data)?
            .ok_or_else(|| anyhow::anyhow!("Invalid message"))?;

        if msg.exchange_type == ExchangeType::Quick {
            if msg
                .payloads
                .iter()
                .any(|p| matches!(p, Payload::SecurityAssociation(_)))
            {
                debug!("<<< Upstream ESP SA request");
                return Ok(vec![self.handle_esp_sa(msg).await?]);
            } else {
                debug!("<<< Upstream ESP SA confirmation");
                self.handle_esp_sa_confirmation(msg).await?;
                return Ok(Vec::new());
            }
        }

        if msg
            .payloads
            .iter()
            .any(|p| matches!(p, Payload::SecurityAssociation(_)))
        {
            debug!("<<< Upstream SA request");
            return Ok(vec![self.handle_sa(msg).await?]);
        }

        if msg.payloads.iter().any(|p| matches!(p, Payload::KeyExchange(_))) {
            debug!("<<< Upstream KE request");
            return Ok(vec![self.handle_ke(msg).await?]);
        }

        if msg.payloads.iter().any(|p| matches!(p, Payload::Identification(_))) {
            debug!("<<< Upstream IDPROT request");
            return self.handle_id(msg).await;
        }

        if msg.payloads.iter().any(|p| matches!(p, Payload::Attributes(_))) {
            debug!("<<< Upstream ATTR request");
            return Ok(vec![self.handle_attributes(msg).await?]);
        }

        Ok(Vec::new())
    }

    async fn handle_sa(&mut self, message: Ikev1Message) -> anyhow::Result<Bytes> {
        debug!("<<< Upstream SA request: {:#?}", message);

        let (proposal, response) = self.downstream_service.send_sa_proposal(message).await?;

        debug!(">>> Downstream SA response: {:#?}", response);

        self.downstream_service.session().init_from_sa(proposal.clone())?;

        self.upstream_session.init_from_sa(proposal)?;

        self.upstream_codec.encode(&response)
    }

    // Quick Mode message 1: HASH(1), SA, Ni [, KE] [, IDci, IDcr]
    async fn handle_esp_sa(&mut self, message: Ikev1Message) -> anyhow::Result<Bytes> {
        debug!("<<< Upstream ESP SA request: {:#?}", message);

        let message_id = message.message_id;
        let (hash_i, payloads) = split_hash(message.payloads)?;

        // HASH(1) = prf(SKEYID_a, M-ID | SA | Ni [ | KE ] [ | IDci | IDcr ])
        verify_hash(
            "upstream HASH(1)",
            &hash_i,
            &quick_mode_hash(&self.upstream_session, &[&message_id.to_be_bytes()], &payloads)?,
        );

        let nonce_i = find_nonce(&payloads).context("No nonce in ESP SA request!")?;
        let spi_i = find_proposal_spi(&payloads).context("No SPI in ESP SA request!")?;

        debug!("ESP SA initiator SPI: {:08x}", spi_i);

        let hash_payload = Payload::Hash(BasicPayload::new(quick_mode_hash(
            &self.downstream_session,
            &[&message_id.to_be_bytes()],
            &payloads,
        )?));

        let request = Ikev1Message {
            initiator_spi: self.downstream_session.initiator_spi(),
            responder_spi: self.downstream_session.responder_spi(),
            version: 0x10,
            exchange_type: ExchangeType::Quick,
            flags: IsakmpFlags::ENCRYPTION,
            message_id,
            payloads: std::iter::once(hash_payload).chain(payloads).collect(),
        };

        debug!(">>> Downstream ESP SA request: {:#?}", request);

        let response = self
            .downstream_transport
            .send_receive(&request, QUICK_MODE_TIMEOUT)
            .await?;

        debug!(">>> Downstream ESP SA response: {:#?}", response);

        if response.exchange_type != ExchangeType::Quick || response.message_id != message_id {
            anyhow::bail!(
                "Unexpected ESP SA response: exchange type {:?}, message ID {:08x}",
                response.exchange_type,
                response.message_id
            );
        }

        let (hash_r, payloads) = split_hash(response.payloads)?;

        // HASH(2) = prf(SKEYID_a, M-ID | Ni_b | SA | Nr [ | KE ] [ | IDci | IDcr ])
        verify_hash(
            "downstream HASH(2)",
            &hash_r,
            &quick_mode_hash(
                &self.downstream_session,
                &[&message_id.to_be_bytes(), &nonce_i],
                &payloads,
            )?,
        );

        let nonce_r = find_nonce(&payloads).context("No nonce in ESP SA response!")?;
        let spi_r = find_proposal_spi(&payloads).context("No SPI in ESP SA response!")?;
        let (transform_id, auth_alg, key_len) = parse_esp_transform(&payloads)?;

        debug!(
            "Negotiated ESP SA: responder SPI: {:08x}, transform: {:?}, auth: {:?}, key length: {}",
            spi_r, transform_id, auth_alg, key_len
        );

        self.quick_mode = Some(QuickModeState {
            message_id,
            spi_i,
            nonce_i: nonce_i.clone(),
            spi_r,
            nonce_r,
            transform_id,
            auth_alg,
            key_len,
        });

        let hash_payload = Payload::Hash(BasicPayload::new(quick_mode_hash(
            &self.upstream_session,
            &[&message_id.to_be_bytes(), &nonce_i],
            &payloads,
        )?));

        let msg = Ikev1Message {
            initiator_spi: self.upstream_session.initiator_spi(),
            responder_spi: self.upstream_session.responder_spi(),
            version: 0x10,
            exchange_type: ExchangeType::Quick,
            flags: IsakmpFlags::ENCRYPTION,
            message_id,
            payloads: std::iter::once(hash_payload).chain(payloads).collect(),
        };

        debug!("<<< Upstream ESP SA response: {:#?}", msg);

        self.upstream_codec.encode(&msg)
    }

    // Quick Mode message 3: HASH(3)
    async fn handle_esp_sa_confirmation(&mut self, message: Ikev1Message) -> anyhow::Result<()> {
        debug!("<<< Upstream ESP SA confirmation: {:#?}", message);

        let Some(state) = self.quick_mode.take_if(|qm| qm.message_id == message.message_id) else {
            anyhow::bail!(
                "No ESP SA exchange in progress for message ID {:08x}",
                message.message_id
            );
        };

        let (hash, _) = split_hash(message.payloads)?;

        // HASH(3) = prf(SKEYID_a, 0 | M-ID | Ni_b | Nr_b)
        let hash3 = |session: &Ikev1Session| {
            session.prf(
                &session.session_keys().skeyid_a,
                &[&[0], &state.message_id.to_be_bytes(), &state.nonce_i, &state.nonce_r],
            )
        };

        verify_hash("upstream HASH(3)", &hash, &hash3(&self.upstream_session)?);

        let msg = Ikev1Message {
            initiator_spi: self.downstream_session.initiator_spi(),
            responder_spi: self.downstream_session.responder_spi(),
            version: 0x10,
            exchange_type: ExchangeType::Quick,
            flags: IsakmpFlags::ENCRYPTION,
            message_id: state.message_id,
            payloads: vec![Payload::Hash(BasicPayload::new(hash3(&self.downstream_session)?))],
        };

        debug!(">>> Downstream ESP SA confirmation: {:#?}", msg);

        self.downstream_transport.send(&msg).await?;

        let proposal = state.to_esp_proposal();
        self.upstream_session.init_from_qm(proposal.clone())?;
        self.downstream_session.init_from_qm(proposal)?;

        log_esp_keys("Upstream (client <-> proxy)", &self.upstream_session, state.spi_i);
        log_esp_keys("Downstream (proxy <-> gateway)", &self.downstream_session, state.spi_i);

        Ok(())
    }

    async fn handle_ke(&mut self, message: Ikev1Message) -> anyhow::Result<Bytes> {
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

    async fn handle_id(&mut self, message: Ikev1Message) -> anyhow::Result<Vec<Bytes>> {
        debug!("<<< Upstream IDPROT request: {:#?}", message);

        let Some(data) = message.payloads.iter().find_map(|payload| match payload {
            Payload::Notification(notify) if notify.message_type == NotifyMessageType::CccAuth => {
                Some(notify.data.clone())
            }
            _ => None,
        }) else {
            anyhow::bail!("No auth blob");
        };

        debug!("Auth data: {}", String::from_utf8_lossy(&data));

        let request = IdentityRequest {
            auth_blob: String::from_utf8_lossy(&data).into_owned(),
            internal_ca_fingerprints: vec![],
            with_mfa: !self.params.no_mfa,
        };

        let (response, message_id) = self.downstream_service.do_identity_protection(request).await?;

        let mut result = Vec::new();

        result.push(self.build_id_response()?);

        if let Some(attributes) = response {
            result.push(self.build_attrs_response(attributes, message_id)?);
        }

        Ok(result)
    }

    async fn handle_attributes(&mut self, message: Ikev1Message) -> anyhow::Result<Bytes> {
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

            let msg = Ikev1Message {
                initiator_spi: self.upstream_session.initiator_spi(),
                responder_spi: self.upstream_session.responder_spi(),
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
            self.upstream_session.initiator_spi().to_be_bytes().as_slice(),
            self.upstream_session.responder_spi().to_be_bytes().as_slice(),
            remote_ip.to_be_bytes().as_slice(),
            4500u16.to_be_bytes().as_slice(),
        ])?;

        let natd_r_payload = Payload::Natd(BasicPayload::new(hash_r));

        let local_ip: u32 = 0;

        let hash_i = self.upstream_session.hash(&[
            self.upstream_session.initiator_spi().to_be_bytes().as_slice(),
            self.upstream_session.responder_spi().to_be_bytes().as_slice(),
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

        let msg = Ikev1Message {
            initiator_spi: self.upstream_session.initiator_spi(),
            responder_spi: self.upstream_session.responder_spi(),
            version: 0x10,
            exchange_type: ExchangeType::IdentityProtection,
            flags: IsakmpFlags::empty(),
            message_id: 0,
            payloads,
        };

        self.upstream_codec.encode(&msg)
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
        payloads.push(Payload::Signature(BasicPayload {
            data: signature,
            sensitive: false,
        }));

        let msg = Ikev1Message {
            initiator_spi: self.upstream_session.initiator_spi(),
            responder_spi: self.upstream_session.responder_spi(),
            version: 0x10,
            exchange_type: ExchangeType::IdentityProtection,
            flags: IsakmpFlags::ENCRYPTION,
            message_id: self.downstream_message_id,
            payloads,
        };

        self.upstream_codec.encode(&msg)
    }

    fn build_attrs_response(&mut self, attributes: AttributesPayload, message_id: u32) -> anyhow::Result<Bytes> {
        let attr_payload = Payload::Attributes(attributes);
        let hash_payload = self.make_hash_from_payloads(message_id, &[&attr_payload])?;

        let msg = Ikev1Message {
            initiator_spi: self.upstream_session.initiator_spi(),
            responder_spi: self.upstream_session.responder_spi(),
            version: 0x10,
            exchange_type: ExchangeType::Transaction,
            flags: IsakmpFlags::ENCRYPTION,
            message_id,
            payloads: vec![hash_payload, attr_payload],
        };

        debug!("<<< Upstream ATTR response: {:#?}", msg);

        self.upstream_codec.encode(&msg)
    }

    fn make_hash_from_payloads(&self, message_id: u32, payloads: &[&Payload]) -> anyhow::Result<Payload> {
        let hash = self.upstream_session.prf(
            &self.upstream_session.session_keys().skeyid_a,
            &[message_id.to_be_bytes().as_slice(), &serialize_payloads(payloads)],
        )?;

        Ok(Payload::Hash(BasicPayload::new(hash)))
    }
}

// Serialize payloads with generic headers, as they appear on the wire
fn serialize_payloads(payloads: &[&Payload]) -> Bytes {
    let mut buf = BytesMut::new();
    for (i, payload) in payloads.iter().enumerate() {
        let data = payload.to_bytes();
        let next_payload = payloads.get(i + 1).map_or(PayloadType::None, |p| p.as_payload_type());
        buf.put_u8(next_payload.into());
        buf.put_u8(0);
        buf.put_u16(4 + data.len() as u16);
        buf.put_slice(&data);
    }
    buf.freeze()
}

// prf(SKEYID_a, prefix | payloads)
fn quick_mode_hash(session: &Ikev1Session, prefix: &[&[u8]], payloads: &[Payload]) -> anyhow::Result<Bytes> {
    let data = serialize_payloads(&payloads.iter().collect::<Vec<_>>());
    let input = prefix
        .iter()
        .copied()
        .chain(std::iter::once(data.as_ref()))
        .collect::<Vec<_>>();
    session.prf(&session.session_keys().skeyid_a, &input)
}

fn verify_hash(name: &str, received: &[u8], computed: &[u8]) {
    if received == computed {
        debug!("{} verification succeeded", name);
    } else {
        warn!(
            "{} verification failed! received: {}, computed: {}",
            name,
            hex::encode(received),
            hex::encode(computed)
        );
    }
}

// Split the leading HASH payload from the rest of the payloads
fn split_hash(mut payloads: Vec<Payload>) -> anyhow::Result<(Bytes, Vec<Payload>)> {
    match payloads.first() {
        Some(Payload::Hash(hash)) => {
            let hash = hash.data.clone();
            payloads.remove(0);
            Ok((hash, payloads))
        }
        _ => anyhow::bail!("No leading HASH payload in Quick Mode message!"),
    }
}

fn find_nonce(payloads: &[Payload]) -> Option<Bytes> {
    payloads.iter().find_map(|p| match p {
        Payload::Nonce(nonce) => Some(nonce.data.clone()),
        _ => None,
    })
}

fn find_proposal_spi(payloads: &[Payload]) -> Option<u32> {
    payloads.iter().find_map(|p| match p {
        Payload::SecurityAssociation(sa) => sa.payloads.iter().find_map(|p| match p {
            Payload::Proposal(proposal) => proposal.spi.as_ref().try_into().ok().map(u32::from_be_bytes),
            _ => None,
        }),
        _ => None,
    })
}

// Returns the transform ID, auth algorithm and encryption key length in bytes of the selected transform
fn parse_esp_transform(payloads: &[Payload]) -> anyhow::Result<(TransformId, EspAuthAlgorithm, usize)> {
    let transform = payloads
        .iter()
        .find_map(|p| match p {
            Payload::SecurityAssociation(sa) => sa.payloads.iter().find_map(|p| match p {
                Payload::Proposal(proposal) => proposal.transforms.first(),
                _ => None,
            }),
            _ => None,
        })
        .context("No transform in ESP SA response!")?;

    let find_attr = |attr: EspAttributeType| {
        transform
            .attributes
            .iter()
            .find(|a| a.attribute_type == u16::from(attr))
            .and_then(|a| a.as_short())
    };

    let auth_alg: EspAuthAlgorithm = find_attr(EspAttributeType::AuthenticationAlgorithm)
        .context("No auth algorithm in ESP SA response!")?
        .into();

    let key_len = if transform.transform_id == TransformId::EspAesCbc {
        find_attr(EspAttributeType::KeyLength).unwrap_or(128) as usize / 8
    } else {
        // 3DES key length
        24
    };

    Ok((transform.transform_id, auth_alg, key_len))
}

fn log_esp_keys(name: &str, session: &Ikev1Session, spi_i: u32) {
    for material in [session.esp_in(), session.esp_out()] {
        // packets carrying the initiator's SPI are sent from the responder to the initiator
        let direction = if material.spi == spi_i {
            "responder -> initiator"
        } else {
            "initiator -> responder"
        };
        debug!(
            "{} ESP SA [{}]: SPI: {:08x}, cipher: {:?}, auth: {:?}, ENC key: {}, AUTH key: {}",
            name,
            direction,
            material.spi,
            material.cipher,
            material.auth,
            hex::encode(&material.sk_e),
            hex::encode(&material.sk_a)
        );
    }
}
