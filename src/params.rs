use std::{path::PathBuf, str::FromStr};

use anyhow::anyhow;
use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum CertType {
    #[default]
    None,
    Pkcs12,
    Pkcs8,
    Pkcs11,
}

impl FromStr for CertType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(CertType::None),
            "pkcs12" => Ok(CertType::Pkcs12),
            "pkcs8" => Ok(CertType::Pkcs8),
            "pkcs11" => Ok(CertType::Pkcs11),
            _ => Err(anyhow!("Invalid cert type!")),
        }
    }
}

#[derive(Parser)]
#[clap(about = "Check Point IKEv1 proxy VPN", name = "cp-ikev1-proxy", version = env!("CARGO_PKG_VERSION"))]
pub struct ProxyParams {
    #[clap(
        long = "cert-type",
        short = 'c',
        help = "Enable certificate authentication via the provided method, one of: pkcs8, pkcs11, pkcs12, none"
    )]
    pub cert_type: Option<CertType>,

    #[clap(
        long = "cert-path",
        short = 'p',
        help = "Path to PEM file for PKCS8, path to PFX file for PKCS12, path to driver file for PKCS11 token"
    )]
    pub cert_path: Option<PathBuf>,

    #[clap(
        long = "cert-password",
        short = 'a',
        help = "Password for PKCS12 file or PIN for PKCS11 token"
    )]
    pub cert_password: Option<String>,

    #[clap(long = "cert-id", short = 'i', help = "Certificate ID in hexadecimal form")]
    pub cert_id: Option<String>,

    #[clap(long = "no-mfa", short = 'n', help = "Disable multi-factor authentication")]
    pub no_mfa: bool,

    #[clap(help = "Downstream VPN server address")]
    pub server_address: String,
}
