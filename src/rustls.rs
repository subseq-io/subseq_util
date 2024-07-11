/// This exposes a global cert pool which is required by multiple callbacks which have
/// no other mechanism of injecting external certificates.
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Once;

use reqwest::Certificate;
use rustls::pki_types::CertificateDer;

static INIT: Once = Once::new();
static mut CERT_POOL: Option<CertPool> = None;

pub struct CertPool {
    certs: Vec<Certificate>,
    der_certs: Vec<CertificateDer<'static>>,
}

impl CertPool {
    pub fn certs(&self) -> &Vec<Certificate> {
        &self.certs
    }

    pub fn der_certs(&self) -> &Vec<CertificateDer<'static>> {
        &self.der_certs
    }
}

pub fn init_cert_pool<P: Into<PathBuf>>(ca_path: Option<P>) {
    INIT.call_once(|| {
        let mut certs: Vec<_> = vec![];
        let mut der_certs: Vec<_> = vec![];

        if let Some(ca_path) = ca_path {
            let ca_path: PathBuf = ca_path.into();
            // Load the certificate
            let mut ca_file = File::open(ca_path).expect("Failed to open CA cert file");
            let mut buf = Vec::new();
            ca_file
                .read_to_end(&mut buf)
                .expect("CA file could not be read");

            certs.push(Certificate::from_pem(&buf).expect("Invalid certificate"));
            for cert in rustls_pemfile::certs(&mut &buf[..]) {
                if let Ok(cert) = cert {
                    der_certs.push(cert);
                }
            }
        }
        unsafe {
            CERT_POOL = Some(CertPool { certs, der_certs });
        }
    });
}

pub fn get_cert_pool() -> Option<&'static CertPool> {
    unsafe { CERT_POOL.as_ref() }
}
