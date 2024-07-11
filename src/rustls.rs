/// This exposes a global cert pool which is required by multiple callbacks which have
/// no other mechanism of injecting external certificates.
use std::fs::File;
use std::sync::Once;
use std::path::PathBuf;

use reqwest::Certificate;

static INIT: Once = Once::new();
static mut CERT_POOL: Option<CertPool> = None;

pub struct CertPool {
    certs: Vec<Certificate>,
}

impl CertPool {
    pub fn certs(&self) -> &Vec<Certificate> {
        &self.certs
    }
}

pub fn init_cert_pool<P: Into<PathBuf>>(ca_path: Option<P>) {
    INIT.call_once(|| {
        let mut pool_certs: Vec<Certificate> = vec![];
        if let Some(ca_path) = ca_path {
            let ca_path: PathBuf = ca_path.into();
            // Load the certificate
            let mut ca_file = File::open(ca_path).expect("Failed to open CA cert file");
            let mut buf = Vec::new();
            ca_file
                .read_to_end(&mut buf)
                .expect("CA file could not be read");
            pool_certs.push(Certificate::from_pem(&buf).expect("Invalid certificate"));
        }
        unsafe {
            CERT_POOL = Some(CertPool { certs: pool_certs });
        }
    });
}

pub fn get_cert_pool() -> Option<&'static CertPool> {
    unsafe { CERT_POOL.as_ref() }
}
