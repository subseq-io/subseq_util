use base64::Engine;
use rand::{RngCore, rngs::OsRng};

#[inline]
pub fn generate_random_token(size: usize) -> Vec<u8> {
    let mut rng = OsRng::default();
    let mut bytes = vec![0; size];
    rng.fill_bytes(&mut bytes);
    bytes
}


#[inline]
pub fn to_base64(bytes: &[u8]) -> String {
    let engine = base64::engine::general_purpose::URL_SAFE;
    engine.encode(bytes)
}
