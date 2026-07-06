//! Unit tests for mimic-vt.

use super::*;

#[test]
fn vt_config_hash_only_default_meaning() {
    let c = VtConfig {
        api_key: "key".into(),
        hash_only: true,
    };
    assert!(c.hash_only);
}

#[tokio::test]
async fn vt_lookup_empty_key_errors() {
    let client = VtClient::new(VtConfig {
        api_key: String::new(),
        hash_only: true,
    });
    let res = client.lookup_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").await;
    assert!(res.is_err());
}
