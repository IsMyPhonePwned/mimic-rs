//! Unit tests for mimic-web.

use super::*;
use mimic_core::ScanConfig;
use mimic_db::MimicDb;
use mimic_engine::MimicEngine;

#[test]
fn app_state_and_router_build() {
    let config = ScanConfig {
        signature_paths: vec![],
        ..ScanConfig::default()
    };
    let engine = MimicEngine::new(config).unwrap();
    let db = MimicDb::open_memory().unwrap();
    let state = AppState::new(engine, db, None);
    let _app = build_router(state);
}
