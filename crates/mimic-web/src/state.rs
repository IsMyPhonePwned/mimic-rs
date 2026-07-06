use mimic_db::MimicDb;
use mimic_engine::MimicEngine;
use mimic_vt::{VtClient, VtConfig};
use std::sync::Arc;

pub struct AppState {
    pub engine: Arc<MimicEngine>,
    pub db: Arc<MimicDb>,
    pub vt: Option<Arc<VtClient>>,
}

impl AppState {
    pub fn new(engine: MimicEngine, db: MimicDb, vt_config: Option<VtConfig>) -> Self {
        let vt = vt_config
            .filter(|c| !c.api_key.is_empty())
            .map(|c| Arc::new(VtClient::new(c)));
        Self {
            engine: Arc::new(engine),
            db: Arc::new(db),
            vt,
        }
    }
}
