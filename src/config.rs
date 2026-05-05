use anyhow::Result;
use serde::Deserialize;
use std::env;

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    /// Address to bind the API server
    pub bind_addr: String,
    /// Storage backend configuration
    pub storage: StorageConfig,
    /// CDC configuration
    pub cdc: CdcConfig,
    /// Optional directory to serve the admin UI from
    pub ui_dir: Option<String>,
    /// Hex-encoded 256-bit key-encryption key for genesis envelope encryption.
    /// When absent, genesis data is stored in plaintext (dev/test mode).
    pub kek: Option<String>,
    /// AWS KMS key ARN for DEK wrapping (requires `aws-kms` feature).
    pub kms_key_arn: Option<String>,
    /// Admin API bearer token. When set, all admin endpoints require
    /// `Authorization: Bearer <token>`. When absent, admin API is open (dev mode).
    pub admin_token: Option<String>,
    /// HashiCorp Vault server address (requires `vault` feature).
    pub vault_addr: Option<String>,
    /// Vault authentication token.
    pub vault_token: Option<String>,
    /// Vault Transit secret engine key name.
    pub vault_transit_key: Option<String>,
    /// External peat-mesh broker mappings that should be surfaced as live
    /// formation state inside the gateway.
    pub mesh_brokers: Vec<MeshBrokerMapping>,
    /// Poll interval for remote broker refreshes.
    pub mesh_poll_interval_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub enum StorageConfig {
    Redb { path: String },
    Postgres { url: String },
}

#[derive(Debug, Clone, Deserialize)]
pub struct CdcConfig {
    /// NATS server URL (if nats feature enabled)
    pub nats_url: Option<String>,
    /// Kafka broker list (if kafka feature enabled)
    pub kafka_brokers: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct MeshBrokerMapping {
    pub org_id: String,
    pub app_id: String,
    pub base_url: String,
    pub collections: Vec<String>,
}

impl GatewayConfig {
    pub fn from_env() -> Result<Self> {
        let storage = match env::var("PEAT_STORAGE_BACKEND")
            .unwrap_or_else(|_| "redb".into())
            .as_str()
        {
            "postgres" => {
                let url = env::var("PEAT_STORAGE_POSTGRES_URL")
                    .unwrap_or_else(|_| "postgres://peat:peat@localhost:5432/peat_gateway".into());
                StorageConfig::Postgres { url }
            }
            _ => {
                let data_dir =
                    env::var("PEAT_GATEWAY_DATA_DIR").unwrap_or_else(|_| "./data".into());
                let path = format!("{}/gateway.redb", data_dir);
                StorageConfig::Redb { path }
            }
        };

        Ok(Self {
            bind_addr: env::var("PEAT_GATEWAY_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into()),
            storage,
            cdc: CdcConfig {
                nats_url: env::var("PEAT_CDC_NATS_URL").ok(),
                kafka_brokers: env::var("PEAT_CDC_KAFKA_BROKERS").ok(),
            },
            ui_dir: env::var("PEAT_UI_DIR").ok(),
            admin_token: env::var("PEAT_ADMIN_TOKEN").ok(),
            kek: env::var("PEAT_KEK").ok(),
            kms_key_arn: env::var("PEAT_KMS_KEY_ARN").ok(),
            vault_addr: env::var("PEAT_VAULT_ADDR").ok(),
            vault_token: env::var("PEAT_VAULT_TOKEN").ok(),
            vault_transit_key: env::var("PEAT_VAULT_TRANSIT_KEY").ok(),
            mesh_brokers: parse_mesh_broker_mappings(env::var("PEAT_MESH_BROKERS").ok())?,
            mesh_poll_interval_ms: env::var("PEAT_MESH_POLL_INTERVAL_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5_000),
        })
    }
}

fn parse_mesh_broker_mappings(raw: Option<String>) -> Result<Vec<MeshBrokerMapping>> {
    let Some(raw) = raw else {
        return Ok(vec![]);
    };

    let mut mappings = Vec::new();
    for entry in raw.split(';').map(str::trim).filter(|s| !s.is_empty()) {
        let mut parts = entry.split('|').map(str::trim);
        let org_id = parts.next().filter(|s| !s.is_empty()).ok_or_else(|| {
            anyhow::anyhow!("missing org_id in PEAT_MESH_BROKERS entry '{entry}'")
        })?;
        let app_id = parts.next().filter(|s| !s.is_empty()).ok_or_else(|| {
            anyhow::anyhow!("missing app_id in PEAT_MESH_BROKERS entry '{entry}'")
        })?;
        let base_url = parts.next().filter(|s| !s.is_empty()).ok_or_else(|| {
            anyhow::anyhow!("missing base_url in PEAT_MESH_BROKERS entry '{entry}'")
        })?;
        let collections = parts
            .next()
            .map(|segment| {
                segment
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>()
            })
            .filter(|v| !v.is_empty())
            .unwrap_or_else(default_mesh_collections);

        mappings.push(MeshBrokerMapping {
            org_id: org_id.to_string(),
            app_id: app_id.to_string(),
            base_url: base_url.trim_end_matches('/').to_string(),
            collections,
        });
    }

    Ok(mappings)
}

fn default_mesh_collections() -> Vec<String> {
    vec![
        "cot-broadcast".into(),
        "contacts".into(),
        "markers".into(),
        "missions".into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mesh_broker_mappings() {
        let mappings = parse_mesh_broker_mappings(Some(
            "acme|mesh-a|http://127.0.0.1:9001|cot-broadcast,markers;bravo|mesh-b|http://mesh:8081|"
                .into(),
        ))
        .unwrap();

        assert_eq!(mappings.len(), 2);
        assert_eq!(mappings[0].org_id, "acme");
        assert_eq!(mappings[0].app_id, "mesh-a");
        assert_eq!(mappings[0].base_url, "http://127.0.0.1:9001");
        assert_eq!(mappings[0].collections, vec!["cot-broadcast", "markers"]);
        assert_eq!(mappings[1].collections, default_mesh_collections());
    }

    #[test]
    fn rejects_invalid_mesh_broker_entry() {
        let err = parse_mesh_broker_mappings(Some("acme|missing".into())).unwrap_err();
        assert!(err.to_string().contains("base_url"));
    }
}
