use std::env;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};

pub const HONEYPOT_HOST_SMOKE_ENV: &str = "DGW_HONEYPOT_HOST_SMOKE";
pub const HONEYPOT_LAB_E2E_ENV: &str = "DGW_HONEYPOT_LAB_E2E";
pub const HONEYPOT_TIER_GATE_ENV: &str = "DGW_HONEYPOT_TIER_GATE";
pub const HONEYPOT_RUNTIME_PROOF_STRICT_ENV: &str = "DGW_HONEYPOT_RUNTIME_PROOF_STRICT";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HoneypotTestTier {
    Contract,
    HostSmoke,
    LabE2e,
}

impl HoneypotTestTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Contract => "contract",
            Self::HostSmoke => "host-smoke",
            Self::LabE2e => "lab-e2e",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoneypotTierGate {
    pub contract_passed: bool,
    pub host_smoke_passed: bool,
}

impl HoneypotTierGate {
    pub fn is_ready_for_lab_e2e(&self) -> bool {
        self.contract_passed && self.host_smoke_passed
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoneypotTierSelection {
    pub active_tier: HoneypotTestTier,
    pub gate_path: Option<PathBuf>,
}

impl HoneypotTierSelection {
    pub fn from_env() -> Self {
        let host_smoke = env_var_truthy(HONEYPOT_HOST_SMOKE_ENV);
        let lab_e2e = env_var_truthy(HONEYPOT_LAB_E2E_ENV);

        let active_tier = if lab_e2e {
            HoneypotTestTier::LabE2e
        } else if host_smoke {
            HoneypotTestTier::HostSmoke
        } else {
            HoneypotTestTier::Contract
        };

        let gate_path = env::var_os(HONEYPOT_TIER_GATE_ENV).map(PathBuf::from);

        Self { active_tier, gate_path }
    }

    pub fn allows(&self, requested_tier: HoneypotTestTier) -> bool {
        self.active_tier >= requested_tier
    }

    pub fn require(&self, requested_tier: HoneypotTestTier) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.allows(requested_tier),
            "{} tier requested, but active tier is {}; set {} or {} to opt in",
            requested_tier.as_str(),
            self.active_tier.as_str(),
            HONEYPOT_HOST_SMOKE_ENV,
            HONEYPOT_LAB_E2E_ENV,
        );

        if requested_tier == HoneypotTestTier::LabE2e {
            let gate = self.load_gate().context("load honeypot tier gate")?;
            anyhow::ensure!(
                gate.is_ready_for_lab_e2e(),
                "lab-e2e tier requires contract_passed=true and host_smoke_passed=true in {}",
                HONEYPOT_TIER_GATE_ENV,
            );
        }

        Ok(())
    }

    pub fn require_runtime_proof(&self, requested_tier: HoneypotTestTier, strict: bool) -> anyhow::Result<()> {
        if !strict {
            return Ok(());
        }

        self.require(requested_tier)
            .with_context(|| format!("runtime-proof mode enabled by {HONEYPOT_RUNTIME_PROOF_STRICT_ENV}=1"))
    }

    pub fn load_gate(&self) -> anyhow::Result<HoneypotTierGate> {
        let gate_path = self
            .gate_path
            .as_deref()
            .context("lab-e2e tier requires a gate manifest path in DGW_HONEYPOT_TIER_GATE")?;

        load_honeypot_tier_gate(gate_path)
    }
}

pub fn active_honeypot_tier() -> HoneypotTestTier {
    HoneypotTierSelection::from_env().active_tier
}

pub fn require_honeypot_tier(requested_tier: HoneypotTestTier) -> anyhow::Result<()> {
    HoneypotTierSelection::from_env().require(requested_tier)
}

pub fn runtime_proof_strict_enabled() -> bool {
    env_var_truthy(HONEYPOT_RUNTIME_PROOF_STRICT_ENV)
}

pub fn require_runtime_proof_honeypot_tier(requested_tier: HoneypotTestTier) -> anyhow::Result<()> {
    HoneypotTierSelection::from_env().require_runtime_proof(requested_tier, runtime_proof_strict_enabled())
}

pub fn load_honeypot_tier_gate(path: &Path) -> anyhow::Result<HoneypotTierGate> {
    let data =
        std::fs::read_to_string(path).with_context(|| format!("read honeypot tier gate at {}", path.display()))?;
    let gate =
        serde_json::from_str(&data).with_context(|| format!("parse honeypot tier gate at {}", path.display()))?;
    Ok(gate)
}

fn env_var_truthy(name: &str) -> bool {
    env::var(name)
        .ok()
        .map(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}
