use serde::{Deserialize, Serialize};

pub const CONTROL_PLANE_SCOPE: &str = "gateway.honeypot.control-plane";
pub const WATCH_SCOPE: &str = "gateway.honeypot.watch";
pub const STREAM_READ_SCOPE: &str = "gateway.honeypot.stream.read";
pub const SESSION_KILL_SCOPE: &str = "gateway.honeypot.session.kill";
pub const SYSTEM_KILL_SCOPE: &str = "gateway.honeypot.system.kill";
pub const COMMAND_PROPOSE_SCOPE: &str = "gateway.honeypot.command.propose";
pub const COMMAND_APPROVE_SCOPE: &str = "gateway.honeypot.command.approve";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    Service,
    Operator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorRole {
    Watch,
    Propose,
    Approve,
    Kill,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenScope {
    #[serde(rename = "gateway.honeypot.control-plane")]
    ControlPlane,
    #[serde(rename = "gateway.honeypot.watch")]
    Watch,
    #[serde(rename = "gateway.honeypot.stream.read")]
    StreamRead,
    #[serde(rename = "gateway.honeypot.session.kill")]
    SessionKill,
    #[serde(rename = "gateway.honeypot.system.kill")]
    SystemKill,
    #[serde(rename = "gateway.honeypot.command.propose")]
    CommandPropose,
    #[serde(rename = "gateway.honeypot.command.approve")]
    CommandApprove,
}

impl TokenScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ControlPlane => CONTROL_PLANE_SCOPE,
            Self::Watch => WATCH_SCOPE,
            Self::StreamRead => STREAM_READ_SCOPE,
            Self::SessionKill => SESSION_KILL_SCOPE,
            Self::SystemKill => SYSTEM_KILL_SCOPE,
            Self::CommandPropose => COMMAND_PROPOSE_SCOPE,
            Self::CommandApprove => COMMAND_APPROVE_SCOPE,
        }
    }
}
