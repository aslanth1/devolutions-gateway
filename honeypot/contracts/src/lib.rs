pub mod auth;
pub mod control_plane;
pub mod error;
pub mod events;
pub mod frontend;
pub mod stream;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedSchemaVersion {
    pub found: u32,
}

impl std::fmt::Display for UnsupportedSchemaVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unsupported honeypot schema_version {}", self.found)
    }
}

impl std::error::Error for UnsupportedSchemaVersion {}

pub trait Versioned {
    fn schema_version(&self) -> u32;

    fn ensure_supported_schema(&self) -> Result<(), UnsupportedSchemaVersion> {
        if self.schema_version() == SCHEMA_VERSION {
            Ok(())
        } else {
            Err(UnsupportedSchemaVersion {
                found: self.schema_version(),
            })
        }
    }
}

macro_rules! impl_versioned {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl crate::Versioned for $ty {
                fn schema_version(&self) -> u32 {
                    self.schema_version
                }
            }
        )+
    };
}

pub(crate) use impl_versioned;

#[cfg(test)]
mod tests;
