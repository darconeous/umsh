//! The core logs with the `log` crate; the platform installs a
//! `MobileLogger` that hands each record to its own logging (`os_log` on
//! iOS, logcat on Android).
//!
//! A record's message is public. Values that could identify someone (an
//! address, a location, message text) are passed as key-value pairs,
//! `log::info!(address = address.as_str(); "...")`, and reach the platform
//! as private fields, which it redacts or leaves out. Nothing logs a key.

use std::sync::{Arc, PoisonError, RwLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum MobileLogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileLogField {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct MobileLogRecord {
    pub level: MobileLogLevel,
    /// The Rust module path, or the target the call named.
    pub target: String,
    pub message: String,
    /// Values the platform must treat as private.
    pub private_fields: Vec<MobileLogField>,
}

/// The platform's logging. Called on whichever thread logged, so it must
/// be thread-safe and must not throw.
#[uniffi::export(with_foreign)]
pub trait MobileLogger: Send + Sync {
    fn log(&self, record: MobileLogRecord);
}

/// Sends the core's log records to `logger` from now on, at `level` and
/// more severe. A later call replaces both.
#[uniffi::export]
pub fn set_logger(logger: Arc<dyn MobileLogger>, level: MobileLogLevel) {
    *LOGGER.write().unwrap_or_else(PoisonError::into_inner) = Some(logger);
    // Only the first call installs the bridge; the ones after it fail
    // because it is already there, which is what they want.
    let _ = log::set_logger(&Bridge);
    log::set_max_level(level.into());
}

static LOGGER: RwLock<Option<Arc<dyn MobileLogger>>> = RwLock::new(None);

struct Bridge;

impl log::Log for Bridge {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        let Some(logger) = LOGGER
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        else {
            return;
        };
        let mut fields = Fields(Vec::new());
        let _ = record.key_values().visit(&mut fields);
        logger.log(MobileLogRecord {
            level: record.level().into(),
            target: record.target().to_owned(),
            message: record.args().to_string(),
            private_fields: fields.0,
        });
    }

    fn flush(&self) {}
}

struct Fields(Vec<MobileLogField>);

impl<'kvs> log::kv::VisitSource<'kvs> for Fields {
    fn visit_pair(
        &mut self,
        key: log::kv::Key<'kvs>,
        value: log::kv::Value<'kvs>,
    ) -> Result<(), log::kv::Error> {
        self.0.push(MobileLogField {
            key: key.to_string(),
            value: value.to_string(),
        });
        Ok(())
    }
}

impl From<log::Level> for MobileLogLevel {
    fn from(level: log::Level) -> Self {
        match level {
            log::Level::Error => Self::Error,
            log::Level::Warn => Self::Warn,
            log::Level::Info => Self::Info,
            log::Level::Debug => Self::Debug,
            log::Level::Trace => Self::Trace,
        }
    }
}

impl From<MobileLogLevel> for log::LevelFilter {
    fn from(level: MobileLogLevel) -> Self {
        match level {
            MobileLogLevel::Error => Self::Error,
            MobileLogLevel::Warn => Self::Warn,
            MobileLogLevel::Info => Self::Info,
            MobileLogLevel::Debug => Self::Debug,
            MobileLogLevel::Trace => Self::Trace,
        }
    }
}

/// The one logger tests install, since the logger is process-wide and
/// tests run side by side. Each test picks its own records out by text.
#[cfg(test)]
pub(crate) mod capture {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    struct Capture(Mutex<Vec<MobileLogRecord>>);

    impl MobileLogger for Capture {
        fn log(&self, record: MobileLogRecord) {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(record);
        }
    }

    static CAPTURE: OnceLock<Arc<Capture>> = OnceLock::new();

    /// Starts capturing, at every level, if nothing has yet.
    pub(crate) fn install() {
        CAPTURE.get_or_init(|| {
            let capture = Arc::new(Capture(Mutex::new(Vec::new())));
            set_logger(capture.clone(), MobileLogLevel::Trace);
            capture
        });
    }

    /// Every record captured so far whose message contains `text`.
    pub(crate) fn containing(text: &str) -> Vec<MobileLogRecord> {
        install();
        CAPTURE
            .get()
            .map(|capture| {
                capture
                    .0
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .iter()
                    .filter(|record| record.message.contains(text))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_reaches_the_platform_with_its_values_private() {
        capture::install();
        let target = "umsh_mobile_core::logging::test";
        log::info!(target: target, address = "an-address", body = 7; "late echo");

        assert_eq!(
            capture::containing("late echo"),
            [MobileLogRecord {
                level: MobileLogLevel::Info,
                target: target.to_owned(),
                message: "late echo".to_owned(),
                private_fields: vec![
                    MobileLogField {
                        key: "address".to_owned(),
                        value: "an-address".to_owned(),
                    },
                    MobileLogField {
                        key: "body".to_owned(),
                        value: "7".to_owned(),
                    },
                ],
            }]
        );
    }
}
