//! Log trait for the CLI. The core crate does not depend on `tracing` or
//! `defmt`; callers that want either plug it in via the trait.

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

pub trait CliLogger {
    fn level(&self) -> LogLevel;
    fn set_level(&mut self, level: LogLevel);
    fn log(&mut self, level: LogLevel, args: core::fmt::Arguments<'_>);
}

#[macro_export]
macro_rules! cli_log {
    ($logger:expr, $level:expr, $($arg:tt)*) => {{
        let logger = &mut $logger;
        if logger.level() >= $level {
            logger.log($level, core::format_args!($($arg)*));
        }
    }};
}

/// Drops all log records. Useful in tests and on targets that don't want logs.
pub struct NullLogger {
    level: LogLevel,
}

impl NullLogger {
    pub const fn new() -> Self {
        NullLogger {
            level: LogLevel::Info,
        }
    }
}

impl Default for NullLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl CliLogger for NullLogger {
    fn level(&self) -> LogLevel {
        self.level
    }
    fn set_level(&mut self, level: LogLevel) {
        self.level = level;
    }
    fn log(&mut self, _level: LogLevel, _args: core::fmt::Arguments<'_>) {}
}
