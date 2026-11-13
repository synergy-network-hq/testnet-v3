use chrono::DateTime;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "trace" => Some(LogLevel::Trace),
            "debug" => Some(LogLevel::Debug),
            "info" => Some(LogLevel::Info),
            "warn" => Some(LogLevel::Warn),
            "error" => Some(LogLevel::Error),
            _ => None,
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            LogLevel::Trace => "TRACE".to_string(),
            LogLevel::Debug => "DEBUG".to_string(),
            LogLevel::Info => "INFO".to_string(),
            LogLevel::Warn => "WARN".to_string(),
            LogLevel::Error => "ERROR".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: u64,
    pub level: LogLevel,
    pub module: String,
    pub message: String,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug)]
pub struct Logger {
    level: LogLevel,
    enable_console: bool,
    log_file: String,
    max_file_size: u64,
    max_files: u32,
    entries: Arc<Mutex<Vec<LogEntry>>>,
}

impl Logger {
    pub fn new(
        level: LogLevel,
        enable_console: bool,
        log_file: String,
        max_file_size: u64,
        max_files: u32,
    ) -> Self {
        Logger {
            level,
            enable_console,
            log_file,
            max_file_size,
            max_files,
            entries: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn log(&self, level: LogLevel, module: &str, message: &str) {
        if self.should_log(&level) {
            let entry = LogEntry {
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                level: level.clone(),
                module: module.to_string(),
                message: message.to_string(),
                metadata: None,
            };

            // Add to in-memory buffer
            if let Ok(mut entries) = self.entries.lock() {
                entries.push(entry.clone());
            }

            // Write to console if enabled
            if self.enable_console {
                self.write_to_console(&entry);
            }

            // Write to file
            self.write_to_file(&entry);
        }
    }

    pub fn log_with_metadata(
        &self,
        level: LogLevel,
        module: &str,
        message: &str,
        metadata: serde_json::Value,
    ) {
        if self.should_log(&level) {
            let entry = LogEntry {
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                level: level.clone(),
                module: module.to_string(),
                message: message.to_string(),
                metadata: Some(metadata),
            };

            // Add to in-memory buffer
            if let Ok(mut entries) = self.entries.lock() {
                entries.push(entry.clone());
            }

            // Write to console if enabled
            if self.enable_console {
                self.write_to_console(&entry);
            }

            // Write to file
            self.write_to_file(&entry);
        }
    }

    fn should_log(&self, level: &LogLevel) -> bool {
        match (&self.level, level) {
            (LogLevel::Trace, _) => true,
            (LogLevel::Debug, LogLevel::Trace) => false,
            (LogLevel::Debug, _) => true,
            (LogLevel::Info, LogLevel::Trace) | (LogLevel::Info, LogLevel::Debug) => false,
            (LogLevel::Info, _) => true,
            (LogLevel::Warn, LogLevel::Trace)
            | (LogLevel::Warn, LogLevel::Debug)
            | (LogLevel::Warn, LogLevel::Info) => false,
            (LogLevel::Warn, _) => true,
            (LogLevel::Error, LogLevel::Error) => true,
            _ => false,
        }
    }

    fn write_to_console(&self, entry: &LogEntry) {
        let timestamp = DateTime::from_timestamp(entry.timestamp as i64, 0)
            .unwrap_or_default()
            .format("%Y-%m-%d %H:%M:%S UTC");

        let level_str = entry.level.to_string();
        let module = &entry.module;
        let message = &entry.message;

        println!("[{}] [{}] [{}] {}", timestamp, level_str, module, message);

        if let Some(metadata) = &entry.metadata {
            println!(
                "  Metadata: {}",
                serde_json::to_string_pretty(metadata).unwrap_or_default()
            );
        }
    }

    fn write_to_file(&self, entry: &LogEntry) {
        // Check if we need to rotate the log file
        if self.should_rotate() {
            if let Err(e) = self.rotate_logs() {
                eprintln!("Failed to rotate logs: {}", e);
            }
        }

        // Create directory if it doesn't exist
        if let Some(parent) = Path::new(&self.log_file).parent() {
            if !parent.exists() {
                if let Err(e) = fs::create_dir_all(parent) {
                    eprintln!("Failed to create log directory: {}", e);
                    return;
                }
            }
        }

        // Write to file
        let mut file = match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_file)
        {
            Ok(file) => file,
            Err(e) => {
                eprintln!("Failed to open log file: {}", e);
                return;
            }
        };

        let timestamp = DateTime::from_timestamp(entry.timestamp as i64, 0)
            .unwrap_or_default()
            .format("%Y-%m-%d %H:%M:%S UTC");

        let level_str = entry.level.to_string();
        let module = &entry.module;
        let message = &entry.message;

        let log_line = format!("[{}] [{}] [{}] {}\n", timestamp, level_str, module, message);

        if let Err(e) = file.write_all(log_line.as_bytes()) {
            eprintln!("Failed to write to log file: {}", e);
        }

        if let Some(metadata) = &entry.metadata {
            let metadata_line = format!(
                "  Metadata: {}\n",
                serde_json::to_string(metadata).unwrap_or_default()
            );
            if let Err(e) = file.write_all(metadata_line.as_bytes()) {
                eprintln!("Failed to write metadata to log file: {}", e);
            }
        }
    }

    fn should_rotate(&self) -> bool {
        if let Ok(metadata) = fs::metadata(&self.log_file) {
            metadata.len() > self.max_file_size
        } else {
            false
        }
    }

    fn rotate_logs(&self) -> io::Result<()> {
        let log_dir = Path::new(&self.log_file).parent().unwrap_or(Path::new("."));

        // Remove oldest log file if we exceed max_files
        let mut log_files: Vec<_> = fs::read_dir(log_dir)?
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let path = entry.path();
                if path.extension()?.to_str()? == "log" {
                    Some(path)
                } else {
                    None
                }
            })
            .collect();

        log_files.sort_by_key(|path| fs::metadata(path).and_then(|m| m.modified()).ok());

        if log_files.len() >= self.max_files as usize {
            for old_file in log_files
                .iter()
                .take(log_files.len() - (self.max_files as usize - 1))
            {
                fs::remove_file(old_file)?;
            }
        }

        // Rotate current log file
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let rotated_file = format!("{}.{}", self.log_file, timestamp);

        if Path::new(&self.log_file).exists() {
            fs::rename(&self.log_file, rotated_file)?;
        }

        Ok(())
    }

    pub fn get_entries(&self) -> Vec<LogEntry> {
        if let Ok(entries) = self.entries.lock() {
            entries.clone()
        } else {
            Vec::new()
        }
    }

    pub fn clear_entries(&self) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.clear();
        }
    }
}

// Global logger instance
lazy_static::lazy_static! {
    static ref LOGGER: Arc<Mutex<Option<Logger>>> = Arc::new(Mutex::new(None));
}

pub fn init_logger(
    level: LogLevel,
    enable_console: bool,
    log_file: String,
    max_file_size: u64,
    max_files: u32,
) {
    let logger = Logger::new(level, enable_console, log_file, max_file_size, max_files);

    if let Ok(mut global_logger) = LOGGER.lock() {
        *global_logger = Some(logger);
    }
}

pub fn log(level: LogLevel, module: &str, message: &str) {
    if let Ok(logger) = LOGGER.lock() {
        if let Some(ref logger) = *logger {
            logger.log(level, module, message);
        }
    }
}

pub fn log_with_metadata(
    level: LogLevel,
    module: &str,
    message: &str,
    metadata: serde_json::Value,
) {
    if let Ok(logger) = LOGGER.lock() {
        if let Some(ref logger) = *logger {
            logger.log_with_metadata(level, module, message, metadata);
        }
    }
}

#[macro_export]
macro_rules! trace {
    ($module:expr, $message:expr) => {
        $crate::logging::log($crate::logging::LogLevel::Trace, $module, $message)
    };
    ($module:expr, $message:expr, $($key:expr => $value:expr),*) => {{
        let mut metadata = serde_json::Map::new();
        $(
            metadata.insert($key.to_string(), serde_json::Value::from($value));
        )*
        $crate::logging::log_with_metadata(
            $crate::logging::LogLevel::Trace,
            $module,
            $message,
            serde_json::Value::Object(metadata)
        )
    }};
}

#[macro_export]
macro_rules! debug {
    ($module:expr, $message:expr) => {
        $crate::logging::log($crate::logging::LogLevel::Debug, $module, $message)
    };
    ($module:expr, $message:expr, $($key:expr => $value:expr),*) => {{
        let mut metadata = serde_json::Map::new();
        $(
            metadata.insert($key.to_string(), serde_json::Value::from($value));
        )*
        $crate::logging::log_with_metadata(
            $crate::logging::LogLevel::Debug,
            $module,
            $message,
            serde_json::Value::Object(metadata)
        )
    }};
}

#[macro_export]
macro_rules! info {
    ($module:expr, $message:expr) => {
        $crate::logging::log($crate::logging::LogLevel::Info, $module, $message)
    };
    ($module:expr, $message:expr, $($key:expr => $value:expr),*) => {{
        let mut metadata = serde_json::Map::new();
        $(
            metadata.insert($key.to_string(), serde_json::Value::from($value));
        )*
        $crate::logging::log_with_metadata(
            $crate::logging::LogLevel::Info,
            $module,
            $message,
            serde_json::Value::Object(metadata)
        )
    }};
}

#[macro_export]
macro_rules! warn {
    ($module:expr, $message:expr) => {
        $crate::logging::log($crate::logging::LogLevel::Warn, $module, $message)
    };
    ($module:expr, $message:expr, $($key:expr => $value:expr),*) => {{
        let mut metadata = serde_json::Map::new();
        $(
            metadata.insert($key.to_string(), serde_json::Value::from($value));
        )*
        $crate::logging::log_with_metadata(
            $crate::logging::LogLevel::Warn,
            $module,
            $message,
            serde_json::Value::Object(metadata)
        )
    }};
}

#[macro_export]
macro_rules! error {
    ($module:expr, $message:expr) => {
        $crate::logging::log($crate::logging::LogLevel::Error, $module, $message)
    };
    ($module:expr, $message:expr, $($key:expr => $value:expr),*) => {{
        let mut metadata = serde_json::Map::new();
        $(
            metadata.insert($key.to_string(), serde_json::Value::from($value));
        )*
        $crate::logging::log_with_metadata(
            $crate::logging::LogLevel::Error,
            $module,
            $message,
            serde_json::Value::Object(metadata)
        )
    }};
}
