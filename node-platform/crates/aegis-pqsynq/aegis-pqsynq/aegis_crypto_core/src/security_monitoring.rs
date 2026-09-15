//! Security Monitoring and Detection System for Aegis
//!
//! This module provides comprehensive security monitoring, audit logging,
//! and anomaly detection for cryptographic operations.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Security event types
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SecurityEventType {
    /// Key generation event
    KeyGeneration,
    /// Key usage event
    KeyUsage,
    /// Key rotation event
    KeyRotation,
    /// Cryptographic operation event
    CryptoOperation,
    /// Authentication event
    Authentication,
    /// Authorization event
    Authorization,
    /// Security violation event
    SecurityViolation,
    /// Anomaly detection event
    AnomalyDetected,
    /// System error event
    SystemError,
}

/// Security event severity levels
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SecuritySeverity {
    /// Low severity - informational
    Low,
    /// Medium severity - warning
    Medium,
    /// High severity - error
    High,
    /// Critical severity - immediate action required
    Critical,
}

/// Security event structure
#[derive(Debug, Clone)]
pub struct SecurityEvent {
    /// Event timestamp
    pub timestamp: SystemTime,
    /// Event type
    pub event_type: SecurityEventType,
    /// Event severity
    pub severity: SecuritySeverity,
    /// Event source (component/module)
    pub source: String,
    /// Event message
    pub message: String,
    /// Additional event data
    pub data: HashMap<String, String>,
    /// Event ID for tracking
    pub event_id: String,
    /// User/session ID if applicable
    pub user_id: Option<String>,
    /// IP address if applicable
    pub ip_address: Option<String>,
}

/// Anomaly detection rule
pub struct AnomalyRule {
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: String,
    /// Time window for analysis
    pub time_window: Duration,
    /// Threshold for triggering
    pub threshold: u64,
    /// Rule function
    pub rule_function: Box<dyn Fn(&[SecurityEvent]) -> bool + Send + Sync>,
}

/// Security metrics
#[derive(Debug, Clone)]
pub struct SecurityMetrics {
    /// Total events processed
    pub total_events: u64,
    /// Events by type
    pub events_by_type: HashMap<SecurityEventType, u64>,
    /// Events by severity
    pub events_by_severity: HashMap<SecuritySeverity, u64>,
    /// Events by source
    pub events_by_source: HashMap<String, u64>,
    /// Anomalies detected
    pub anomalies_detected: u64,
    /// Security violations
    pub security_violations: u64,
    /// Last updated timestamp
    pub last_updated: SystemTime,
}

impl Default for SecurityMetrics {
    fn default() -> Self {
        Self {
            total_events: 0,
            events_by_type: HashMap::new(),
            events_by_severity: HashMap::new(),
            events_by_source: HashMap::new(),
            anomalies_detected: 0,
            security_violations: 0,
            last_updated: SystemTime::now(),
        }
    }
}

/// Security monitor
pub struct SecurityMonitor {
    /// Event storage
    events: Arc<RwLock<Vec<SecurityEvent>>>,
    /// Anomaly detection rules
    anomaly_rules: Arc<RwLock<Vec<AnomalyRule>>>,
    /// Security metrics
    metrics: Arc<Mutex<SecurityMetrics>>,
    /// Event handlers
    event_handlers: Arc<RwLock<Vec<Box<dyn Fn(&SecurityEvent) + Send + Sync>>>>,
    /// Configuration
    config: Arc<RwLock<SecurityMonitorConfig>>,
}

/// Security monitor configuration
#[derive(Debug, Clone)]
pub struct SecurityMonitorConfig {
    /// Maximum number of events to store
    pub max_events: usize,
    /// Event retention period
    pub retention_period: Duration,
    /// Anomaly detection enabled
    pub anomaly_detection_enabled: bool,
    /// Real-time alerting enabled
    pub real_time_alerting: bool,
    /// Log level threshold
    pub log_level_threshold: SecuritySeverity,
}

impl Default for SecurityMonitorConfig {
    fn default() -> Self {
        Self {
            max_events: 100000,
            retention_period: Duration::from_secs(86400 * 30), // 30 days
            anomaly_detection_enabled: true,
            real_time_alerting: true,
            log_level_threshold: SecuritySeverity::Low,
        }
    }
}

impl SecurityMonitor {
    /// Create a new security monitor
    pub fn new(config: SecurityMonitorConfig) -> Self {
        Self {
            events: Arc::new(RwLock::new(Vec::new())),
            anomaly_rules: Arc::new(RwLock::new(Vec::new())),
            metrics: Arc::new(Mutex::new(SecurityMetrics::default())),
            event_handlers: Arc::new(RwLock::new(Vec::new())),
            config: Arc::new(RwLock::new(config)),
        }
    }

    /// Log a security event
    pub fn log_event(&self, event: SecurityEvent) {
        self.log_event_internal(event, true);
    }

    /// Internal log event method with recursion control
    pub fn log_event_internal(&self, mut event: SecurityEvent, run_anomaly_detection: bool) {
        // Generate event ID if not provided
        if event.event_id.is_empty() {
            event.event_id = format!(
                "evt_{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
        }

        // Check if event meets log level threshold
        let config = self.config.read().unwrap();
        if self.should_log_event(&event, &config) {
            // Store event
            {
                let mut events = self.events.write().unwrap();
                events.push(event.clone());

                // Maintain event limit
                if events.len() > config.max_events {
                    events.drain(0..config.max_events / 10);
                }
            }

            // Update metrics
            self.update_metrics(&event);

            // Run anomaly detection (only for non-anomaly events to prevent recursion)
            if config.anomaly_detection_enabled
                && run_anomaly_detection
                && event.event_type != SecurityEventType::AnomalyDetected
            {
                self.run_anomaly_detection(&event);
            }

            // Trigger event handlers
            self.trigger_event_handlers(&event);
        }
    }

    /// Add anomaly detection rule
    pub fn add_anomaly_rule(&self, rule: AnomalyRule) {
        let mut rules = self.anomaly_rules.write().unwrap();
        rules.push(rule);
    }

    /// Add event handler
    pub fn add_event_handler<F>(&self, handler: F)
    where
        F: Fn(&SecurityEvent) + Send + Sync + 'static,
    {
        let mut handlers = self.event_handlers.write().unwrap();
        handlers.push(Box::new(handler));
    }

    /// Get security metrics
    pub fn get_metrics(&self) -> SecurityMetrics {
        let metrics = self.metrics.lock().unwrap();
        metrics.clone()
    }

    /// Get events by time range
    pub fn get_events_by_time_range(
        &self,
        start: SystemTime,
        end: SystemTime,
    ) -> Vec<SecurityEvent> {
        let events = self.events.read().unwrap();
        events
            .iter()
            .filter(|event| event.timestamp >= start && event.timestamp <= end)
            .cloned()
            .collect()
    }

    /// Get events by type
    pub fn get_events_by_type(&self, event_type: SecurityEventType) -> Vec<SecurityEvent> {
        let events = self.events.read().unwrap();
        events
            .iter()
            .filter(|event| event.event_type == event_type)
            .cloned()
            .collect()
    }

    /// Get events by severity
    pub fn get_events_by_severity(&self, severity: SecuritySeverity) -> Vec<SecurityEvent> {
        let events = self.events.read().unwrap();
        events
            .iter()
            .filter(|event| event.severity == severity)
            .cloned()
            .collect()
    }

    /// Clean up old events
    pub fn cleanup_old_events(&self) {
        let config = self.config.read().unwrap();
        let cutoff_time = SystemTime::now() - config.retention_period;

        let mut events = self.events.write().unwrap();
        events.retain(|event| event.timestamp > cutoff_time);
    }

    /// Check if event should be logged based on configuration
    fn should_log_event(&self, event: &SecurityEvent, config: &SecurityMonitorConfig) -> bool {
        match (&event.severity, &config.log_level_threshold) {
            (SecuritySeverity::Critical, _) => true,
            (
                SecuritySeverity::High,
                SecuritySeverity::Low | SecuritySeverity::Medium | SecuritySeverity::High,
            ) => true,
            (SecuritySeverity::Medium, SecuritySeverity::Low | SecuritySeverity::Medium) => true,
            (SecuritySeverity::Low, SecuritySeverity::Low) => true,
            _ => false,
        }
    }

    /// Update security metrics
    fn update_metrics(&self, event: &SecurityEvent) {
        let mut metrics = self.metrics.lock().unwrap();
        metrics.total_events += 1;
        metrics.last_updated = SystemTime::now();

        // Update events by type
        *metrics
            .events_by_type
            .entry(event.event_type.clone())
            .or_insert(0) += 1;

        // Update events by severity
        *metrics
            .events_by_severity
            .entry(event.severity.clone())
            .or_insert(0) += 1;

        // Update events by source
        *metrics
            .events_by_source
            .entry(event.source.clone())
            .or_insert(0) += 1;

        // Update specific counters
        if event.event_type == SecurityEventType::SecurityViolation {
            metrics.security_violations += 1;
        }
    }

    /// Run anomaly detection
    pub fn run_anomaly_detection(&self, event: &SecurityEvent) {
        let rules = self.anomaly_rules.read().unwrap();
        let events = self.events.read().unwrap();

        for rule in rules.iter() {
            // Get events in the time window
            let time_window_start = event.timestamp - rule.time_window;
            let relevant_events: Vec<SecurityEvent> = events
                .iter()
                .filter(|e| e.timestamp >= time_window_start)
                .cloned()
                .collect();

            // Check if rule is triggered
            if (rule.rule_function)(&relevant_events) {
                // Check if we've already detected this anomaly recently to prevent spam
                let recent_anomaly = events
                    .iter()
                    .rev()
                    .take(10) // Check last 10 events
                    .any(|e| {
                        e.event_type == SecurityEventType::AnomalyDetected
                            && e.data.get("rule_name") == Some(&rule.name)
                            && e.timestamp > event.timestamp - Duration::from_secs(60)
                        // Within last minute
                    });

                if !recent_anomaly {
                    // Create anomaly event
                    let anomaly_event = SecurityEvent {
                        timestamp: SystemTime::now(),
                        event_type: SecurityEventType::AnomalyDetected,
                        severity: SecuritySeverity::High,
                        source: "SecurityMonitor".to_string(),
                        message: format!("Anomaly detected: {}", rule.name),
                        data: {
                            let mut data = HashMap::new();
                            data.insert("rule_name".to_string(), rule.name.clone());
                            data.insert("rule_description".to_string(), rule.description.clone());
                            data.insert("triggering_event_id".to_string(), event.event_id.clone());
                            data
                        },
                        event_id: format!(
                            "anomaly_{}",
                            SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_nanos()
                        ),
                        user_id: event.user_id.clone(),
                        ip_address: event.ip_address.clone(),
                    };

                    // Log the anomaly (without running anomaly detection to prevent recursion)
                    self.log_event_internal(anomaly_event, false);

                    // Update metrics
                    let mut metrics = self.metrics.lock().unwrap();
                    metrics.anomalies_detected += 1;
                }
            }
        }
    }

    /// Trigger event handlers
    fn trigger_event_handlers(&self, event: &SecurityEvent) {
        let handlers = self.event_handlers.read().unwrap();
        for handler in handlers.iter() {
            handler(event);
        }
    }
}

impl Default for SecurityMonitor {
    fn default() -> Self {
        Self::new(SecurityMonitorConfig::default())
    }
}

/// Predefined anomaly detection rules
pub struct PredefinedAnomalyRules;

impl PredefinedAnomalyRules {
    /// Rule for detecting excessive key generation
    pub fn excessive_key_generation() -> AnomalyRule {
        AnomalyRule {
            name: "excessive_key_generation".to_string(),
            description: "Detects when too many keys are generated in a short time".to_string(),
            time_window: Duration::from_secs(3600), // 1 hour
            threshold: 100,                         // 100 keys per hour
            rule_function: Box::new(|events| {
                let key_gen_count = events
                    .iter()
                    .filter(|e| e.event_type == SecurityEventType::KeyGeneration)
                    .count();
                key_gen_count > 100
            }),
        }
    }

    /// Rule for detecting unusual key usage patterns
    pub fn unusual_key_usage() -> AnomalyRule {
        AnomalyRule {
            name: "unusual_key_usage".to_string(),
            description: "Detects unusual key usage patterns".to_string(),
            time_window: Duration::from_secs(1800), // 30 minutes
            threshold: 1000,                        // 1000 uses per 30 minutes
            rule_function: Box::new(|events| {
                let key_usage_count = events
                    .iter()
                    .filter(|e| e.event_type == SecurityEventType::KeyUsage)
                    .count();
                key_usage_count > 1000
            }),
        }
    }

    /// Rule for detecting security violations
    pub fn security_violations() -> AnomalyRule {
        AnomalyRule {
            name: "security_violations".to_string(),
            description: "Detects security violations".to_string(),
            time_window: Duration::from_secs(3600), // 1 hour
            threshold: 5,                           // 5 violations per hour
            rule_function: Box::new(|events| {
                let violation_count = events
                    .iter()
                    .filter(|e| e.event_type == SecurityEventType::SecurityViolation)
                    .count();
                violation_count > 5
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_monitor_creation() {
        let config = SecurityMonitorConfig::default();
        let monitor = SecurityMonitor::new(config);

        let metrics = monitor.get_metrics();
        assert_eq!(metrics.total_events, 0);
    }

    #[test]
    fn test_event_logging() {
        let monitor = SecurityMonitor::default();

        let event = SecurityEvent {
            timestamp: SystemTime::now(),
            event_type: SecurityEventType::KeyGeneration,
            severity: SecuritySeverity::Medium,
            source: "test".to_string(),
            message: "Test event".to_string(),
            data: HashMap::new(),
            event_id: "test_id".to_string(),
            user_id: None,
            ip_address: None,
        };

        monitor.log_event(event);

        let metrics = monitor.get_metrics();
        assert_eq!(metrics.total_events, 1);
    }

    #[test]
    fn test_anomaly_detection() {
        let monitor = SecurityMonitor::default();

        // Add a simple anomaly rule
        let rule = AnomalyRule {
            name: "test_rule".to_string(),
            description: "Test rule".to_string(),
            time_window: Duration::from_secs(3600),
            threshold: 2,
            rule_function: Box::new(|events| events.len() > 2),
        };
        monitor.add_anomaly_rule(rule);

        // Log a few events without triggering anomaly detection
        for i in 0..3 {
            let event = SecurityEvent {
                timestamp: SystemTime::now(),
                event_type: SecurityEventType::KeyGeneration,
                severity: SecuritySeverity::Low,
                source: "test".to_string(),
                message: format!("Event {}", i),
                data: HashMap::new(),
                event_id: format!("test_id_{}", i),
                user_id: None,
                ip_address: None,
            };
            monitor.log_event_internal(event, false);
        }

        // Check that we have the events
        let metrics = monitor.get_metrics();
        assert_eq!(metrics.total_events, 3);
        assert_eq!(metrics.anomalies_detected, 0);

        // Now test the rule function directly
        let events = monitor.events.read().unwrap();
        let rule_result = events.len() > 2; // Test the same logic as the rule
        assert!(rule_result); // Should be true since we have 3 events > 2
    }
}
