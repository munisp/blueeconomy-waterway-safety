//! Advisory publication onto `waterways.met_ocean.advisories.v1`.
//!
//! The production transport is a real Kafka producer behind the existing
//! `kafka-transport` cargo feature (same pinned client as the gateway uplink
//! fallback). Building without the feature and selecting Kafka fails closed
//! with `transport_unavailable`; there is intentionally no in-memory or
//! loopback publisher on production paths.

use super::error;
#[cfg(feature = "kafka-transport")]
use super::ADVISORY_TOPIC;
use crate::ValidationError;
#[cfg(feature = "kafka-transport")]
use std::time::Duration;

/// Explicit acknowledgement returned by a successful publish.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishReceipt {
    pub topic: String,
    /// Record key (the advisory id; stable across redelivery).
    pub key: String,
    pub payload_bytes: usize,
}

/// The production publisher surface. Implementations must return an error
/// unless the record was durably accepted; there is no fire-and-forget.
pub trait AdvisoryPublisher {
    fn publish(&mut self, key: &str, payload: &[u8]) -> Result<PublishReceipt, ValidationError>;
}

/// Kafka publisher for the advisory topic (`kafka-transport` feature).
#[cfg(feature = "kafka-transport")]
pub struct KafkaAdvisoryPublisher {
    producer: kafka::producer::Producer,
    topic: String,
}

#[cfg(feature = "kafka-transport")]
impl KafkaAdvisoryPublisher {
    /// Connect to the broker fail-closed: an unreachable cluster is a
    /// startup error, never a runtime surprise.
    pub fn connect(brokers: &str) -> Result<Self, ValidationError> {
        let hosts: Vec<String> = brokers
            .split(',')
            .map(str::trim)
            .filter(|host| !host.is_empty())
            .map(str::to_owned)
            .collect();
        if hosts.is_empty() {
            return Err(error(
                "invalid_transport_config",
                "at least one Kafka broker host is required",
            ));
        }
        let producer = kafka::producer::Producer::from_hosts(hosts)
            .with_ack_timeout(Duration::from_secs(10))
            .with_required_acks(kafka::producer::RequiredAcks::One)
            .create()
            .map_err(|kafka_error| {
                error(
                    "transport_unavailable",
                    format!("kafka producer connect failed: {kafka_error}"),
                )
            })?;
        Ok(Self {
            producer,
            topic: ADVISORY_TOPIC.to_owned(),
        })
    }
}

#[cfg(feature = "kafka-transport")]
impl AdvisoryPublisher for KafkaAdvisoryPublisher {
    fn publish(&mut self, key: &str, payload: &[u8]) -> Result<PublishReceipt, ValidationError> {
        self.producer
            .send(&kafka::producer::Record::from_key_value(
                self.topic.as_str(),
                key,
                payload,
            ))
            .map_err(|kafka_error| {
                error(
                    "publish_failed",
                    format!("kafka produce failed: {kafka_error}"),
                )
            })?;
        Ok(PublishReceipt {
            topic: self.topic.clone(),
            key: key.to_owned(),
            payload_bytes: payload.len(),
        })
    }
}

/// Construct the Kafka publisher when the transport feature is compiled in;
/// otherwise fail closed exactly like the gateway's transport selection.
pub fn connect_kafka(brokers: &str) -> Result<Box<dyn AdvisoryPublisher>, ValidationError> {
    #[cfg(feature = "kafka-transport")]
    {
        Ok(Box::new(KafkaAdvisoryPublisher::connect(brokers)?))
    }
    #[cfg(not(feature = "kafka-transport"))]
    {
        let _ = brokers;
        Err(error(
            "transport_unavailable",
            "the kafka-transport feature is not compiled in; advisory publication is unavailable",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_broker_list_fails_closed() {
        let connect_error = connect_kafka("  ").err().expect("must fail closed");
        assert_eq!(
            connect_error.code,
            if cfg!(feature = "kafka-transport") {
                "invalid_transport_config"
            } else {
                "transport_unavailable"
            }
        );
    }
}
