//! Persistence for the met-ocean subsystem.
//!
//! [`MetoceanStore`] is the fail-closed storage surface: every corruption,
//! unavailability or validation failure is an error, never a silent reset.
//! The production backend is PostgreSQL behind the `metocean-pg-store`
//! cargo feature; there is no in-memory production store (tests provide
//! their own, mirroring the gateway's in-test uploader precedent).

use super::evaluate::{Advisory, AdvisoryStatus};
use super::{error, FeedHealth, MetoceanDeadLetter, NormalizedReading};
use crate::ValidationError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Delivery record for one advisory over one channel.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AdvisoryDelivery {
    pub advisory_id: String,
    pub channel: String,
    pub delivered_at: String,
    pub outcome: String,
}

/// The fail-closed met-ocean storage surface.
pub trait MetoceanStore {
    /// Persist a reading; returns false when the reading id already exists
    /// (idempotent re-ingest).
    fn record_reading(&mut self, reading: &NormalizedReading) -> Result<bool, ValidationError>;
    fn record_dead_letter(
        &mut self,
        dead_letter: &MetoceanDeadLetter,
    ) -> Result<(), ValidationError>;
    /// Readings for one zone from one feed fetched at or after `not_before`.
    fn fresh_readings(
        &mut self,
        zone_id: &str,
        feed_id: &str,
        not_before: DateTime<Utc>,
    ) -> Result<Vec<NormalizedReading>, ValidationError>;
    /// Active advisories for one zone (ALERT/UPDATE instances not yet
    /// terminated).
    fn active_advisories(&mut self, zone_id: &str) -> Result<Vec<Advisory>, ValidationError>;
    /// Persist an advisory; idempotent on advisory_id.
    fn record_advisory(&mut self, advisory: &Advisory) -> Result<(), ValidationError>;
    fn set_advisory_status(
        &mut self,
        advisory_id: &str,
        status: AdvisoryStatus,
    ) -> Result<(), ValidationError>;
    fn upsert_feed_health(&mut self, health: &FeedHealth) -> Result<(), ValidationError>;
    fn feed_health(&mut self, feed_id: &str) -> Result<Option<FeedHealth>, ValidationError>;
    fn record_delivery(&mut self, delivery: &AdvisoryDelivery) -> Result<(), ValidationError>;
    /// Claim an operator-override nonce. Returns false when the (key, nonce)
    /// pair was already used (replay — the override must be refused).
    fn claim_operator_nonce(
        &mut self,
        key_id: &str,
        nonce: &str,
        claimed_at: &str,
    ) -> Result<bool, ValidationError>;
    /// Read API: advisories for a zone (or all zones), optionally only
    /// currently active ones.
    fn advisories(
        &mut self,
        zone_id: Option<&str>,
        active_only: bool,
    ) -> Result<Vec<Advisory>, ValidationError>;
    /// Read API: immutable readings with provenance for a zone and window.
    fn readings(
        &mut self,
        zone_id: &str,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<Vec<NormalizedReading>, ValidationError>;
}

/// Embedded schema migration applied by [`PgMetoceanStore::migrate`].
pub const MIGRATION_0001: &str = include_str!("../../schemas/metocean/0001_init.sql");

#[cfg(feature = "metocean-pg-store")]
mod pg {
    use super::*;
    use chrono::SecondsFormat;

    fn rfc3339_z(value: DateTime<Utc>) -> String {
        value.to_rfc3339_opts(SecondsFormat::Secs, true)
    }

    fn parse_z(field: &'static str, value: &str) -> Result<DateTime<Utc>, ValidationError> {
        Ok(DateTime::parse_from_rfc3339(value)
            .map_err(|_| error("store_corrupt", field))?
            .with_timezone(&Utc))
    }

    fn pg_error(context: &'static str, error: postgres::Error) -> ValidationError {
        super::error("store_unavailable", format!("{context}: {error}"))
    }

    /// PostgreSQL-backed store. Connect fail-closed: an unreachable or
    /// unauthenticated database is a startup error.
    pub struct PgMetoceanStore {
        client: postgres::Client,
    }

    impl PgMetoceanStore {
        pub fn connect(dsn: &str) -> Result<Self, ValidationError> {
            let client = postgres::Client::connect(dsn, postgres::NoTls)
                .map_err(|error| pg_error("connect", error))?;
            Ok(Self { client })
        }

        /// Apply the embedded schema (idempotent).
        pub fn migrate(&mut self) -> Result<(), ValidationError> {
            self.client
                .batch_execute(MIGRATION_0001)
                .map_err(|error| pg_error("migrate", error))
        }

        /// Administrative statement (test harness / ops maintenance only;
        /// production flows use the typed trait methods).
        pub fn raw_execute(&mut self, statement: &str) -> Result<u64, ValidationError> {
            self.client
                .execute(statement, &[])
                .map_err(|error| pg_error("raw_execute", error))
        }

        fn advisory_from_document(document: &str) -> Result<Advisory, ValidationError> {
            serde_json::from_str(document)
                .map_err(|serde_error| error("store_corrupt", serde_error.to_string()))
        }

        fn reading_from_row(row: &postgres::Row) -> Result<NormalizedReading, ValidationError> {
            let document: String = row.get("document");
            serde_json::from_str(&document)
                .map_err(|serde_error| error("store_corrupt", serde_error.to_string()))
        }
    }

    impl MetoceanStore for PgMetoceanStore {
        fn record_reading(&mut self, reading: &NormalizedReading) -> Result<bool, ValidationError> {
            let document = serde_json::to_string(reading)
                .map_err(|serde_error| error("store_encode_failed", serde_error.to_string()))?;
            // Normalize the ordering column so lexical = chronological.
            let fetched_at = rfc3339_z(parse_z("fetched_at", &reading.fetched_at)?);
            let changed = self
                .client
                .execute(
                    "INSERT INTO metocean_reading (
                        reading_id, feed_id, feed_kind, zone_id, latitude, longitude,
                        observed_at, forecast_for, model_run_at, fetched_at,
                        wave_height_m, wave_period_s, wave_direction_deg,
                        swell_height_m, swell_period_s, wind_speed_ms, wind_gust_ms, sst_c,
                        source_payload_sha256, attribution_text, document
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
                    ON CONFLICT (reading_id) DO NOTHING",
                    &[
                        &reading.reading_id,
                        &reading.feed_id,
                        &reading.feed_kind.as_str(),
                        &reading.zone_id,
                        &reading.latitude,
                        &reading.longitude,
                        &reading.observed_at,
                        &reading.forecast_for,
                        &reading.model_run_at,
                        &fetched_at,
                        &reading.wave_height_m,
                        &reading.wave_period_s,
                        &reading.wave_direction_deg,
                        &reading.swell_height_m,
                        &reading.swell_period_s,
                        &reading.wind_speed_ms,
                        &reading.wind_gust_ms,
                        &reading.sst_c,
                        &reading.source_payload_sha256,
                        &reading.attribution_text,
                        &document,
                    ],
                )
                .map_err(|error| pg_error("record_reading", error))?;
            Ok(changed > 0)
        }

        fn record_dead_letter(
            &mut self,
            dead_letter: &MetoceanDeadLetter,
        ) -> Result<(), ValidationError> {
            self.client
                .execute(
                    "INSERT INTO metocean_dead_letter
                        (feed_id, feed_kind, reason, error_code, payload_sha256, detail, recorded_at)
                     VALUES ($1,$2,$3,$4,$5,$6,$7)",
                    &[
                        &dead_letter.feed_id,
                        &dead_letter.feed_kind,
                        &serde_json::to_value(dead_letter.reason)
                            .ok()
                            .and_then(|value| value.as_str().map(str::to_owned))
                            .unwrap_or_else(|| "unknown".to_owned()),
                        &dead_letter.error_code,
                        &dead_letter.payload_sha256,
                        &dead_letter.detail,
                        &dead_letter.recorded_at,
                    ],
                )
                .map_err(|error| pg_error("record_dead_letter", error))?;
            Ok(())
        }

        fn fresh_readings(
            &mut self,
            zone_id: &str,
            feed_id: &str,
            not_before: DateTime<Utc>,
        ) -> Result<Vec<NormalizedReading>, ValidationError> {
            let rows = self
                .client
                .query(
                    "SELECT document FROM metocean_reading
                     WHERE zone_id = $1 AND feed_id = $2 AND fetched_at >= $3
                     ORDER BY fetched_at",
                    &[&zone_id, &feed_id, &rfc3339_z(not_before)],
                )
                .map_err(|error| pg_error("fresh_readings", error))?;
            rows.iter().map(Self::reading_from_row).collect()
        }

        fn active_advisories(&mut self, zone_id: &str) -> Result<Vec<Advisory>, ValidationError> {
            let rows = self
                .client
                .query(
                    "SELECT document FROM metocean_advisory
                     WHERE zone_id = $1 AND status = 'ACTIVE' AND msg_type <> 'Cancel'
                     ORDER BY issued_at",
                    &[&zone_id],
                )
                .map_err(|error| pg_error("active_advisories", error))?;
            rows.iter()
                .map(|row| Self::advisory_from_document(row.get("document")))
                .collect()
        }

        fn record_advisory(&mut self, advisory: &Advisory) -> Result<(), ValidationError> {
            advisory.validate()?;
            let document = serde_json::to_string(advisory)
                .map_err(|serde_error| error("store_encode_failed", serde_error.to_string()))?;
            self.client
                .execute(
                    "INSERT INTO metocean_advisory (
                        advisory_id, msg_type, phenomenon_code, severity, urgency, certainty,
                        zone_id, effective_from, effective_until, bulletin_reference,
                        references_advisory_id, source, feed_kind, attribution_text, status,
                        policy_digest_sha256, issued_at, cancel_reason, document
                    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
                    ON CONFLICT (advisory_id) DO NOTHING",
                    &[
                        &advisory.advisory_id,
                        &advisory.msg_type.wire(),
                        &advisory.phenomenon_code,
                        &advisory.severity.wire(),
                        &advisory.urgency.wire(),
                        &advisory.certainty.wire(),
                        &advisory.zone_id,
                        &rfc3339_z(parse_z("effective_from", &advisory.effective_from)?),
                        &rfc3339_z(parse_z("effective_until", &advisory.effective_until)?),
                        &advisory.bulletin_reference,
                        &advisory.references_advisory_id,
                        &advisory.source.wire(),
                        &advisory.feed_kind.map(|kind| kind.as_str()),
                        &advisory.attribution_text,
                        &advisory.status.wire(),
                        &advisory.policy_digest_sha256,
                        &rfc3339_z(parse_z("issued_at", &advisory.issued_at)?),
                        &advisory
                            .cancel_reason
                            .and_then(|reason| serde_json::to_value(reason).ok())
                            .and_then(|value| value.as_str().map(str::to_owned)),
                        &document,
                    ],
                )
                .map_err(|error| pg_error("record_advisory", error))?;
            Ok(())
        }

        fn set_advisory_status(
            &mut self,
            advisory_id: &str,
            status: AdvisoryStatus,
        ) -> Result<(), ValidationError> {
            let changed = self
                .client
                .execute(
                    "UPDATE metocean_advisory SET status = $2 WHERE advisory_id = $1",
                    &[&advisory_id, &status.wire()],
                )
                .map_err(|error| pg_error("set_advisory_status", error))?;
            if changed == 0 {
                return Err(error(
                    "store_corrupt",
                    "advisory status update matched no row",
                ));
            }
            Ok(())
        }

        fn upsert_feed_health(&mut self, health: &FeedHealth) -> Result<(), ValidationError> {
            let availability = serde_json::to_value(health.availability)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| "UNAVAILABLE".to_owned());
            self.client
                .execute(
                    "INSERT INTO metocean_feed_health
                        (feed_id, feed_kind, enabled, availability, last_success_at, last_failure_at, last_error)
                     VALUES ($1,$2,$3,$4,$5,$6,$7)
                     ON CONFLICT (feed_id) DO UPDATE SET
                        feed_kind = EXCLUDED.feed_kind,
                        enabled = EXCLUDED.enabled,
                        availability = EXCLUDED.availability,
                        last_success_at = EXCLUDED.last_success_at,
                        last_failure_at = EXCLUDED.last_failure_at,
                        last_error = EXCLUDED.last_error",
                    &[
                        &health.feed_id,
                        &health.feed_kind,
                        &health.enabled,
                        &health.availability,
                        &health.last_success_at,
                        &health.last_failure_at,
                        &health.last_error,
                    ],
                )
                .map_err(|error| pg_error("upsert_feed_health", error))?;
            Ok(())
        }

        fn feed_health(&mut self, feed_id: &str) -> Result<Option<FeedHealth>, ValidationError> {
            let rows = self
                .client
                .query(
                    "SELECT feed_id, feed_kind, enabled, availability, last_success_at,
                            last_failure_at, last_error
                     FROM metocean_feed_health WHERE feed_id = $1",
                    &[&feed_id],
                )
                .map_err(|error| pg_error("feed_health", error))?;
            let Some(row) = rows.first() else {
                return Ok(None);
            };
            let availability: String = row.get("availability");
            Ok(Some(FeedHealth {
                feed_id: row.get("feed_id"),
                feed_kind: row.get("feed_kind"),
                enabled: row.get("enabled"),
                availability: match availability.as_str() {
                    "OK" => super::super::FeedAvailability::Ok,
                    "DEGRADED" => super::super::FeedAvailability::Degraded,
                    _ => super::super::FeedAvailability::Unavailable,
                },
                last_success_at: row.get("last_success_at"),
                last_failure_at: row.get("last_failure_at"),
                last_error: row.get("last_error"),
                staleness_seconds: None,
            }))
        }

        fn record_delivery(&mut self, delivery: &AdvisoryDelivery) -> Result<(), ValidationError> {
            self.client
                .execute(
                    "INSERT INTO metocean_delivery (advisory_id, channel, delivered_at, outcome)
                     VALUES ($1,$2,$3,$4)",
                    &[
                        &delivery.advisory_id,
                        &delivery.channel,
                        &delivery.delivered_at,
                        &delivery.outcome,
                    ],
                )
                .map_err(|error| pg_error("record_delivery", error))?;
            Ok(())
        }

        fn claim_operator_nonce(
            &mut self,
            key_id: &str,
            nonce: &str,
            claimed_at: &str,
        ) -> Result<bool, ValidationError> {
            let changed = self
                .client
                .execute(
                    "INSERT INTO metocean_operator_nonce (key_id, nonce, claimed_at)
                     VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
                    &[&key_id, &nonce, &claimed_at],
                )
                .map_err(|error| pg_error("claim_operator_nonce", error))?;
            Ok(changed > 0)
        }

        fn advisories(
            &mut self,
            zone_id: Option<&str>,
            active_only: bool,
        ) -> Result<Vec<Advisory>, ValidationError> {
            let rows = match (zone_id, active_only) {
                (Some(zone), true) => self.client.query(
                    "SELECT document FROM metocean_advisory WHERE zone_id = $1 AND status = 'ACTIVE' ORDER BY issued_at",
                    &[&zone],
                ),
                (Some(zone), false) => self.client.query(
                    "SELECT document FROM metocean_advisory WHERE zone_id = $1 ORDER BY issued_at",
                    &[&zone],
                ),
                (None, true) => self.client.query(
                    "SELECT document FROM metocean_advisory WHERE status = 'ACTIVE' ORDER BY issued_at",
                    &[],
                ),
                (None, false) => self.client.query(
                    "SELECT document FROM metocean_advisory ORDER BY issued_at",
                    &[],
                ),
            }
            .map_err(|error| pg_error("advisories", error))?;
            rows.iter()
                .map(|row| Self::advisory_from_document(row.get("document")))
                .collect()
        }

        fn readings(
            &mut self,
            zone_id: &str,
            from: DateTime<Utc>,
            to: DateTime<Utc>,
        ) -> Result<Vec<NormalizedReading>, ValidationError> {
            let rows = self
                .client
                .query(
                    "SELECT document FROM metocean_reading
                     WHERE zone_id = $1 AND fetched_at >= $2 AND fetched_at <= $3
                     ORDER BY fetched_at",
                    &[&zone_id, &rfc3339_z(from), &rfc3339_z(to)],
                )
                .map_err(|error| pg_error("readings", error))?;
            rows.iter().map(Self::reading_from_row).collect()
        }
    }
}

#[cfg(feature = "metocean-pg-store")]
pub use pg::PgMetoceanStore;

/// Construct the PostgreSQL store when the feature is compiled in;
/// otherwise fail closed.
#[cfg(feature = "metocean-pg-store")]
pub fn connect_postgres(dsn: &str) -> Result<PgMetoceanStore, ValidationError> {
    PgMetoceanStore::connect(dsn)
}

#[cfg(not(feature = "metocean-pg-store"))]
pub fn connect_postgres(dsn: &str) -> Result<(), ValidationError> {
    let _ = dsn;
    Err(error(
        "store_unavailable",
        "the metocean-pg-store feature is not compiled in; persistence is unavailable",
    ))
}
