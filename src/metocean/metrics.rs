//! Local metrics for the met-ocean subsystem (Phase-7 OTel conventions:
//! spans via `tracing` are no-ops unless OTLP is configured; local counters
//! are always available and rendered in Prometheus exposition format for the
//! `/metrics` scrape). Low-cardinality labels only — feed kind, zone id,
//! severity, outcome; never payload content.

use std::collections::BTreeMap;
use std::sync::Mutex;

/// Counters and gauges named per the Phase-8 spec metrics plan.
#[derive(Debug, Default)]
pub struct MetoceanMetrics {
    feed_poll_total: Mutex<BTreeMap<(String, String), u64>>,
    feed_last_success_seconds: Mutex<BTreeMap<String, i64>>,
    readings_ingested_total: Mutex<u64>,
    dead_letters_total: Mutex<BTreeMap<String, u64>>,
    advisories_active: Mutex<BTreeMap<(String, String), u64>>,
    advisories_issued_total: Mutex<BTreeMap<(String, String), u64>>,
    advisory_deliveries_total: Mutex<BTreeMap<(String, String), u64>>,
}

fn bump(map: &Mutex<BTreeMap<(String, String), u64>>, key: (String, String), by: u64) {
    let mut guard = map.lock().expect("metrics lock");
    *guard.entry(key).or_insert(0) += by;
}

impl MetoceanMetrics {
    pub fn feed_poll(&self, kind: &str, outcome: &str) {
        bump(
            &self.feed_poll_total,
            (kind.to_owned(), outcome.to_owned()),
            1,
        );
    }

    /// Gauge: epoch seconds of the feed's last successful poll.
    pub fn feed_last_success(&self, kind: &str, epoch_seconds: i64) {
        self.feed_last_success_seconds
            .lock()
            .expect("metrics lock")
            .insert(kind.to_owned(), epoch_seconds);
    }

    pub fn readings_ingested(&self, count: u64) {
        let mut guard = self.readings_ingested_total.lock().expect("metrics lock");
        *guard += count;
    }

    pub fn dead_letter(&self, reason: &str) {
        let mut guard = self.dead_letters_total.lock().expect("metrics lock");
        *guard.entry(reason.to_owned()).or_insert(0) += 1;
    }

    pub fn advisories_active(&self, zone: &str, severity: &str, count: u64) {
        self.advisories_active
            .lock()
            .expect("metrics lock")
            .insert((zone.to_owned(), severity.to_owned()), count);
    }

    pub fn advisory_issued(&self, msg_type: &str, severity: &str) {
        bump(
            &self.advisories_issued_total,
            (msg_type.to_owned(), severity.to_owned()),
            1,
        );
    }

    pub fn advisory_delivery(&self, channel: &str, outcome: &str) {
        bump(
            &self.advisory_deliveries_total,
            (channel.to_owned(), outcome.to_owned()),
            1,
        );
    }

    /// Prometheus text exposition (`/metrics` body).
    pub fn render_prometheus(&self) -> String {
        fn line(out: &mut String, name: &str, labels: &str, value: impl std::fmt::Display) {
            out.push_str(name);
            if !labels.is_empty() {
                out.push('{');
                out.push_str(labels);
                out.push('}');
            }
            out.push(' ');
            out.push_str(&value.to_string());
            out.push('\n');
        }
        let mut out = String::new();
        for ((kind, outcome), value) in self.feed_poll_total.lock().expect("metrics lock").iter() {
            line(
                &mut out,
                "metocean_feed_poll_total",
                &format!("kind=\"{kind}\",outcome=\"{outcome}\""),
                *value,
            );
        }
        for (kind, value) in self
            .feed_last_success_seconds
            .lock()
            .expect("metrics lock")
            .iter()
        {
            line(
                &mut out,
                "metocean_feed_last_success_seconds",
                &format!("kind=\"{kind}\""),
                *value,
            );
        }
        line(
            &mut out,
            "metocean_readings_ingested_total",
            "",
            *self.readings_ingested_total.lock().expect("metrics lock"),
        );
        for (reason, value) in self.dead_letters_total.lock().expect("metrics lock").iter() {
            line(
                &mut out,
                "metocean_dead_letters_total",
                &format!("reason=\"{reason}\""),
                *value,
            );
        }
        for ((zone, severity), value) in self.advisories_active.lock().expect("metrics lock").iter()
        {
            line(
                &mut out,
                "metocean_advisories_active",
                &format!("zone=\"{zone}\",severity=\"{severity}\""),
                *value,
            );
        }
        for ((msg_type, severity), value) in self
            .advisories_issued_total
            .lock()
            .expect("metrics lock")
            .iter()
        {
            line(
                &mut out,
                "metocean_advisories_issued_total",
                &format!("msg_type=\"{msg_type}\",severity=\"{severity}\""),
                *value,
            );
        }
        for ((channel, outcome), value) in self
            .advisory_deliveries_total
            .lock()
            .expect("metrics lock")
            .iter()
        {
            line(
                &mut out,
                "metocean_advisory_deliveries_total",
                &format!("channel=\"{channel}\",outcome=\"{outcome}\""),
                *value,
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_render_in_prometheus_format() {
        let metrics = MetoceanMetrics::default();
        metrics.feed_poll("open_meteo_marine", "ok");
        metrics.feed_poll("open_meteo_marine", "error");
        metrics.feed_poll("open_meteo_marine", "ok");
        metrics.feed_last_success("open_meteo_marine", 1_800_000_000);
        metrics.readings_ingested(24);
        metrics.dead_letter("malformed_payload");
        metrics.advisories_active("hz-lagos-approach", "Moderate", 1);
        metrics.advisory_issued("Alert", "Moderate");
        metrics.advisory_delivery("kafka", "ok");
        let exposition = metrics.render_prometheus();
        assert!(exposition
            .contains("metocean_feed_poll_total{kind=\"open_meteo_marine\",outcome=\"ok\"} 2"));
        assert!(exposition
            .contains("metocean_feed_last_success_seconds{kind=\"open_meteo_marine\"} 1800000000"));
        assert!(exposition.contains("metocean_readings_ingested_total 24"));
        assert!(exposition.contains("metocean_dead_letters_total{reason=\"malformed_payload\"} 1"));
        assert!(exposition.contains(
            "metocean_advisories_active{zone=\"hz-lagos-approach\",severity=\"Moderate\"} 1"
        ));
        assert!(exposition.contains(
            "metocean_advisories_issued_total{msg_type=\"Alert\",severity=\"Moderate\"} 1"
        ));
        assert!(exposition
            .contains("metocean_advisory_deliveries_total{channel=\"kafka\",outcome=\"ok\"} 1"));
    }
}
