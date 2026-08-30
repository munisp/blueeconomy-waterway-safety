-- Phase-8 met-ocean advisories: persistence for the waterway-safety
-- metocean subsystem. Timestamps are RFC 3339 Z-normalized TEXT so lexical
-- order equals chronological order and round-trips stay byte-exact with the
-- signed artifacts. Readings are immutable and digest-bound; advisories
-- transition ACTIVE -> EXPIRED|CANCELLED only through explicit CANCEL
-- issuance recorded here.
CREATE TABLE IF NOT EXISTS metocean_reading (
    reading_id              TEXT PRIMARY KEY,
    feed_id                 TEXT NOT NULL,
    feed_kind               TEXT NOT NULL,
    zone_id                 TEXT,
    latitude                DOUBLE PRECISION NOT NULL,
    longitude               DOUBLE PRECISION NOT NULL,
    observed_at             TEXT,
    forecast_for            TEXT,
    model_run_at            TEXT,
    fetched_at              TEXT NOT NULL,
    wave_height_m           DOUBLE PRECISION,
    wave_period_s           DOUBLE PRECISION,
    wave_direction_deg      DOUBLE PRECISION,
    swell_height_m          DOUBLE PRECISION,
    swell_period_s          DOUBLE PRECISION,
    wind_speed_ms           DOUBLE PRECISION,
    wind_gust_ms            DOUBLE PRECISION,
    sst_c                   DOUBLE PRECISION,
    source_payload_sha256   TEXT NOT NULL,
    attribution_text        TEXT NOT NULL,
    document                TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS metocean_reading_zone_fetched
    ON metocean_reading (zone_id, feed_id, fetched_at);

CREATE TABLE IF NOT EXISTS metocean_advisory (
    advisory_id             TEXT PRIMARY KEY,
    msg_type                TEXT NOT NULL CHECK (msg_type IN ('Alert','Update','Cancel')),
    phenomenon_code         TEXT NOT NULL,
    severity                TEXT NOT NULL,
    urgency                 TEXT NOT NULL,
    certainty               TEXT NOT NULL,
    zone_id                 TEXT NOT NULL,
    effective_from          TEXT NOT NULL,
    effective_until         TEXT NOT NULL,
    bulletin_reference      TEXT NOT NULL,
    references_advisory_id  TEXT NOT NULL DEFAULT '',
    source                  TEXT NOT NULL CHECK (source IN ('FEED','OPERATOR_OVERRIDE')),
    feed_kind               TEXT,
    attribution_text        TEXT NOT NULL,
    status                  TEXT NOT NULL CHECK (status IN ('ACTIVE','EXPIRED','CANCELLED')),
    policy_digest_sha256    TEXT NOT NULL,
    issued_at               TEXT NOT NULL,
    cancel_reason           TEXT,
    document                TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS metocean_advisory_zone_status
    ON metocean_advisory (zone_id, status);

CREATE TABLE IF NOT EXISTS metocean_dead_letter (
    id                      BIGSERIAL PRIMARY KEY,
    feed_id                 TEXT NOT NULL,
    feed_kind               TEXT NOT NULL,
    reason                  TEXT NOT NULL,
    error_code              TEXT NOT NULL,
    payload_sha256          TEXT NOT NULL,
    detail                  TEXT NOT NULL,
    recorded_at             TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS metocean_feed_health (
    feed_id                 TEXT PRIMARY KEY,
    feed_kind               TEXT NOT NULL,
    enabled                 BOOLEAN NOT NULL,
    availability            TEXT NOT NULL CHECK (availability IN ('OK','DEGRADED','UNAVAILABLE')),
    last_success_at         TEXT,
    last_failure_at         TEXT,
    last_error              TEXT
);

CREATE TABLE IF NOT EXISTS metocean_delivery (
    id                      BIGSERIAL PRIMARY KEY,
    advisory_id             TEXT NOT NULL REFERENCES metocean_advisory(advisory_id),
    channel                 TEXT NOT NULL,
    delivered_at            TEXT NOT NULL,
    outcome                 TEXT NOT NULL
);

-- Operator-override replay protection: a nonce may be claimed exactly once.
CREATE TABLE IF NOT EXISTS metocean_operator_nonce (
    key_id                  TEXT NOT NULL,
    nonce                   TEXT NOT NULL,
    claimed_at              TEXT NOT NULL,
    PRIMARY KEY (key_id, nonce)
);
