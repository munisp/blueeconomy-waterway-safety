//! Feed payload parsers for the documented open APIs.
//!
//! Every parser is fail-closed: malformed, truncated, out-of-range or
//! partially missing input is a structured [`ValidationError`] so the ingest
//! path dead-letters it explicitly. Parsers never fabricate a measurement:
//! absent variables stay `None`, and there is no interpolation or synthesis.
//!
//! - Open-Meteo Marine Forecast API (hourly JSON; CC BY 4.0):
//!   <https://open-meteo.com/en/docs/marine-weather-api>
//! - Copernicus Marine toolbox `subset` CSV output (registered account):
//!   <https://help.marine.copernicus.eu/en/articles/7972861>
//! - NOAA GFS via NOMADS `filter_gfs_0p25.pl` GRIB2 slices (WMO FM-92 GRIB
//!   edition 2, templates 3.0 / 4.0 / 5.0 simple packing only):
//!   <https://nomads.ncep.noaa.gov/>

use super::{
    error, reading_id, FeedSourceConfig, MonitoredPoint, NormalizedReading, MAX_FEED_PAYLOAD_BYTES,
    MAX_READINGS_PER_PAYLOAD, MAX_SST_C, MAX_WAVE_HEIGHT_M, MAX_WAVE_PERIOD_S, MAX_WIND_SPEED_MS,
    MIN_SST_C, READING_SCHEMA_VERSION,
};
use crate::geo::GeoPosition;
use crate::ValidationError;
use chrono::{DateTime, Duration, FixedOffset};
use sha2::{Digest, Sha256};

/// Parse one raw feed payload into normalised readings bound to `point`.
/// `fetched_at` is supplied by the caller (the poll clock); parsers never
/// invent timestamps beyond what the payload itself carries.
pub fn parse_feed_payload(
    feed: &FeedSourceConfig,
    zone_id: &str,
    point: MonitoredPoint,
    payload: &[u8],
    fetched_at: &str,
) -> Result<Vec<NormalizedReading>, ValidationError> {
    if payload.is_empty() || payload.len() > MAX_FEED_PAYLOAD_BYTES {
        return Err(error(
            "invalid_feed_payload",
            format!("feed payload must contain between 1 and {MAX_FEED_PAYLOAD_BYTES} bytes"),
        ));
    }
    crate::validate_timestamp("fetched_at", fetched_at)?;
    crate::validate_identifier("zone_id", zone_id, 256)?;
    point.position()?;
    let payload_digest = crate::hex_lowercase(Sha256::digest(payload));
    let readings = match feed.kind {
        super::FeedKind::OpenMeteoMarine => {
            parse_open_meteo_marine(feed, zone_id, point, payload, &payload_digest, fetched_at)?
        }
        super::FeedKind::CopernicusWave => {
            parse_copernicus_subset_csv(feed, zone_id, point, payload, &payload_digest, fetched_at)?
        }
        super::FeedKind::NoaaGfs => {
            parse_gfs_grib2_slice(feed, zone_id, point, payload, &payload_digest, fetched_at)?
        }
        super::FeedKind::NimetCap => {
            return Err(error(
                "feed_requires_external_agreement",
                "nimet_cap feeds require a concluded external agreement; no adapter ships",
            ))
        }
    };
    if readings.len() > MAX_READINGS_PER_PAYLOAD {
        return Err(error(
            "feed_payload_capacity_exceeded",
            format!("payload yielded more than {MAX_READINGS_PER_PAYLOAD} readings"),
        ));
    }
    Ok(readings)
}

fn base_reading(
    feed: &FeedSourceConfig,
    zone_id: &str,
    point: MonitoredPoint,
    payload_digest: &str,
    fetched_at: &str,
) -> NormalizedReading {
    NormalizedReading {
        schema_version: READING_SCHEMA_VERSION.to_owned(),
        reading_id: String::new(),
        feed_id: feed.feed_id.clone(),
        feed_kind: feed.kind,
        zone_id: Some(zone_id.to_owned()),
        latitude: point.latitude,
        longitude: point.longitude,
        observed_at: None,
        forecast_for: None,
        model_run_at: None,
        fetched_at: fetched_at.to_owned(),
        wave_height_m: None,
        wave_period_s: None,
        wave_direction_deg: None,
        swell_height_m: None,
        swell_period_s: None,
        wind_speed_ms: None,
        wind_gust_ms: None,
        sst_c: None,
        source_payload_sha256: payload_digest.to_owned(),
        attribution_text: feed.attribution_text.clone(),
    }
}

fn finish(mut reading: NormalizedReading) -> Result<NormalizedReading, ValidationError> {
    validate_measurement_bounds(&reading)?;
    if reading.wave_height_m.is_none()
        && reading.wave_period_s.is_none()
        && reading.swell_height_m.is_none()
        && reading.swell_period_s.is_none()
        && reading.wind_speed_ms.is_none()
        && reading.wind_gust_ms.is_none()
        && reading.sst_c.is_none()
    {
        return Err(error(
            "empty_reading",
            "payload row carried no usable measurement; refusing to fabricate one",
        ));
    }
    reading.reading_id = reading_id(
        &reading.feed_id,
        &reading.source_payload_sha256,
        reading.zone_id.as_deref(),
        reading.forecast_for.as_deref(),
        reading.observed_at.as_deref(),
    );
    Ok(reading)
}

/// Physical sanity bounds. Out-of-range values are rejected, never clamped.
fn validate_measurement_bounds(reading: &NormalizedReading) -> Result<(), ValidationError> {
    let check = |field: &'static str, value: Option<f64>, min: f64, max: f64| match value {
        None => Ok(()),
        Some(v) if v.is_finite() && (min..=max).contains(&v) => Ok(()),
        _ => Err(error(
            "out_of_range_measurement",
            format!("{field} is absent, non-finite or outside [{min}, {max}]"),
        )),
    };
    check(
        "wave_height_m",
        reading.wave_height_m,
        0.0,
        MAX_WAVE_HEIGHT_M,
    )?;
    check(
        "wave_period_s",
        reading.wave_period_s,
        0.0,
        MAX_WAVE_PERIOD_S,
    )?;
    check("wave_direction_deg", reading.wave_direction_deg, 0.0, 360.0)?;
    check(
        "swell_height_m",
        reading.swell_height_m,
        0.0,
        MAX_WAVE_HEIGHT_M,
    )?;
    check(
        "swell_period_s",
        reading.swell_period_s,
        0.0,
        MAX_WAVE_PERIOD_S,
    )?;
    check(
        "wind_speed_ms",
        reading.wind_speed_ms,
        0.0,
        MAX_WIND_SPEED_MS,
    )?;
    check("wind_gust_ms", reading.wind_gust_ms, 0.0, MAX_WIND_SPEED_MS)?;
    check("sst_c", reading.sst_c, MIN_SST_C, MAX_SST_C)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Open-Meteo Marine Forecast API (hourly JSON, iso8601 time axis).
// ---------------------------------------------------------------------------

/// The hourly variables requested from the marine endpoint. Keep in sync
/// with [`open_meteo_request_url`].
pub const OPEN_METEO_HOURLY_VARIABLES: &[&str] = &[
    "wave_height",
    "wave_direction",
    "wave_period",
    "wind_wave_height",
    "wind_wave_period",
    "swell_wave_height",
    "swell_wave_period",
    "ocean_current_velocity",
    "sea_surface_temperature",
];

/// Build the documented request URL for one monitored point (forecast of
/// `forecast_days` days on the UTC time axis).
pub fn open_meteo_request_url(base_url: &str, point: MonitoredPoint, forecast_days: u32) -> String {
    format!(
        "{base_url}?latitude={:.4}&longitude={:.4}&hourly={}&forecast_days={forecast_days}&timezone=UTC",
        point.latitude,
        point.longitude,
        OPEN_METEO_HOURLY_VARIABLES.join(",")
    )
}

fn parse_open_meteo_marine(
    feed: &FeedSourceConfig,
    zone_id: &str,
    point: MonitoredPoint,
    payload: &[u8],
    payload_digest: &str,
    fetched_at: &str,
) -> Result<Vec<NormalizedReading>, ValidationError> {
    let document: serde_json::Value = serde_json::from_slice(payload)
        .map_err(|serde_error| error("invalid_json", serde_error.to_string()))?;
    if document.get("error").and_then(|value| value.as_bool()) == Some(true) {
        return Err(error(
            "feed_api_error",
            format!(
                "open-meteo reported an error: {}",
                document
                    .get("reason")
                    .and_then(|value| value.as_str())
                    .unwrap_or("unspecified")
            ),
        ));
    }
    let hourly = document
        .get("hourly")
        .and_then(|value| value.as_object())
        .ok_or_else(|| error("invalid_feed_payload", "missing hourly object"))?;
    let times = hourly
        .get("time")
        .and_then(|value| value.as_array())
        .ok_or_else(|| error("invalid_feed_payload", "missing hourly.time array"))?;
    if times.is_empty() {
        return Err(error("invalid_feed_payload", "hourly.time is empty"));
    }
    let series = |name: &str| -> Result<Vec<Option<f64>>, ValidationError> {
        let values = hourly
            .get(name)
            .and_then(|value| value.as_array())
            .ok_or_else(|| {
                error(
                    "invalid_feed_payload",
                    format!("missing hourly.{name} array"),
                )
            })?;
        if values.len() != times.len() {
            return Err(error(
                "invalid_feed_payload",
                format!("hourly.{name} length does not match hourly.time"),
            ));
        }
        values
            .iter()
            .map(|value| match value {
                serde_json::Value::Null => Ok(None),
                serde_json::Value::Number(number) => number
                    .as_f64()
                    .map(Some)
                    .ok_or_else(|| error("invalid_feed_payload", "non-double hourly value")),
                _ => Err(error("invalid_feed_payload", "non-numeric hourly value")),
            })
            .collect()
    };
    let wave_height = series("wave_height")?;
    let wave_direction = series("wave_direction")?;
    let wave_period = series("wave_period")?;
    let wind_wave_height = series("wind_wave_height")?;
    let wind_wave_period = series("wind_wave_period")?;
    let swell_height = series("swell_wave_height")?;
    let swell_period = series("swell_wave_period")?;
    let sst = series("sea_surface_temperature")?;

    let mut readings = Vec::with_capacity(times.len());
    for (index, time) in times.iter().enumerate() {
        let time = time.as_str().ok_or_else(|| {
            error(
                "invalid_feed_payload",
                "hourly.time entries must be strings",
            )
        })?;
        // The marine API renders naive local/UTC times ("2026-08-30T06:00");
        // timezone=UTC is pinned in the request, so Zulu is authoritative.
        let forecast = DateTime::parse_from_rfc3339(&format!("{time}:00Z"))
            .or_else(|_| DateTime::parse_from_rfc3339(&format!("{time}Z")))
            .map_err(|_| error("invalid_feed_payload", "hourly.time is not iso8601"))?;
        let mut reading = base_reading(feed, zone_id, point, payload_digest, fetched_at);
        reading.forecast_for = Some(forecast.to_rfc3339());
        reading.wave_direction_deg = wave_direction[index];
        reading.wind_speed_ms = None; // marine endpoint carries no 10 m wind; GFS adapter covers wind
        reading.wave_height_m = wave_height[index].or(wind_wave_height[index]);
        reading.wave_period_s = wave_period[index].or(wind_wave_period[index]);
        reading.swell_height_m = swell_height[index];
        reading.swell_period_s = swell_period[index];
        reading.sst_c = sst[index];
        readings.push(finish(reading)?);
    }
    Ok(readings)
}

// ---------------------------------------------------------------------------
// Copernicus Marine toolbox `subset` CSV output.
// Layout (documented toolbox CSV): a header row naming `time`, `latitude`,
// `longitude` (and optionally `depth`) plus one column per variable, then
// one row per (time, point). Wave variables follow the CMEMS wave product
// conventions: VHM0 (significant wave height, m), VTPK (peak period, s),
// VMDR (mean direction, deg), VHM0_SW1 (primary swell height, m),
// VTM10 (mean swell period, s), VSDX/VSDY (Stokes drift, m/s).
// ---------------------------------------------------------------------------

fn parse_copernicus_subset_csv(
    feed: &FeedSourceConfig,
    zone_id: &str,
    point: MonitoredPoint,
    payload: &[u8],
    payload_digest: &str,
    fetched_at: &str,
) -> Result<Vec<NormalizedReading>, ValidationError> {
    let text = std::str::from_utf8(payload).map_err(|_| {
        error(
            "invalid_feed_payload",
            "copernicus subset output is not UTF-8",
        )
    })?;
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let header = lines
        .next()
        .ok_or_else(|| error("invalid_feed_payload", "copernicus subset CSV is empty"))?;
    let columns: Vec<&str> = header.split(',').map(|column| column.trim()).collect();
    let column_index = |name: &str| columns.iter().position(|column| *column == name);
    let time_col = column_index("time")
        .ok_or_else(|| error("invalid_feed_payload", "copernicus CSV lacks a time column"))?;
    let lat_col = column_index("latitude").ok_or_else(|| {
        error(
            "invalid_feed_payload",
            "copernicus CSV lacks a latitude column",
        )
    })?;
    let lon_col = column_index("longitude").ok_or_else(|| {
        error(
            "invalid_feed_payload",
            "copernicus CSV lacks a longitude column",
        )
    })?;
    let var = |names: &[&str]| names.iter().find_map(|name| column_index(name));
    let vhm0 = var(&["VHM0"]);
    let vtpk = var(&["VTPK"]);
    let vmdr = var(&["VMDR"]);
    let swell = var(&["VHM0_SW1"]);
    let swell_period = var(&["VTM10", "VTPK_SW1"]);
    if vhm0.is_none() && swell.is_none() {
        return Err(error(
            "invalid_feed_payload",
            "copernicus CSV carries none of the documented wave variables (VHM0/VHM0_SW1)",
        ));
    }
    let cell = |row: &[&str], index: usize| -> Result<Option<f64>, ValidationError> {
        let raw = row
            .get(index)
            .ok_or_else(|| error("invalid_feed_payload", "copernicus CSV row is short"))?
            .trim();
        if raw.is_empty() || raw.eq_ignore_ascii_case("nan") {
            return Ok(None);
        }
        raw.parse::<f64>().map(Some).map_err(|_| {
            error(
                "invalid_feed_payload",
                "copernicus CSV cell is not a number",
            )
        })
    };
    let mut readings = Vec::new();
    for line in lines {
        let row: Vec<&str> = line.split(',').collect();
        if row.len() < columns.len() {
            return Err(error(
                "invalid_feed_payload",
                "copernicus CSV row has fewer cells than the header",
            ));
        }
        let timestamp = row
            .get(time_col)
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| error("invalid_feed_payload", "copernicus CSV row lacks a time"))?;
        let valid_time = DateTime::parse_from_rfc3339(timestamp).map_err(|_| {
            error(
                "invalid_feed_payload",
                "copernicus CSV time is not RFC 3339",
            )
        })?;
        let latitude: f64 = row[lat_col].trim().parse().map_err(|_| {
            error(
                "invalid_feed_payload",
                "copernicus CSV latitude is not a number",
            )
        })?;
        let longitude: f64 = row[lon_col].trim().parse().map_err(|_| {
            error(
                "invalid_feed_payload",
                "copernicus CSV longitude is not a number",
            )
        })?;
        // The subset is requested around the monitored point; rows that do
        // not resolve inside it are rejected, never silently re-assigned.
        let row_point = GeoPosition::new(latitude, longitude)?;
        let requested = point.position()?;
        let close = (row_point.latitude() - requested.latitude()).abs() <= 0.25
            && (row_point.longitude() - requested.longitude()).abs() <= 0.25;
        if !close {
            return Err(error(
                "feed_point_mismatch",
                "copernicus CSV row is outside the requested monitored point neighbourhood",
            ));
        }
        let mut reading = base_reading(feed, zone_id, point, payload_digest, fetched_at);
        reading.latitude = row_point.latitude();
        reading.longitude = row_point.longitude();
        reading.forecast_for = Some(valid_time.to_rfc3339());
        reading.wave_height_m = match vhm0 {
            Some(index) => cell(&row, index)?,
            None => None,
        };
        reading.wave_period_s = match vtpk {
            Some(index) => cell(&row, index)?,
            None => None,
        };
        reading.wave_direction_deg = match vmdr {
            Some(index) => cell(&row, index)?,
            None => None,
        };
        reading.swell_height_m = match swell {
            Some(index) => cell(&row, index)?,
            None => None,
        };
        reading.swell_period_s = match swell_period {
            Some(index) => cell(&row, index)?,
            None => None,
        };
        readings.push(finish(reading)?);
    }
    if readings.is_empty() {
        return Err(error(
            "invalid_feed_payload",
            "copernicus CSV carried a header but no data rows",
        ));
    }
    Ok(readings)
}

// ---------------------------------------------------------------------------
// NOAA GFS via NOMADS GRIB2 filter slices (WMO FM-92 GRIB edition 2).
// Only the exact templates the documented filter endpoint returns are
// supported: grid 3.0 (regular lat/lon), product 4.0 (analysis/forecast at
// a fixed level), data representation 5.0 (simple packing), no bitmap.
// Anything else fails closed.
// ---------------------------------------------------------------------------

/// Request URL for a 10 m wind slice around the monitored point.
pub fn gfs_request_url(
    base_url: &str,
    point: MonitoredPoint,
    model_run: &str,
    forecast_hour: u32,
) -> Result<String, ValidationError> {
    // model_run is the NOMADS directory stamp "YYYYMMDD/HH".
    let valid = model_run.len() == 11
        && model_run.as_bytes()[8] == b'/'
        && model_run
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'/');
    if !valid || forecast_hour > 384 {
        return Err(error(
            "invalid_feed_config",
            "GFS model run must be stamped YYYYMMDD/HH and forecast hour at most 384",
        ));
    }
    let half = 1.0_f64;
    let left = (point.longitude - half).max(-180.0);
    let right = (point.longitude + half).min(180.0);
    let bottom = (point.latitude - half).max(-90.0);
    let top = (point.latitude + half).min(90.0);
    Ok(format!(
        "{base_url}?file=gfs.t{hour}z.pgrb2.0p25.f{forecast:03}&lev_10_m_above_ground=on\
         &var_UGRD=on&var_VGRD=on&subregion=&leftlon={left}&rightlon={right}\
         &toplat={top}&bottomlat={bottom}&dir=%2Fgfs.{date}%2F{hour}%2Fatmos",
        date = &model_run[..8],
        hour = &model_run[9..11],
        forecast = forecast_hour,
    ))
}

struct GribMessage {
    parameter: u8,
    reference_time: DateTime<FixedOffset>,
    forecast_for: DateTime<FixedOffset>,
    ni: usize,
    nj: usize,
    lat_first: f64,
    lon_first: f64,
    di: f64,
    dj: f64,
    lat_decreases: bool,
    values: Vec<f64>,
}

fn parse_gfs_grib2_slice(
    feed: &FeedSourceConfig,
    zone_id: &str,
    point: MonitoredPoint,
    payload: &[u8],
    payload_digest: &str,
    fetched_at: &str,
) -> Result<Vec<NormalizedReading>, ValidationError> {
    let mut u_component: Option<GribMessage> = None;
    let mut v_component: Option<GribMessage> = None;
    let mut model_run_at: Option<DateTime<FixedOffset>> = None;
    let mut offset = 0usize;
    while offset + 16 <= payload.len() {
        if &payload[offset..offset + 4] != b"GRIB" {
            return Err(error(
                "invalid_feed_payload",
                "GRIB2 indicator section missing",
            ));
        }
        if payload[offset + 7] != 2 {
            return Err(error(
                "unsupported_grib_edition",
                "only GRIB edition 2 is supported",
            ));
        }
        let total = read_u64(payload, offset + 8)? as usize;
        if total < 20 || offset + total > payload.len() {
            return Err(error(
                "invalid_feed_payload",
                "GRIB2 message length is invalid",
            ));
        }
        let message = parse_grib2_message(&payload[offset..offset + total])?;
        if &payload[offset + total - 4..offset + total] != b"7777" {
            return Err(error("invalid_feed_payload", "GRIB2 end section missing"));
        }
        model_run_at = Some(message.reference_time);
        match message.parameter {
            2 => u_component = Some(message),
            3 => v_component = Some(message),
            _ => {}
        }
        offset += total;
    }
    if offset != payload.len() {
        return Err(error(
            "invalid_feed_payload",
            "trailing bytes after GRIB2 messages",
        ));
    }
    let (u_message, v_message) = match (u_component, v_component) {
        (Some(u), Some(v)) => (u, v),
        _ => {
            return Err(error(
                "invalid_feed_payload",
                "GFS slice must carry both UGRD and VGRD messages",
            ))
        }
    };
    if u_message.ni != v_message.ni
        || u_message.nj != v_message.nj
        || u_message.forecast_for != v_message.forecast_for
    {
        return Err(error(
            "invalid_feed_payload",
            "UGRD and VGRD messages disagree on grid or validity time",
        ));
    }
    let requested = point.position()?;
    let grid_index = nearest_grid_index(&u_message, requested.latitude(), requested.longitude())?;
    let u = *u_message
        .values
        .get(grid_index)
        .ok_or_else(|| error("invalid_feed_payload", "UGRD grid index out of range"))?;
    let v = *v_message
        .values
        .get(grid_index)
        .ok_or_else(|| error("invalid_feed_payload", "VGRD grid index out of range"))?;
    let (lat, lon) = grid_position(&u_message, grid_index);
    let speed = (u * u + v * v).sqrt();
    let mut reading = base_reading(feed, zone_id, point, payload_digest, fetched_at);
    reading.latitude = lat;
    reading.longitude = lon;
    reading.forecast_for = Some(u_message.forecast_for.to_rfc3339());
    reading.model_run_at = model_run_at.map(|run| run.to_rfc3339());
    reading.wind_speed_ms = Some(speed);
    finish(reading).map(|reading| vec![reading])
}

fn read_u16(payload: &[u8], offset: usize) -> Result<u16, ValidationError> {
    let bytes: [u8; 2] = payload
        .get(offset..offset + 2)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| error("invalid_feed_payload", "GRIB2 section truncated"))?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u32(payload: &[u8], offset: usize) -> Result<u32, ValidationError> {
    let bytes: [u8; 4] = payload
        .get(offset..offset + 4)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| error("invalid_feed_payload", "GRIB2 section truncated"))?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_i32(payload: &[u8], offset: usize) -> Result<i32, ValidationError> {
    Ok(read_u32(payload, offset)? as i32)
}

fn read_u64(payload: &[u8], offset: usize) -> Result<u64, ValidationError> {
    let bytes: [u8; 8] = payload
        .get(offset..offset + 8)
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| error("invalid_feed_payload", "GRIB2 section truncated"))?;
    Ok(u64::from_be_bytes(bytes))
}

fn read_f32(payload: &[u8], offset: usize) -> Result<f32, ValidationError> {
    Ok(f32::from_bits(read_u32(payload, offset)?))
}

fn scaled_coord(raw: i32) -> f64 {
    // GRIB2 lat/lon values are scaled by 1e-6 degrees.
    (raw as f64) / 1_000_000.0
}

fn parse_grib2_message(message: &[u8]) -> Result<GribMessage, ValidationError> {
    let mut section = 16usize; // section 0 is 16 bytes
    let end = message.len() - 4;
    let mut reference_time: Option<DateTime<FixedOffset>> = None;
    let mut grid: Option<(usize, usize, f64, f64, f64, f64, bool)> = None;
    let mut product: Option<(u8, DateTime<FixedOffset>)> = None;
    let mut packing: Option<(f64, i32, i32, u8, usize)> = None;
    let mut bitmap_seen = false;
    let mut values: Option<Vec<f64>> = None;
    while section < end {
        let length = read_u32(message, section)? as usize;
        if length < 5 || section + length > end + 4 {
            return Err(error(
                "invalid_feed_payload",
                "GRIB2 section length is invalid",
            ));
        }
        let kind = *message
            .get(section + 4)
            .ok_or_else(|| error("invalid_feed_payload", "GRIB2 section truncated"))?;
        match kind {
            1 => {
                // Identification: reference time at offsets 12..19.
                let year = read_u16(message, section + 12)? as i32;
                let (month, day, hour, minute, second) = (
                    *message.get(section + 14).unwrap_or(&0),
                    *message.get(section + 15).unwrap_or(&0),
                    *message.get(section + 16).unwrap_or(&0),
                    *message.get(section + 17).unwrap_or(&0),
                    *message.get(section + 18).unwrap_or(&0),
                );
                let naive =
                    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z");
                reference_time =
                    Some(DateTime::parse_from_rfc3339(&naive).map_err(|_| {
                        error("invalid_feed_payload", "GRIB2 reference time invalid")
                    })?);
            }
            3 => {
                if read_u16(message, section + 12)? != 0 {
                    return Err(error(
                        "unsupported_grib_template",
                        "only grid template 3.0 (regular lat/lon) is supported",
                    ));
                }
                let ni = read_u32(message, section + 30)? as usize;
                let nj = read_u32(message, section + 34)? as usize;
                let lat_first = scaled_coord(read_i32(message, section + 46)?);
                let lon_first = scaled_coord(read_i32(message, section + 50)?);
                let lat_last = scaled_coord(read_i32(message, section + 55)?);
                let lon_last = scaled_coord(read_i32(message, section + 59)?);
                let di = scaled_coord(read_u32(message, section + 63)? as i32);
                let dj = scaled_coord(read_u32(message, section + 67)? as i32);
                let scanning = *message
                    .get(section + 71)
                    .ok_or_else(|| error("invalid_feed_payload", "GRIB2 grid truncated"))?;
                // Reject boustrophedon and other non-row-major scans. The
                // latitude row direction is derived from the grid corners:
                // NCEP's filter endpoint does not always keep the WMO scan
                // flag bit and the La1 corner consistent, while the corners
                // plus increments are the documented grid definition.
                if scanning & 0b1010_1111 != 0 {
                    return Err(error(
                        "unsupported_grib_scanning",
                        "only standard row-major +i scanning modes are supported",
                    ));
                }
                let lat_decreases = lat_last < lat_first;
                let span_lat = if lat_decreases { -dj } else { dj } * (nj as f64 - 1.0);
                let span_lon = di * (ni as f64 - 1.0);
                if ni == 0
                    || nj == 0
                    || (lat_first + span_lat - lat_last).abs() > 1e-4
                    || (lon_first + span_lon - lon_last).abs() > 1e-4
                {
                    return Err(error(
                        "invalid_feed_payload",
                        "GRIB2 grid corners are inconsistent with the scan increments",
                    ));
                }
                grid = Some((ni, nj, lat_first, lon_first, di, dj, lat_decreases));
            }
            4 => {
                if read_u16(message, section + 7)? != 0 {
                    return Err(error(
                        "unsupported_grib_template",
                        "only product template 4.0 (analysis/forecast) is supported",
                    ));
                }
                let category = *message
                    .get(section + 9)
                    .ok_or_else(|| error("invalid_feed_payload", "GRIB2 product truncated"))?;
                let parameter = *message
                    .get(section + 10)
                    .ok_or_else(|| error("invalid_feed_payload", "GRIB2 product truncated"))?;
                if category != 2 {
                    return Err(error(
                        "unsupported_grib_parameter",
                        "only momentum (wind) parameters are decoded",
                    ));
                }
                let time_unit = *message.get(section + 17).unwrap_or(&1);
                let forecast = read_u32(message, section + 18)? as i64;
                let level_type = *message.get(section + 22).unwrap_or(&0);
                let level_scale = *message.get(section + 23).unwrap_or(&0) as i32;
                let level_value = read_u32(message, section + 24)? as i32;
                let level_meters = (level_value as f64) * 10_f64.powi(-level_scale);
                // 103 = specified height above ground; the request pins 10 m.
                if level_type != 103 || (level_meters - 10.0).abs() > 0.5 {
                    return Err(error(
                        "unsupported_grib_level",
                        "only 10 m above-ground wind is decoded",
                    ));
                }
                let reference = reference_time.ok_or_else(|| {
                    error(
                        "invalid_feed_payload",
                        "GRIB2 product precedes identification",
                    )
                })?;
                let delta = match time_unit {
                    0 => Duration::minutes(forecast),
                    1 => Duration::hours(forecast),
                    2 => Duration::days(forecast),
                    10 => Duration::hours(forecast * 3),
                    11 => Duration::hours(forecast * 6),
                    12 => Duration::hours(forecast * 12),
                    13 => Duration::seconds(forecast),
                    _ => {
                        return Err(error(
                            "unsupported_grib_time_unit",
                            "unsupported GRIB2 forecast time unit",
                        ))
                    }
                };
                product = Some((parameter, reference + delta));
            }
            5 => {
                if read_u16(message, section + 9)? != 0 {
                    return Err(error(
                        "unsupported_grib_template",
                        "only data representation 5.0 (simple packing) is supported",
                    ));
                }
                let count = read_u32(message, section + 5)? as usize;
                let reference = read_f32(message, section + 11)? as f64;
                let binary_scale = read_u16(message, section + 15)? as i16 as i32;
                let decimal_scale = read_u16(message, section + 17)? as i16 as i32;
                let bits = *message
                    .get(section + 19)
                    .ok_or_else(|| error("invalid_feed_payload", "GRIB2 packing truncated"))?;
                packing = Some((reference, binary_scale, decimal_scale, bits, count));
            }
            6 => {
                let indicator = *message.get(section + 5).unwrap_or(&255);
                if indicator != 255 {
                    return Err(error(
                        "unsupported_grib_bitmap",
                        "bitmap-masked GRIB2 data is not supported",
                    ));
                }
                bitmap_seen = true;
            }
            7 => {
                let (reference, binary_scale, decimal_scale, bits, count) =
                    packing.ok_or_else(|| {
                        error(
                            "invalid_feed_payload",
                            "GRIB2 data precedes packing definition",
                        )
                    })?;
                if !bitmap_seen {
                    return Err(error(
                        "invalid_feed_payload",
                        "GRIB2 data section precedes the bitmap section",
                    ));
                }
                if !reference.is_finite() {
                    return Err(error(
                        "invalid_feed_payload",
                        "GRIB2 reference value invalid",
                    ));
                }
                let data = &message[section + 5..section + length];
                let mut decoded = Vec::with_capacity(count);
                let mut reader = BitReader::new(data, bits);
                for _ in 0..count {
                    let packed = reader.next().ok_or_else(|| {
                        error("invalid_feed_payload", "GRIB2 packed data truncated")
                    })?;
                    let value = (reference + (packed as f64) * 2_f64.powi(binary_scale))
                        / 10_f64.powi(decimal_scale);
                    if !value.is_finite() {
                        return Err(error(
                            "invalid_feed_payload",
                            "GRIB2 decoded value non-finite",
                        ));
                    }
                    decoded.push(value);
                }
                values = Some(decoded);
            }
            _ => {}
        }
        section += length;
        if kind == 7 {
            break;
        }
    }
    let (parameter, forecast_for) = product.ok_or_else(|| {
        error(
            "invalid_feed_payload",
            "GRIB2 message lacks a product section",
        )
    })?;
    let (ni, nj, lat_first, lon_first, di, dj, lat_decreases) =
        grid.ok_or_else(|| error("invalid_feed_payload", "GRIB2 message lacks a grid section"))?;
    let values = values
        .ok_or_else(|| error("invalid_feed_payload", "GRIB2 message lacks a data section"))?;
    if values.len() != ni * nj {
        return Err(error(
            "invalid_feed_payload",
            "GRIB2 decoded value count does not match the grid",
        ));
    }
    Ok(GribMessage {
        parameter,
        reference_time: reference_time
            .ok_or_else(|| error("invalid_feed_payload", "GRIB2 lacks identification"))?,
        forecast_for,
        ni,
        nj,
        lat_first,
        lon_first,
        di,
        dj,
        lat_decreases,
        values,
    })
}

/// MSB-first packed unsigned integer reader (GRIB2 simple packing).
struct BitReader<'a> {
    data: &'a [u8],
    bits: u8,
    bit_position: usize,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8], bits: u8) -> Self {
        Self {
            data,
            bits,
            bit_position: 0,
        }
    }

    fn next(&mut self) -> Option<u64> {
        if self.bits == 0 {
            return Some(0);
        }
        if self.bits > 64 {
            return None;
        }
        let width = self.bits as usize;
        if self.bit_position + width > self.data.len() * 8 {
            return None;
        }
        let mut value = 0u64;
        for _ in 0..width {
            let byte = self.data[self.bit_position / 8];
            let bit = (byte >> (7 - (self.bit_position % 8))) & 1;
            value = (value << 1) | u64::from(bit);
            self.bit_position += 1;
        }
        Some(value)
    }
}

fn grid_position(grid: &GribMessage, index: usize) -> (f64, f64) {
    let row = index / grid.ni;
    let column = index % grid.ni;
    let latitude = if grid.lat_decreases {
        grid.lat_first - grid.dj * row as f64
    } else {
        grid.lat_first + grid.dj * row as f64
    };
    (latitude, grid.lon_first + grid.di * column as f64)
}

fn nearest_grid_index(
    grid: &GribMessage,
    latitude: f64,
    longitude: f64,
) -> Result<usize, ValidationError> {
    let column = ((longitude - grid.lon_first) / grid.di).round();
    let row_span = if grid.lat_decreases {
        -grid.dj
    } else {
        grid.dj
    };
    let row = ((latitude - grid.lat_first) / row_span).round();
    if column < 0.0 || row < 0.0 {
        return Err(error(
            "feed_point_outside_grid",
            "monitored point lies outside the GFS slice grid",
        ));
    }
    let (column, row) = (column as usize, row as usize);
    if column >= grid.ni || row >= grid.nj {
        return Err(error(
            "feed_point_outside_grid",
            "monitored point lies outside the GFS slice grid",
        ));
    }
    let (lat, lon) = grid_position(grid, row * grid.ni + column);
    if (lat - latitude).abs() > grid.dj || (lon - longitude).abs() > grid.di {
        return Err(error(
            "feed_point_outside_grid",
            "monitored point is not representable on the GFS slice grid",
        ));
    }
    Ok(row * grid.ni + column)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metocean::FeedKind;

    const OPEN_METEO_FIXTURE: &str =
        include_str!("../../tests/fixtures/metocean/open_meteo_marine_sample.json");
    const COPERNICUS_FIXTURE: &str =
        include_str!("../../tests/fixtures/metocean/copernicus_wave_subset_sample.csv");
    const GFS_FIXTURE: &[u8] =
        include_bytes!("../../tests/fixtures/metocean/gfs_10m_wind_slice.grb2");

    fn feed(kind: FeedKind) -> FeedSourceConfig {
        FeedSourceConfig {
            feed_id: format!("feed-{}", kind.as_str()),
            kind,
            base_url: kind.default_base_url().to_owned(),
            poll_interval_seconds: 900,
            attribution_text: match kind {
                FeedKind::OpenMeteoMarine => "Weather data by Open-Meteo.com".to_owned(),
                FeedKind::CopernicusWave => {
                    "Contains modified Copernicus Marine Service information".to_owned()
                }
                FeedKind::NoaaGfs => "NOAA GFS (NCEP/NOMADS), public domain".to_owned(),
                FeedKind::NimetCap => unreachable!("nimet feeds are not configurable"),
            },
            enabled: true,
        }
    }

    fn point() -> MonitoredPoint {
        MonitoredPoint {
            latitude: 6.0,
            longitude: 3.0,
        }
    }

    #[test]
    fn open_meteo_fixture_parses_into_bound_readings() {
        let feed = feed(FeedKind::OpenMeteoMarine);
        let readings = parse_feed_payload(
            &feed,
            "hz-lagos-approach",
            point(),
            OPEN_METEO_FIXTURE.as_bytes(),
            "2026-08-30T12:00:00Z",
        )
        .expect("fixture payload parses");
        assert_eq!(readings.len(), 24);
        let first = &readings[0];
        assert_eq!(
            first.forecast_for.as_deref(),
            Some("2026-08-30T00:00:00+00:00")
        );
        assert_eq!(first.attribution_text, "Weather data by Open-Meteo.com");
        assert_eq!(first.schema_version, READING_SCHEMA_VERSION);
        assert_eq!(first.source_payload_sha256.len(), 64);
        assert!(first.wave_height_m.expect("wave height") > 0.0);
        assert!(first.reading_id.starts_with("mor-"));
        for reading in &readings {
            validate_measurement_bounds(reading).expect("in range");
        }
    }

    #[test]
    fn open_meteo_api_error_and_shape_errors_fail_closed() {
        let feed = feed(FeedKind::OpenMeteoMarine);
        let api_error = br#"{"error":true,"reason":"latitude is invalid"}"#;
        assert_eq!(
            parse_feed_payload(&feed, "zone", point(), api_error, "2026-08-30T12:00:00Z")
                .unwrap_err()
                .code,
            "feed_api_error"
        );
        let wrong_shape = br#"{"hourly":{"time":[],"wave_height":[]}}"#;
        assert_eq!(
            parse_feed_payload(&feed, "zone", point(), wrong_shape, "2026-08-30T12:00:00Z")
                .unwrap_err()
                .code,
            "invalid_feed_payload"
        );
        let mut tampered: serde_json::Value =
            serde_json::from_str(OPEN_METEO_FIXTURE).expect("fixture json");
        tampered["hourly"]["wave_height"][0] = serde_json::json!(500.0);
        assert_eq!(
            parse_feed_payload(
                &feed,
                "zone",
                point(),
                serde_json::to_vec(&tampered).expect("encode").as_slice(),
                "2026-08-30T12:00:00Z"
            )
            .unwrap_err()
            .code,
            "out_of_range_measurement"
        );
        tampered["hourly"]["wave_height"][0] = serde_json::Value::Null;
        tampered["hourly"]["wave_direction"][0] = serde_json::Value::Null;
        tampered["hourly"]["wave_period"][0] = serde_json::Value::Null;
        tampered["hourly"]["wind_wave_height"][0] = serde_json::Value::Null;
        tampered["hourly"]["wind_wave_period"][0] = serde_json::Value::Null;
        tampered["hourly"]["swell_wave_height"][0] = serde_json::Value::Null;
        tampered["hourly"]["swell_wave_period"][0] = serde_json::Value::Null;
        tampered["hourly"]["sea_surface_temperature"][0] = serde_json::Value::Null;
        assert_eq!(
            parse_feed_payload(
                &feed,
                "zone",
                point(),
                serde_json::to_vec(&tampered).expect("encode").as_slice(),
                "2026-08-30T12:00:00Z"
            )
            .unwrap_err()
            .code,
            "empty_reading"
        );
    }

    #[test]
    fn copernicus_fixture_parses_documented_wave_variables() {
        let feed = feed(FeedKind::CopernicusWave);
        let readings = parse_feed_payload(
            &feed,
            "hz-lagos-approach",
            point(),
            COPERNICUS_FIXTURE.as_bytes(),
            "2026-08-30T12:00:00Z",
        )
        .expect("fixture payload parses");
        assert_eq!(readings.len(), 3);
        let first = &readings[0];
        assert_eq!(first.wave_height_m, Some(1.42));
        assert_eq!(first.wave_period_s, Some(9.6));
        assert_eq!(first.swell_height_m, Some(1.05));
        assert!(first.attribution_text.contains("Copernicus Marine Service"));
        let malformed = b"time,latitude,longitude,VHM0\nnot-a-time,6.0,3.0,1.2\n";
        assert_eq!(
            parse_feed_payload(&feed, "zone", point(), malformed, "2026-08-30T12:00:00Z")
                .unwrap_err()
                .code,
            "invalid_feed_payload"
        );
        let far_away = b"time,latitude,longitude,VHM0\n2026-08-30T00:00:00Z,40.0,-30.0,1.2\n";
        assert_eq!(
            parse_feed_payload(&feed, "zone", point(), far_away, "2026-08-30T12:00:00Z")
                .unwrap_err()
                .code,
            "feed_point_mismatch"
        );
    }

    #[test]
    fn gfs_grib2_fixture_decodes_10m_wind() {
        let feed = feed(FeedKind::NoaaGfs);
        let readings = parse_feed_payload(
            &feed,
            "hz-lagos-approach",
            point(),
            GFS_FIXTURE,
            "2026-08-30T12:00:00Z",
        )
        .expect("fixture payload parses");
        assert_eq!(readings.len(), 1);
        let reading = &readings[0];
        let speed = reading.wind_speed_ms.expect("wind speed decoded");
        assert!(
            speed > 0.0 && speed < 60.0,
            "plausible Gulf of Guinea wind: {speed}"
        );
        assert_eq!(
            reading.forecast_for.as_deref(),
            Some("2026-08-30T03:00:00+00:00")
        );
        assert_eq!(
            reading.model_run_at.as_deref(),
            Some("2026-08-30T00:00:00+00:00")
        );
        assert!((reading.latitude - 6.0).abs() < 1e-9);
        assert!((reading.longitude - 3.0).abs() < 1e-9);
        // Truncated slices and non-GRIB bytes fail closed.
        assert_eq!(
            parse_feed_payload(
                &feed,
                "zone",
                point(),
                &GFS_FIXTURE[..100],
                "2026-08-30T12:00:00Z"
            )
            .unwrap_err()
            .code,
            "invalid_feed_payload"
        );
        assert_eq!(
            parse_feed_payload(&feed, "zone", point(), b"NOTGRIB", "2026-08-30T12:00:00Z")
                .unwrap_err()
                .code,
            "invalid_feed_payload"
        );
    }

    #[test]
    fn gfs_point_outside_grid_fails_closed() {
        let feed = feed(FeedKind::NoaaGfs);
        let far = MonitoredPoint {
            latitude: 6.0,
            longitude: 10.0,
        };
        assert_eq!(
            parse_feed_payload(&feed, "zone", far, GFS_FIXTURE, "2026-08-30T12:00:00Z")
                .unwrap_err()
                .code,
            "feed_point_outside_grid"
        );
    }

    #[test]
    fn nimet_adapter_refuses_without_external_agreement() {
        let mut feed = feed(FeedKind::OpenMeteoMarine);
        feed.kind = FeedKind::NimetCap;
        assert_eq!(
            parse_feed_payload(&feed, "zone", point(), b"{}", "2026-08-30T12:00:00Z")
                .unwrap_err()
                .code,
            "feed_requires_external_agreement"
        );
    }

    #[test]
    fn request_urls_follow_the_documented_api_shapes() {
        let url = open_meteo_request_url("https://marine-api.open-meteo.com/v1/marine", point(), 3);
        assert!(url.contains("latitude=6.0000"));
        assert!(url.contains("longitude=3.0000"));
        assert!(url.contains("wave_height"));
        assert!(url.contains("timezone=UTC"));
        let gfs = gfs_request_url(
            "https://nomads.ncep.noaa.gov/cgi-bin/filter_gfs_0p25.pl",
            point(),
            "20260830/00",
            3,
        )
        .expect("valid run stamp");
        assert!(gfs.contains("file=gfs.t00z.pgrb2.0p25.f003"));
        assert!(gfs.contains("var_UGRD=on"));
        assert!(gfs.contains("dir=%2Fgfs.20260830%2F00%2Fatmos"));
        assert!(gfs_request_url("", point(), "2026-08-30", 3).is_err());
    }
}
