//! NMEA 0183 sentence parsing for AIS-receiver and GPS feeds.
//!
//! The vessel-side gateway consumes the navigation sentences published by the
//! AIS receiver (or the vessel GNSS feed forwarded alongside AIS traffic) over
//! TCP or serial. Only the position/time sentences needed by Workstream B are
//! decoded: `RMC` (recommended minimum: position, speed, course, full
//! timestamp) and `GGA` (fix data: position and time-of-day). Encapsulated AIS
//! payloads (`!AIVDM`/`!AIVDO`) and every other formatter are rejected with a
//! structured error so the caller can dead-letter them; parsing never panics
//! and never produces a partial or fabricated fix.
//!
//! Checksums are mandatory: a sentence without a valid `*HH` XOR checksum is
//! rejected. This fail-closed posture matches the crate-wide rule that
//! malformed input is an explicit error, never a guess.

use chrono::{DateTime, FixedOffset, NaiveDate, NaiveTime};

/// NMEA 0183 sentences are limited to 82 characters including framing; a
/// small margin is refused above this to bound memory on hostile input.
pub const MAX_SENTENCE_BYTES: usize = 82;

/// A structured parse failure. `code` is stable for dead-letter routing and
/// metrics; `message` is diagnostic only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NmeaError {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for NmeaError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for NmeaError {}

fn error(code: &'static str, message: impl Into<String>) -> NmeaError {
    NmeaError {
        code,
        message: message.into(),
    }
}

/// Parsed `RMC` fix: full UTC timestamp, position, speed, and course.
#[derive(Clone, Debug, PartialEq)]
pub struct RmcFix {
    pub observed_at: DateTime<FixedOffset>,
    pub latitude: f64,
    pub longitude: f64,
    pub speed_knots: Option<f64>,
    pub course_degrees: Option<f64>,
}

/// Parsed `GGA` fix: position plus fix quality metadata. The sentence carries
/// only a time-of-day, so the gateway combines it with its wall-clock date
/// (documented in `gateway`); `RMC` is preferred whenever available.
#[derive(Clone, Debug, PartialEq)]
pub struct GgaFix {
    pub time_of_day: NaiveTime,
    pub latitude: f64,
    pub longitude: f64,
    pub fix_quality: u8,
    pub satellites_in_use: u8,
    pub hdop: Option<f64>,
    pub altitude_meters: Option<f64>,
}

/// One successfully decoded sentence.
#[derive(Clone, Debug, PartialEq)]
pub enum NmeaSentence {
    Rmc(RmcFix),
    Gga(GgaFix),
}

/// Parse one NMEA 0183 sentence (a single line, with or without the trailing
/// CR/LF). Returns [`NmeaError`] for any malformed, truncated, bad-checksum,
/// out-of-range, or unsupported sentence.
pub fn parse_sentence(raw: &str) -> Result<NmeaSentence, NmeaError> {
    let line = raw.trim_end_matches(['\r', '\n']);
    if line.is_empty() {
        return Err(error("empty_sentence", "sentence is empty"));
    }
    if line.len() > MAX_SENTENCE_BYTES {
        return Err(error(
            "sentence_too_long",
            format!("sentence exceeds {MAX_SENTENCE_BYTES} bytes"),
        ));
    }
    let body = line
        .strip_prefix('$')
        .ok_or_else(|| error("unsupported_sentence", "only '$' sentences are decoded"))?;
    let (content, checksum_text) = body
        .split_once('*')
        .ok_or_else(|| error("missing_checksum", "sentence has no '*HH' checksum"))?;
    let expected = u8::from_str_radix(checksum_text, 16)
        .map_err(|_| error("invalid_checksum", "checksum is not two hexadecimal digits"))?;
    if checksum_text.len() != 2 || !checksum_text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(error(
            "invalid_checksum",
            "checksum is not two hexadecimal digits",
        ));
    }
    let observed = content.bytes().fold(0u8, |acc, byte| acc ^ byte);
    if observed != expected {
        return Err(error(
            "checksum_mismatch",
            format!("checksum {expected:02X} does not match computed {observed:02X}"),
        ));
    }
    let fields: Vec<&str> = content.split(',').collect();
    let header = fields
        .first()
        .copied()
        .ok_or_else(|| error("invalid_sentence", "sentence has no address field"))?;
    if header.len() != 5 || !header.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(error(
            "invalid_sentence",
            "address field must be a 5-character uppercase talker+formatter",
        ));
    }
    let formatter = &header[2..5];
    match formatter {
        "RMC" => parse_rmc(&fields[1..]).map(NmeaSentence::Rmc),
        "GGA" => parse_gga(&fields[1..]).map(NmeaSentence::Gga),
        _ => Err(error(
            "unsupported_sentence",
            format!("formatter {formatter} is not decoded (RMC/GGA only)"),
        )),
    }
}

fn parse_rmc(fields: &[&str]) -> Result<RmcFix, NmeaError> {
    // RMC: time,status,lat,NS,lon,EW,speed,course,date[,magvar,magEW[,mode]]
    if fields.len() < 9 {
        return Err(error(
            "invalid_sentence",
            "RMC sentence has fewer than 9 data fields",
        ));
    }
    let time = parse_time_of_day(fields[0])?;
    let status = fields[1];
    if status != "A" {
        return Err(error(
            "invalid_fix",
            "RMC status is not 'A' (valid); void fixes are dead-lettered",
        ));
    }
    let latitude = parse_coordinate(fields[2], fields[3], 2)?;
    let longitude = parse_coordinate(fields[4], fields[5], 3)?;
    let speed_knots = parse_optional_decimal(fields[6], 0.0, 200.0, "speed")?;
    let course_degrees = parse_optional_decimal(fields[7], 0.0, 360.0, "course")?;
    let date = parse_date(fields[8])?;
    let naive = date.and_time(time);
    let offset = FixedOffset::east_opt(0)
        .ok_or_else(|| error("invalid_timestamp", "zero UTC offset is not constructible"))?;
    let observed_at = DateTime::from_naive_utc_and_offset(naive, offset);
    Ok(RmcFix {
        observed_at,
        latitude,
        longitude,
        speed_knots,
        course_degrees,
    })
}

fn parse_gga(fields: &[&str]) -> Result<GgaFix, NmeaError> {
    // GGA: time,lat,NS,lon,EW,quality,sats,hdop,alt,M[,geoid,M,age,station]
    if fields.len() < 11 {
        return Err(error(
            "invalid_sentence",
            "GGA sentence has fewer than 11 data fields",
        ));
    }
    let time_of_day = parse_time_of_day(fields[0])?;
    let fix_quality: u8 = fields[5]
        .parse()
        .map_err(|_| error("invalid_field", "GGA fix quality is not an integer"))?;
    if fix_quality == 0 {
        return Err(error(
            "invalid_fix",
            "GGA fix quality 0 (no fix); sentence is dead-lettered",
        ));
    }
    let latitude = parse_coordinate(fields[1], fields[2], 2)?;
    let longitude = parse_coordinate(fields[3], fields[4], 3)?;
    let satellites_in_use: u8 = fields[6]
        .parse()
        .map_err(|_| error("invalid_field", "GGA satellite count is not an integer"))?;
    let hdop = parse_optional_decimal(fields[7], 0.0, 99.9, "hdop")?;
    let altitude_meters = parse_optional_decimal(fields[8], -500.0, 20_000.0, "altitude")?;
    Ok(GgaFix {
        time_of_day,
        latitude,
        longitude,
        fix_quality,
        satellites_in_use,
        hdop,
        altitude_meters,
    })
}

/// Parse `hhmmss` or `hhmmss.ss(s)` into a [`NaiveTime`].
fn parse_time_of_day(text: &str) -> Result<NaiveTime, NmeaError> {
    let invalid = || {
        error(
            "invalid_timestamp",
            format!("time field {text:?} is malformed"),
        )
    };
    let (hms, fraction) = text.split_once('.').unwrap_or((text, ""));
    if hms.len() != 6 || !hms.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid());
    }
    if !fraction.is_empty()
        && (fraction.len() > 3 || !fraction.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(invalid());
    }
    let hour: u32 = hms[0..2].parse().map_err(|_| invalid())?;
    let minute: u32 = hms[2..4].parse().map_err(|_| invalid())?;
    let second: u32 = hms[4..6].parse().map_err(|_| invalid())?;
    let millis: u32 = if fraction.is_empty() {
        0
    } else {
        let mut scaled: u32 = fraction.parse().map_err(|_| invalid())?;
        for _ in fraction.len()..3 {
            scaled *= 10;
        }
        scaled
    };
    NaiveTime::from_hms_milli_opt(hour, minute, second, millis).ok_or_else(invalid)
}

/// Parse `ddmmyy` with the documented pivot: years below 80 map to 20yy,
/// years 80..=99 map to 19yy.
fn parse_date(text: &str) -> Result<NaiveDate, NmeaError> {
    let invalid = || {
        error(
            "invalid_timestamp",
            format!("date field {text:?} is malformed"),
        )
    };
    if text.len() != 6 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid());
    }
    let day: i32 = text[0..2].parse().map_err(|_| invalid())?;
    let month: i32 = text[2..4].parse().map_err(|_| invalid())?;
    let year_two: i32 = text[4..6].parse().map_err(|_| invalid())?;
    let year = if year_two < 80 {
        2000 + year_two
    } else {
        1900 + year_two
    };
    NaiveDate::from_ymd_opt(year, month as u32, day as u32).ok_or_else(invalid)
}

/// Parse an NMEA coordinate (`ddmm.mmmm` for latitude, `dddmm.mmmm` for
/// longitude) plus its hemisphere indicator into signed degrees.
fn parse_coordinate(value: &str, hemisphere: &str, degree_digits: usize) -> Result<f64, NmeaError> {
    let invalid = || {
        error(
            "invalid_coordinate",
            format!("coordinate {value:?} {hemisphere:?} is malformed"),
        )
    };
    if value.len() < degree_digits + 3
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return Err(invalid());
    }
    let degrees: f64 = value[..degree_digits].parse().map_err(|_| invalid())?;
    let minutes: f64 = value[degree_digits..].parse().map_err(|_| invalid())?;
    if !(0.0..60.0).contains(&minutes) {
        return Err(invalid());
    }
    let magnitude = degrees + minutes / 60.0;
    let signed = match hemisphere {
        "N" if degree_digits == 2 => magnitude,
        "S" if degree_digits == 2 => -magnitude,
        "E" if degree_digits == 3 => magnitude,
        "W" if degree_digits == 3 => -magnitude,
        _ => return Err(invalid()),
    };
    let limit = if degree_digits == 2 { 90.0 } else { 180.0 };
    if !signed.is_finite() || signed.abs() > limit {
        return Err(invalid());
    }
    Ok(signed)
}

/// Parse an optional decimal field, enforcing a finite value in `range`.
fn parse_optional_decimal(
    text: &str,
    minimum: f64,
    maximum: f64,
    field: &'static str,
) -> Result<Option<f64>, NmeaError> {
    if text.is_empty() {
        return Ok(None);
    }
    let value: f64 = text.parse().map_err(|_| {
        error(
            "invalid_field",
            format!("{field} field {text:?} is not a decimal number"),
        )
    })?;
    if !value.is_finite() || !(minimum..=maximum).contains(&value) {
        return Err(error(
            "invalid_field",
            format!("{field} field {text:?} is outside {minimum}..={maximum}"),
        ));
    }
    Ok(Some(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checksummed(content: &str) -> String {
        let checksum = content.bytes().fold(0u8, |acc, byte| acc ^ byte);
        format!("${content}*{checksum:02X}")
    }

    #[test]
    fn parses_valid_rmc_with_full_timestamp() {
        let sentence =
            checksummed("GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W,A");
        let parsed = parse_sentence(&sentence).expect("valid RMC");
        let NmeaSentence::Rmc(fix) = parsed else {
            panic!("expected RMC fix");
        };
        assert_eq!(fix.observed_at.to_rfc3339(), "1994-03-23T12:35:19+00:00");
        assert!((fix.latitude - 48.1173).abs() < 1e-4);
        assert!((fix.longitude - 11.5166667).abs() < 1e-4);
        assert_eq!(fix.speed_knots, Some(22.4));
        assert_eq!(fix.course_degrees, Some(84.4));
    }

    #[test]
    fn parses_rmc_with_crlf_and_fractional_seconds_and_southern_western() {
        let mut sentence = checksummed("GNRMC,000001.25,A,0622.417,S,00307.512,W,0.5,,010126,,,A");
        sentence.push_str("\r\n");
        let NmeaSentence::Rmc(fix) = parse_sentence(&sentence).expect("valid RMC") else {
            panic!("expected RMC fix");
        };
        assert_eq!(
            fix.observed_at.to_rfc3339(),
            "2026-01-01T00:00:01.250+00:00"
        );
        assert!((fix.latitude + 6.3736167).abs() < 1e-4);
        assert!((fix.longitude + 3.1252).abs() < 1e-4);
        assert_eq!(fix.course_degrees, None);
    }

    #[test]
    fn parses_valid_gga() {
        let sentence = checksummed("GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,");
        let NmeaSentence::Gga(fix) = parse_sentence(&sentence).expect("valid GGA") else {
            panic!("expected GGA fix");
        };
        assert_eq!(
            fix.time_of_day,
            NaiveTime::from_hms_milli_opt(12, 35, 19, 0).expect("time")
        );
        assert!((fix.latitude - 48.1173).abs() < 1e-4);
        assert_eq!(fix.fix_quality, 1);
        assert_eq!(fix.satellites_in_use, 8);
        assert_eq!(fix.hdop, Some(0.9));
        assert_eq!(fix.altitude_meters, Some(545.4));
    }

    #[test]
    fn rejects_checksum_mismatch() {
        assert_eq!(
            parse_sentence("$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*00")
                .unwrap_err()
                .code,
            "checksum_mismatch"
        );
    }

    #[test]
    fn rejects_missing_and_malformed_checksums() {
        assert_eq!(
            parse_sentence("$GPRMC,123519,A").unwrap_err().code,
            "missing_checksum"
        );
        assert_eq!(
            parse_sentence("$GPRMC,123519,A*ZZ").unwrap_err().code,
            "invalid_checksum"
        );
        assert_eq!(
            parse_sentence("$GPRMC,123519,A*1").unwrap_err().code,
            "invalid_checksum"
        );
    }

    #[test]
    fn rejects_void_fix_and_no_fix_quality() {
        let void_rmc = checksummed("GPRMC,123519,V,,,,,,,230394,,,N");
        assert_eq!(parse_sentence(&void_rmc).unwrap_err().code, "invalid_fix");
        let no_fix = checksummed("GPGGA,123519,,,,,0,00,,,M,,M,,");
        assert_eq!(parse_sentence(&no_fix).unwrap_err().code, "invalid_fix");
    }

    #[test]
    fn rejects_unsupported_and_non_dollar_sentences() {
        let vdm = "!AIVDM,1,1,,B,33P@?P0000PD;88MD5MTDwwP0000,0*5C";
        assert_eq!(
            parse_sentence(vdm).unwrap_err().code,
            "unsupported_sentence"
        );
        let vhw = checksummed("GPVHW,084.4,T,,,022.4,N,,,A");
        assert_eq!(
            parse_sentence(&vhw).unwrap_err().code,
            "unsupported_sentence"
        );
    }

    #[test]
    fn rejects_out_of_range_coordinates_and_times() {
        let bad_lat = checksummed("GPRMC,123519,A,9100.000,N,01131.000,E,0.0,0.0,230394,,,A");
        assert_eq!(
            parse_sentence(&bad_lat).unwrap_err().code,
            "invalid_coordinate"
        );
        let bad_minutes = checksummed("GPRMC,123519,A,4860.000,N,01131.000,E,0.0,0.0,230394,,,A");
        assert_eq!(
            parse_sentence(&bad_minutes).unwrap_err().code,
            "invalid_coordinate"
        );
        let bad_time = checksummed("GPRMC,256100,A,4807.038,N,01131.000,E,0.0,0.0,230394,,,A");
        assert_eq!(
            parse_sentence(&bad_time).unwrap_err().code,
            "invalid_timestamp"
        );
        let bad_date = checksummed("GPRMC,123519,A,4807.038,N,01131.000,E,0.0,0.0,320294,,,A");
        assert_eq!(
            parse_sentence(&bad_date).unwrap_err().code,
            "invalid_timestamp"
        );
    }

    #[test]
    fn rejects_empty_oversized_and_truncated_sentences() {
        assert_eq!(parse_sentence("").unwrap_err().code, "empty_sentence");
        assert_eq!(parse_sentence("\r\n").unwrap_err().code, "empty_sentence");
        let oversized = format!("${}*00", "G".repeat(MAX_SENTENCE_BYTES));
        assert_eq!(
            parse_sentence(&oversized).unwrap_err().code,
            "sentence_too_long"
        );
        let truncated = checksummed("GPRMC,123519,A,4807.038,N");
        assert_eq!(
            parse_sentence(&truncated).unwrap_err().code,
            "invalid_sentence"
        );
    }

    #[test]
    fn rejects_impossible_speed_and_course() {
        let fast = checksummed("GPRMC,123519,A,4807.038,N,01131.000,E,999.9,084.4,230394,,,A");
        assert_eq!(parse_sentence(&fast).unwrap_err().code, "invalid_field");
        let nan_course = checksummed("GPRMC,123519,A,4807.038,N,01131.000,E,1.0,NaN,230394,,,A");
        assert_eq!(
            parse_sentence(&nan_course).unwrap_err().code,
            "invalid_field"
        );
    }
}
