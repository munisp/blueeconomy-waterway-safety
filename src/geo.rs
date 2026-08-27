//! Geospatial safety analytics: EEZ/restricted-zone overlap detection, corridor
//! safety polygon construction from vessel tracks, and track freshness
//! evaluation supporting the vessel-track freshness KPI (staleness at or below
//! five minutes). All functions are deterministic, dependency-disciplined, and
//! fail closed: invalid input is rejected and uncertain tracks are reported as
//! stale, never silently treated as safe.

use crate::store::VesselTrackState;
use crate::{validate_identifier, validate_timestamp, ValidationError};
use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::f64::consts::TAU;

pub const MAX_ZONE_VERTICES: usize = 10_000;
pub const MAX_TRACK_POINTS: usize = 4_096;
pub const MAX_CORRIDOR_HALF_WIDTH_METERS: f64 = 50_000.0;
pub const FRESHNESS_KPI_MAX_STALENESS_SECONDS: i64 = 300;
pub const MAX_FRESHNESS_WINDOW_SECONDS: i64 = 86_400;
pub const FRESHNESS_REPORT_SCHEMA_VERSION: &str = "blueeconomy.waterway-safety.freshness-report.v1";

const METERS_PER_DEGREE_LATITUDE: f64 = 111_320.0;
const CORRIDOR_CIRCLE_SAMPLES: usize = 16;
const MIN_LATITUDE_COSINE: f64 = 1e-3;
const BOUNDARY_CROSS_TOLERANCE: f64 = 1e-12;

/// One validated vessel track observation. Coordinates are WGS-84 degrees.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TrackPoint {
    pub observed_at: String,
    pub latitude: f64,
    pub longitude: f64,
}

/// A validated WGS-84 position. Construct only through [`GeoPosition::new`]
/// so non-finite or out-of-range coordinates can never enter analytics.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields, try_from = "RawGeoPosition")]
pub struct GeoPosition {
    latitude: f64,
    longitude: f64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGeoPosition {
    latitude: f64,
    longitude: f64,
}

impl TryFrom<RawGeoPosition> for GeoPosition {
    type Error = ValidationError;

    fn try_from(raw: RawGeoPosition) -> Result<Self, ValidationError> {
        GeoPosition::new(raw.latitude, raw.longitude)
    }
}

impl GeoPosition {
    pub fn new(latitude: f64, longitude: f64) -> Result<Self, ValidationError> {
        if !latitude.is_finite()
            || !longitude.is_finite()
            || !(-90.0..=90.0).contains(&latitude)
            || !(-180.0..=180.0).contains(&longitude)
        {
            return Err(ValidationError {
                code: "invalid_coordinate",
                message: "coordinates must be finite with latitude in [-90, 90] and longitude in [-180, 180]"
                    .to_owned(),
            });
        }
        Ok(Self {
            latitude,
            longitude,
        })
    }

    pub fn latitude(&self) -> f64 {
        self.latitude
    }

    pub fn longitude(&self) -> f64 {
        self.longitude
    }
}

pub fn validate_track_point(
    field: &'static str,
    point: &TrackPoint,
) -> Result<(), ValidationError> {
    validate_timestamp(field, &point.observed_at)?;
    GeoPosition::new(point.latitude, point.longitude)?;
    Ok(())
}

/// Classification of a safety zone polygon.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ZoneKind {
    Eez,
    Restricted,
}

/// A validated EEZ or restricted-zone polygon. Boundary points are treated as
/// inside the zone (fail-closed for safety alerting).
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct SafetyZone {
    pub zone_id: String,
    pub zone_kind: ZoneKind,
    vertices: Vec<GeoPosition>,
}

impl SafetyZone {
    pub fn new(
        zone_id: String,
        zone_kind: ZoneKind,
        vertices: Vec<GeoPosition>,
    ) -> Result<Self, ValidationError> {
        validate_identifier("zone_id", &zone_id, 256)?;
        if vertices.len() < 3 || vertices.len() > MAX_ZONE_VERTICES {
            return Err(ValidationError {
                code: "invalid_zone_geometry",
                message: format!(
                    "zone polygon must contain between 3 and {MAX_ZONE_VERTICES} vertices"
                ),
            });
        }
        for index in 0..vertices.len() {
            if vertices[index] == vertices[(index + 1) % vertices.len()] {
                return Err(ValidationError {
                    code: "invalid_zone_geometry",
                    message: "zone polygon must not repeat consecutive vertices".to_owned(),
                });
            }
        }
        Ok(Self {
            zone_id,
            zone_kind,
            vertices,
        })
    }

    pub fn vertices(&self) -> &[GeoPosition] {
        &self.vertices
    }

    /// Boundary-inclusive even-odd containment test. A position lying exactly
    /// on an edge or vertex is reported as inside the zone so that EEZ and
    /// restricted-zone alerting never misses a boundary crossing.
    pub fn contains(&self, position: GeoPosition) -> bool {
        let count = self.vertices.len();
        for index in 0..count {
            let start = self.vertices[index];
            let end = self.vertices[(index + 1) % count];
            if point_on_segment(position, start, end) {
                return true;
            }
        }
        let (px, py) = (position.longitude, position.latitude);
        let mut inside = false;
        for index in 0..count {
            let start = self.vertices[index];
            let end = self.vertices[(index + 1) % count];
            let (ax, ay) = (start.longitude, start.latitude);
            let (bx, by) = (end.longitude, end.latitude);
            if (ay > py) != (by > py) {
                let intersection_x = ax + (py - ay) * (bx - ax) / (by - ay);
                if intersection_x > px {
                    inside = !inside;
                }
            }
        }
        inside
    }
}

fn point_on_segment(position: GeoPosition, start: GeoPosition, end: GeoPosition) -> bool {
    let (px, py) = (position.longitude, position.latitude);
    let (ax, ay) = (start.longitude, start.latitude);
    let (bx, by) = (end.longitude, end.latitude);
    let dx = bx - ax;
    let dy = by - ay;
    let cross = dx * (py - ay) - dy * (px - ax);
    let scale = (dx * dx + dy * dy).max(1.0);
    if cross.abs() > BOUNDARY_CROSS_TOLERANCE * scale {
        return false;
    }
    (px - ax) * dx + (py - ay) * dy >= 0.0 && (px - bx) * dx + (py - by) * dy <= 0.0
}

/// One zone that contains a vessel position.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ZoneOverlap {
    pub zone_id: String,
    pub zone_kind: ZoneKind,
}

/// Returns every EEZ/restricted zone containing the position. An empty result
/// means the position is clear of all supplied zones.
pub fn detect_zone_overlaps(position: GeoPosition, zones: &[SafetyZone]) -> Vec<ZoneOverlap> {
    zones
        .iter()
        .filter(|zone| zone.contains(position))
        .map(|zone| ZoneOverlap {
            zone_id: zone.zone_id.clone(),
            zone_kind: zone.zone_kind,
        })
        .collect()
}

/// A corridor safety polygon constructed from a vessel track. The polygon is
/// the convex hull of the track buffered by `half_width_meters`, which is a
/// conservative superset of the true corridor buffer: it never under-covers
/// the sailed corridor, so downstream safety screening cannot miss a hazard
/// inside the corridor.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct CorridorPolygon {
    pub corridor_id: String,
    pub half_width_meters: f64,
    pub source_track_points: usize,
    pub vertices: Vec<GeoPosition>,
    pub corridor_digest_sha256: String,
}

pub fn build_corridor_polygon(
    corridor_id: &str,
    track: &[TrackPoint],
    half_width_meters: f64,
) -> Result<CorridorPolygon, ValidationError> {
    validate_identifier("corridor_id", corridor_id, 256)?;
    if track.is_empty() || track.len() > MAX_TRACK_POINTS {
        return Err(ValidationError {
            code: "invalid_track",
            message: format!("corridor track must contain between 1 and {MAX_TRACK_POINTS} points"),
        });
    }
    if !half_width_meters.is_finite()
        || half_width_meters <= 0.0
        || half_width_meters > MAX_CORRIDOR_HALF_WIDTH_METERS
    {
        return Err(ValidationError {
            code: "invalid_corridor_width",
            message: format!(
                "corridor half width must be finite, positive, and at most {MAX_CORRIDOR_HALF_WIDTH_METERS} meters"
            ),
        });
    }
    let mut positions = Vec::with_capacity(track.len());
    let mut previous: Option<DateTime<FixedOffset>> = None;
    for point in track {
        validate_track_point("track.observed_at", point)?;
        let observed_at = validate_timestamp("track.observed_at", &point.observed_at)?;
        if let Some(earlier) = previous {
            if observed_at < earlier {
                return Err(ValidationError {
                    code: "track_time_regression",
                    message: "corridor track points must be ordered by observed_at".to_owned(),
                });
            }
        }
        previous = Some(observed_at);
        positions.push(GeoPosition::new(point.latitude, point.longitude)?);
    }

    let mut candidates: Vec<(f64, f64)> =
        Vec::with_capacity(positions.len() * CORRIDOR_CIRCLE_SAMPLES);
    for position in &positions {
        let latitude_cosine = position
            .latitude
            .to_radians()
            .cos()
            .abs()
            .max(MIN_LATITUDE_COSINE);
        for sample in 0..CORRIDOR_CIRCLE_SAMPLES {
            let angle = TAU * (sample as f64) / (CORRIDOR_CIRCLE_SAMPLES as f64);
            let latitude = (position.latitude
                + half_width_meters * angle.cos() / METERS_PER_DEGREE_LATITUDE)
                .clamp(-90.0, 90.0);
            let longitude = (position.longitude
                + half_width_meters * angle.sin() / (METERS_PER_DEGREE_LATITUDE * latitude_cosine))
                .clamp(-180.0, 180.0);
            candidates.push((longitude, latitude));
        }
    }
    let hull = convex_hull(&candidates);
    let mut vertices = Vec::with_capacity(hull.len());
    for (longitude, latitude) in hull {
        vertices.push(GeoPosition::new(latitude, longitude)?);
    }
    let digest = corridor_digest(corridor_id, half_width_meters, track, &vertices);
    Ok(CorridorPolygon {
        corridor_id: corridor_id.to_owned(),
        half_width_meters,
        source_track_points: track.len(),
        vertices,
        corridor_digest_sha256: digest,
    })
}

/// Andrew monotone-chain convex hull over (longitude, latitude) pairs.
fn convex_hull(points: &[(f64, f64)]) -> Vec<(f64, f64)> {
    let mut sorted = points.to_vec();
    sorted.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));
    sorted.dedup();
    if sorted.len() <= 2 {
        return sorted;
    }
    let mut hull: Vec<(f64, f64)> = Vec::with_capacity(sorted.len() * 2);
    for point in &sorted {
        while hull.len() >= 2
            && cross_product(hull[hull.len() - 2], hull[hull.len() - 1], *point) <= 0.0
        {
            hull.pop();
        }
        hull.push(*point);
    }
    let lower_len = hull.len();
    for point in sorted.iter().rev().skip(1) {
        while hull.len() > lower_len
            && cross_product(hull[hull.len() - 2], hull[hull.len() - 1], *point) <= 0.0
        {
            hull.pop();
        }
        hull.push(*point);
    }
    hull.pop();
    hull
}

fn cross_product(origin: (f64, f64), a: (f64, f64), b: (f64, f64)) -> f64 {
    (a.0 - origin.0) * (b.1 - origin.1) - (a.1 - origin.1) * (b.0 - origin.0)
}

fn corridor_digest(
    corridor_id: &str,
    half_width_meters: f64,
    track: &[TrackPoint],
    vertices: &[GeoPosition],
) -> String {
    let mut digest = Sha256::new();
    digest.update(corridor_id.as_bytes());
    digest.update([0]);
    digest.update(half_width_meters.to_bits().to_be_bytes());
    for point in track {
        digest.update(point.observed_at.as_bytes());
        digest.update([0]);
        digest.update(point.latitude.to_bits().to_be_bytes());
        digest.update(point.longitude.to_bits().to_be_bytes());
    }
    digest.update((vertices.len() as u64).to_be_bytes());
    for vertex in vertices {
        digest.update(vertex.latitude.to_bits().to_be_bytes());
        digest.update(vertex.longitude.to_bits().to_be_bytes());
    }
    crate::hex_lowercase(digest.finalize())
}

/// Freshness status of one vessel track relative to the evaluation time.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FreshnessStatus {
    Fresh,
    Stale,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct TrackFreshness {
    pub vessel_id: String,
    pub last_observed_at: String,
    pub age_seconds: i64,
    pub status: FreshnessStatus,
}

/// Fleet freshness report for the NIMASA corridor safety dashboard. Tracks
/// older than the configured maximum staleness (the KPI target is
/// [`FRESHNESS_KPI_MAX_STALENESS_SECONDS`]) are listed explicitly; any stale
/// or future-dated track fails the report closed (`all_fresh == false`).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct FreshnessReport {
    pub schema_version: String,
    pub evaluated_at: String,
    pub max_staleness_seconds: i64,
    pub all_fresh: bool,
    pub fresh_track_count: usize,
    pub stale_track_count: usize,
    pub tracks: Vec<TrackFreshness>,
}

pub fn evaluate_track_freshness(
    evaluated_at: &str,
    vessels: &[VesselTrackState],
    max_staleness_seconds: i64,
) -> Result<FreshnessReport, ValidationError> {
    let evaluated = validate_timestamp("evaluated_at", evaluated_at)?;
    if max_staleness_seconds <= 0 || max_staleness_seconds > MAX_FRESHNESS_WINDOW_SECONDS {
        return Err(ValidationError {
            code: "invalid_freshness_window",
            message: format!(
                "max staleness must be between 1 and {MAX_FRESHNESS_WINDOW_SECONDS} seconds"
            ),
        });
    }
    let mut tracks = Vec::with_capacity(vessels.len());
    for vessel in vessels {
        validate_identifier("vessel_id", &vessel.vessel_id, 256)?;
        let last_observed =
            validate_timestamp("vessel.last_observed_at", &vessel.last_observed_at)?;
        let age_seconds = (evaluated - last_observed).num_seconds();
        // Fail closed: tracks with future-dated or over-age observations are
        // reported stale rather than trusted.
        let status = if age_seconds < 0 || age_seconds > max_staleness_seconds {
            FreshnessStatus::Stale
        } else {
            FreshnessStatus::Fresh
        };
        tracks.push(TrackFreshness {
            vessel_id: vessel.vessel_id.clone(),
            last_observed_at: vessel.last_observed_at.clone(),
            age_seconds,
            status,
        });
    }
    let stale_track_count = tracks
        .iter()
        .filter(|track| track.status == FreshnessStatus::Stale)
        .count();
    Ok(FreshnessReport {
        schema_version: FRESHNESS_REPORT_SCHEMA_VERSION.to_owned(),
        evaluated_at: evaluated_at.to_owned(),
        max_staleness_seconds,
        all_fresh: stale_track_count == 0,
        fresh_track_count: tracks.len() - stale_track_count,
        stale_track_count,
        tracks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn position(latitude: f64, longitude: f64) -> GeoPosition {
        GeoPosition::new(latitude, longitude).expect("fixture position")
    }

    fn square_zone() -> SafetyZone {
        SafetyZone::new(
            "eez-nigeria".to_owned(),
            ZoneKind::Eez,
            vec![
                position(0.0, 0.0),
                position(0.0, 4.0),
                position(4.0, 4.0),
                position(4.0, 0.0),
            ],
        )
        .expect("fixture zone")
    }

    #[test]
    fn rejects_out_of_range_and_non_finite_coordinates() {
        assert_eq!(
            GeoPosition::new(91.0, 0.0).unwrap_err().code,
            "invalid_coordinate"
        );
        assert_eq!(
            GeoPosition::new(0.0, -181.0).unwrap_err().code,
            "invalid_coordinate"
        );
        assert_eq!(
            GeoPosition::new(f64::NAN, 0.0).unwrap_err().code,
            "invalid_coordinate"
        );
        assert_eq!(
            GeoPosition::new(0.0, f64::INFINITY).unwrap_err().code,
            "invalid_coordinate"
        );
        assert!(GeoPosition::new(90.0, 180.0).is_ok());
        assert!(GeoPosition::new(-90.0, -180.0).is_ok());
    }

    #[test]
    fn rejects_degenerate_zone_polygons() {
        let too_few = SafetyZone::new(
            "zone".to_owned(),
            ZoneKind::Restricted,
            vec![position(0.0, 0.0), position(1.0, 1.0)],
        );
        assert_eq!(too_few.unwrap_err().code, "invalid_zone_geometry");
        let repeated = SafetyZone::new(
            "zone".to_owned(),
            ZoneKind::Restricted,
            vec![position(0.0, 0.0), position(0.0, 0.0), position(1.0, 1.0)],
        );
        assert_eq!(repeated.unwrap_err().code, "invalid_zone_geometry");
    }

    #[test]
    fn classifies_inside_outside_and_boundary_positions() {
        let zone = square_zone();
        assert!(zone.contains(position(2.0, 2.0)));
        assert!(!zone.contains(position(5.0, 2.0)));
        assert!(!zone.contains(position(2.0, -0.5)));
        // Boundary edge, vertex, and mid-edge points are fail-closed "inside".
        assert!(zone.contains(position(0.0, 2.0)));
        assert!(zone.contains(position(0.0, 0.0)));
        assert!(zone.contains(position(4.0, 4.0)));
        assert!(zone.contains(position(2.0, 4.0)));
    }

    #[test]
    fn detects_overlaps_across_multiple_zones() {
        let eez = square_zone();
        let restricted = SafetyZone::new(
            "restricted-anchorage".to_owned(),
            ZoneKind::Restricted,
            vec![
                position(1.0, 1.0),
                position(1.0, 3.0),
                position(3.0, 3.0),
                position(3.0, 1.0),
            ],
        )
        .expect("fixture zone");
        let zones = vec![eez, restricted];
        let overlaps = detect_zone_overlaps(position(2.0, 2.0), &zones);
        assert_eq!(overlaps.len(), 2);
        assert_eq!(overlaps[0].zone_kind, ZoneKind::Eez);
        assert_eq!(overlaps[1].zone_id, "restricted-anchorage");
        assert!(detect_zone_overlaps(position(10.0, 10.0), &zones).is_empty());
    }

    fn track_point(observed_at: &str, latitude: f64, longitude: f64) -> TrackPoint {
        TrackPoint {
            observed_at: observed_at.to_owned(),
            latitude,
            longitude,
        }
    }

    #[test]
    fn builds_corridor_polygon_covering_buffered_track() {
        let track = vec![
            track_point("2026-08-21T00:00:00Z", 6.0, 3.0),
            track_point("2026-08-21T00:01:00Z", 6.001, 3.001),
            track_point("2026-08-21T00:02:00Z", 6.002, 3.001),
        ];
        let corridor = build_corridor_polygon("corridor-lagos-approach", &track, 500.0)
            .expect("corridor should build");
        assert_eq!(corridor.corridor_id, "corridor-lagos-approach");
        assert_eq!(corridor.source_track_points, 3);
        assert!(corridor.vertices.len() >= 3);
        assert_eq!(corridor.corridor_digest_sha256.len(), 64);
        // Every raw track point must lie inside the corridor polygon.
        let zone = SafetyZone::new(
            corridor.corridor_id.clone(),
            ZoneKind::Eez,
            corridor.vertices.clone(),
        )
        .expect("corridor vertices form a zone");
        for point in &track {
            assert!(
                zone.contains(position(point.latitude, point.longitude)),
                "track point must be inside corridor"
            );
        }
        // Deterministic digest for identical input.
        let repeat = build_corridor_polygon("corridor-lagos-approach", &track, 500.0)
            .expect("corridor should build");
        assert_eq!(corridor, repeat);
        let different =
            build_corridor_polygon("corridor-other", &track, 500.0).expect("corridor should build");
        assert_ne!(
            corridor.corridor_digest_sha256,
            different.corridor_digest_sha256
        );
    }

    #[test]
    fn builds_single_point_corridor_as_buffered_cap() {
        let track = vec![track_point("2026-08-21T00:00:00Z", 6.0, 3.0)];
        let corridor = build_corridor_polygon("corridor-single", &track, 250.0)
            .expect("corridor should build");
        assert_eq!(corridor.vertices.len(), CORRIDOR_CIRCLE_SAMPLES);
        let zone = SafetyZone::new("c".to_owned(), ZoneKind::Eez, corridor.vertices.clone())
            .expect("zone");
        assert!(zone.contains(position(6.0, 3.0)));
        // A point beyond the buffer radius must be outside.
        assert!(!zone.contains(position(6.01, 3.0)));
    }

    #[test]
    fn rejects_invalid_corridor_inputs() {
        let track = vec![track_point("2026-08-21T00:00:00Z", 6.0, 3.0)];
        assert_eq!(
            build_corridor_polygon("corridor", &[], 100.0)
                .unwrap_err()
                .code,
            "invalid_track"
        );
        assert_eq!(
            build_corridor_polygon("corridor", &track, 0.0)
                .unwrap_err()
                .code,
            "invalid_corridor_width"
        );
        assert_eq!(
            build_corridor_polygon("corridor", &track, f64::NAN)
                .unwrap_err()
                .code,
            "invalid_corridor_width"
        );
        assert_eq!(
            build_corridor_polygon("corridor", &track, 60_000.0)
                .unwrap_err()
                .code,
            "invalid_corridor_width"
        );
        let mut regressed = track.clone();
        regressed.push(track_point("2026-08-20T23:59:00Z", 6.001, 3.0));
        assert_eq!(
            build_corridor_polygon("corridor", &regressed, 100.0)
                .unwrap_err()
                .code,
            "track_time_regression"
        );
    }

    fn vessel(vessel_id: &str, last_observed_at: &str) -> VesselTrackState {
        VesselTrackState {
            vessel_id: vessel_id.to_owned(),
            device_id: "device-001".to_owned(),
            gateway_id: "gateway-001".to_owned(),
            last_source_sequence: 1,
            last_observed_at: last_observed_at.to_owned(),
            last_received_at: "2026-08-21T00:05:01Z".to_owned(),
            last_position: track_point(last_observed_at, 6.0, 3.0),
            track: vec![track_point(last_observed_at, 6.0, 3.0)],
        }
    }

    #[test]
    fn reports_stale_tracks_explicitly_against_kpi_window() {
        let vessels = vec![
            vessel("vessel-fresh", "2026-08-21T00:01:00Z"),
            vessel("vessel-stale", "2026-08-20T23:58:00Z"),
        ];
        let report = evaluate_track_freshness(
            "2026-08-21T00:05:00Z",
            &vessels,
            FRESHNESS_KPI_MAX_STALENESS_SECONDS,
        )
        .expect("freshness evaluation");
        assert!(!report.all_fresh);
        assert_eq!(report.fresh_track_count, 1);
        assert_eq!(report.stale_track_count, 1);
        assert_eq!(report.tracks[0].status, FreshnessStatus::Fresh);
        assert_eq!(report.tracks[0].age_seconds, 240);
        assert_eq!(report.tracks[1].status, FreshnessStatus::Stale);
        assert_eq!(report.tracks[1].vessel_id, "vessel-stale");
        assert_eq!(report.tracks[1].age_seconds, 420);
    }

    #[test]
    fn fails_closed_on_future_dated_track() {
        let vessels = vec![vessel("vessel-clock-skew", "2026-08-21T00:06:00Z")];
        let report =
            evaluate_track_freshness("2026-08-21T00:05:00Z", &vessels, 300).expect("evaluation");
        assert!(!report.all_fresh);
        assert_eq!(report.tracks[0].status, FreshnessStatus::Stale);
        assert!(report.tracks[0].age_seconds < 0);
    }

    #[test]
    fn rejects_invalid_freshness_inputs() {
        let vessels = vec![vessel("vessel-001", "2026-08-21T00:04:30Z")];
        assert_eq!(
            evaluate_track_freshness("not-a-time", &vessels, 300)
                .unwrap_err()
                .code,
            "invalid_timestamp"
        );
        assert_eq!(
            evaluate_track_freshness("2026-08-21T00:05:00Z", &vessels, 0)
                .unwrap_err()
                .code,
            "invalid_freshness_window"
        );
        assert_eq!(
            evaluate_track_freshness("2026-08-21T00:05:00Z", &vessels, 86_401)
                .unwrap_err()
                .code,
            "invalid_freshness_window"
        );
        let report = evaluate_track_freshness("2026-08-21T00:05:00Z", &vessels, 300)
            .expect("fresh evaluation");
        assert!(report.all_fresh);
        assert_eq!(
            report.schema_version,
            "blueeconomy.waterway-safety.freshness-report.v1"
        );
    }
}
