# Met-ocean feed fixtures (TEST DATA — never runtime input)

Recorded/constructed payloads used by the adapter parsing tests. These files
are test fixtures only; the production ingest paths fetch from the live
documented APIs and never read this directory.

- `open_meteo_marine_sample.json` — recorded 2026-08-30 from the documented
  Open-Meteo Marine Forecast API
  (`https://marine-api.open-meteo.com/v1/marine?latitude=6.0&longitude=3.0&hourly=...&forecast_days=1&timezone=UTC`,
  Gulf of Guinea / Lagos approach). CC BY 4.0 — Weather data by
  Open-Meteo.com.
- `gfs_10m_wind_slice.grb2` — recorded 2026-08-30 from the documented NOAA
  NOMADS GRIB filter (`filter_gfs_0p25.pl`, GFS 0.25°, run 20260830/00,
  forecast hour 3, 10 m UGRD+VGRD over lon 2–5, lat 5–7). NOAA data, public
  domain.
- `copernicus_wave_subset_sample.csv` — CONSTRUCTED sample in the documented
  `copernicusmarine subset` CSV output layout (time/latitude/longitude +
  CMEMS wave variables VHM0/VTPK/VMDR/VHM0_SW1/VTM10). A live recording
  requires a registered Copernicus Marine account (credentials env-only,
  external to this repo); values here are invented test data and are not a
  real observation.
