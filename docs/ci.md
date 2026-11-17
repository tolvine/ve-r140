# CI

Two jobs run on this box:

- `build` — render `public/` into `dist/` (scripts/build.mjs).
- `smoke` — end-to-end pipeline check (scripts/smoke.mjs): render + hash,
  regenerate runtime-config.json from the live service map, exercise the
  local health endpoints, and upload the report to the artifact store.
