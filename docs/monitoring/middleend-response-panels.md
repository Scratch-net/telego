# Middle-End response panels

This bundle contains only the new response panels. It contains no complete runtime dashboard, datasource configuration, or credentials.
The panels cover shared budget charge, memory classes, ownership stages, admission waits, selection rules, immediate reclamation, and output stall closures.
The existing historical pressure and RSS panels remain unchanged.

The bundle targets dashboard UIDs `telego-dashboard` and `telego-health`.
It uses the existing `instance` variable and Prometheus datasource.
Queries retain the existing VPS and NAS display mappings. These mappings do not change the instance filter.

## Prepare a merged dashboard

1. Save the current dashboard JSON as a local baseline.
2. Keep that baseline for rollback.
3. Run the merge command with a new output path.

```sh
rtk proxy python3 docs/monitoring/merge-response-panels.py \
  --dashboard telego \
  --input /tmp/telego.live.json \
  --output /tmp/telego.response-review.json

rtk proxy python3 docs/monitoring/merge-response-panels.py \
  --dashboard telego-health \
  --input /tmp/telego-health.live.json \
  --output /tmp/telego-health.response-review.json
```

The script appends three summary panels or nine health panels.
It preserves existing panels, UIDs, variables, links, and datasource definitions.
It assigns unused panel IDs and places the new panels after existing content.
An already present panel with matching queries stays unchanged. A conflicting panel title stops the merge.
If the baseline contains several Prometheus datasources, select the existing datasource with `--datasource-uid`.

4. Compare the output with its baseline.
5. After the exporter release, check each new query against Prometheus.
6. Before dashboard deployment, compare the live dashboard with the saved baseline.
7. If the live dashboard changed, prepare a new merge from that content.
8. After the release gates pass, deploy the reviewed JSON through the existing Grafana provisioning process.

The script changes only its new local output file. It does not contact Grafana or deploy a dashboard.
The exact baseline JSON supplies the rollback content.

## Interpret the panels

The response pool counts charged capacity, including reserved output expansion and metadata. It is not a process RSS limit.
The processing reserve forms part of the combined pool limit.
Persistent ME decoders and WEB carrier storage have separate bounds.

Wait entries and completed intervals have separate counters.
Mean completed duration divides duration growth by completed interval growth over the same interval.
It excludes unfinished waits. The active-wait panel shows those intervals separately.

The reclamation panel counts budget charge released synchronously by pressure closure.
It excludes deferred cleanup and later output release, which instead change the pool gauges.
This counter does not measure physical memory returned to the operating system.

All 16 panel expressions passed read-only Prometheus execution during preparation.
Their results were empty before the new exporter deployment.
Post-deployment checks must establish actual series, instance filtering, and panel appearance.
The [ME guide](../middle-end.md#metrics-and-logs) defines the metric names and bounded labels.
