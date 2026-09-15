#!/usr/bin/env python3
"""Append response panels to a saved dashboard without changing existing panels."""

import argparse
import copy
import json
from pathlib import Path


def walk_panels(panels):
    for panel in panels:
        yield panel
        yield from walk_panels(panel.get("panels", []))


def merge(dashboard, definition, datasource_uid=None):
    if dashboard.get("uid") != definition["uid"]:
        raise ValueError("input dashboard UID does not match the selected panel set")
    variables = dashboard.get("templating", {}).get("list", [])
    if not any(variable.get("name") == "instance" for variable in variables):
        raise ValueError("input dashboard must contain its existing instance variable")

    result = copy.deepcopy(dashboard)
    existing = list(walk_panels(result.get("panels", [])))
    if datasource_uid is None:
        datasource_uids = {
            panel["datasource"]["uid"]
            for panel in existing
            if isinstance(panel.get("datasource"), dict)
            and panel["datasource"].get("type") == "prometheus"
            and panel["datasource"].get("uid")
        }
        if len(datasource_uids) != 1:
            raise ValueError("use --datasource-uid because the input has no unique Prometheus datasource")
        datasource_uid = datasource_uids.pop()

    maximum_id = max((panel.get("id", 0) for panel in existing), default=0)
    bottom = max(
        (panel.get("gridPos", {}).get("y", 0) + panel.get("gridPos", {}).get("h", 0) for panel in existing),
        default=0,
    )
    pending = []
    for template in definition["panels"]:
        matches = [panel for panel in existing if panel.get("title") == template["title"]]
        if matches:
            if len(matches) != 1 or matches[0].get("targets") != template["targets"]:
                raise ValueError("existing panel title conflicts with response panel: " + template["title"])
            continue
        panel = copy.deepcopy(template)
        maximum_id += 1
        panel["id"] = maximum_id
        panel["datasource"] = {"type": "prometheus", "uid": datasource_uid}
        pending.append(panel)

    if pending:
        offset = bottom - min(panel["gridPos"]["y"] for panel in pending)
        for panel in pending:
            panel["gridPos"]["y"] += offset
        result.setdefault("panels", []).extend(pending)
        result["version"] = dashboard.get("version", 0) + 1
    return result, len(pending)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dashboard", required=True, choices=["telego", "telego-health"])
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--datasource-uid")
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve():
        parser.error("input and output paths must differ")
    if args.output.exists():
        parser.error("output already exists; choose a new review file")
    bundle = json.loads(Path(__file__).with_name("middleend-response-panels.json").read_text())
    dashboard = json.loads(args.input.read_text())
    try:
        result, count = merge(dashboard, bundle["dashboards"][args.dashboard], args.datasource_uid)
    except ValueError as error:
        parser.error(str(error))
    with args.output.open("x") as output:
        json.dump(result, output, indent=2, ensure_ascii=False)
        output.write("\n")
    print(f"Prepared {count} additional panels in {args.output}; input unchanged.")


if __name__ == "__main__":
    main()
