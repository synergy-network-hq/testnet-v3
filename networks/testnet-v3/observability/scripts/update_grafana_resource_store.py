#!/usr/bin/env python3
import hashlib
import json
import pathlib
import sqlite3
import sys
import time


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: update_grafana_resource_store.py <grafana.db> <dashboard_dir>", file=sys.stderr)
        return 2

    db_path = pathlib.Path(sys.argv[1])
    dashboard_dir = pathlib.Path(sys.argv[2])

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    now = int(time.time() * 1_000_000)
    updated: list[str] = []

    for path in sorted(dashboard_dir.glob("synergy-*.json")):
        spec = json.loads(path.read_text())
        uid = spec["uid"]
        row = cur.execute(
            """
            select guid, resource_version, cast(value as text)
            from resource
            where [group] = 'dashboard.grafana.app'
              and resource = 'dashboards'
              and name = ?
            """,
            (uid,),
        ).fetchone()
        if not row:
            continue

        guid, resource_version, raw_value = row
        document = json.loads(raw_value)
        document["spec"] = spec

        metadata = document.setdefault("metadata", {})
        metadata["name"] = uid
        annotations = metadata.setdefault("annotations", {})
        annotations["grafana.app/sourcePath"] = str(path)
        annotations["grafana.app/sourceTimestamp"] = str(int(path.stat().st_mtime * 1000))
        annotations["grafana.app/sourceChecksum"] = hashlib.md5(path.read_bytes()).hexdigest()

        labels = metadata.setdefault("labels", {})
        labels.pop("grafana.app/deprecatedInternalID", None)

        metadata["generation"] = int(metadata.get("generation", 0)) + 1
        document["status"] = document.get("status", {})

        next_version = max(int(resource_version or 0) + 1, now)
        cur.execute(
            """
            update resource
            set resource_version = ?, value = ?, previous_resource_version = ?
            where guid = ?
            """,
            (
                next_version,
                json.dumps(document, separators=(",", ":")),
                resource_version or 0,
                guid,
            ),
        )
        updated.append(uid)

    conn.commit()
    print(f"updated {len(updated)} dashboards")
    for uid in updated:
        print(uid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
