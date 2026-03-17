#!/usr/bin/env python3
"""
FortiAnalyzer – Fortigate Traffic Log Analyzer
Parses Fortigate application-control logs and generates
structured summaries for use with the Excel dashboard.
"""

import os
import json
import ipaddress
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime

# ===== DIRECTORY LAYOUT =====
# Project root is one level above the scripts/ folder
BASE_DIR = Path(__file__).parent.parent

INPUT_DIR  = BASE_DIR / "input"
OUTPUT_DIR = BASE_DIR / "output"
SCRIPTS_DIR = BASE_DIR / "scripts"
ARCHIVE_DIR = INPUT_DIR / "archive"

# Ensure directories exist
INPUT_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)
SCRIPTS_DIR.mkdir(exist_ok=True)
ARCHIVE_DIR.mkdir(exist_ok=True)

SUMMARY_FILE      = OUTPUT_DIR / "last_summary.json"
CATEGORIES_PATH   = SCRIPTS_DIR / "categories.json"


# ===== CATEGORY CLASSIFICATION =====

def load_categories():
    """Load category mapping from JSON file."""
    if not CATEGORIES_PATH.exists():
        return {"overrides": {}, "fallback": {}}
    with CATEGORIES_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


CATEGORY_CFG = load_categories()


def classify_category(app: str | None, appcat: str | None) -> str:
    """
    Resolve a traffic category for the given app name and app-category.
    Priority: explicit override > fallback by appcat > 'Other'
    """
    app    = (app    or "").strip()
    appcat = (appcat or "").strip()

    # 1) Exact/partial override by app name
    for key, category in CATEGORY_CFG.get("overrides", {}).items():
        if key.lower() in app.lower():
            return category

    # 2) Fallback by appcat
    for key, category in CATEGORY_CFG.get("fallback", {}).items():
        if key.lower() in appcat.lower():
            return category

    # 3) Default
    return "Other"


def is_private_ip(ip: str) -> bool:
    """Return True if the address falls within a private/RFC-1918 range."""
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def classify_traffic_direction(dstip: str | None, dstcountry: str | None) -> str:
    """Return 'Internal' or 'External' based on destination."""
    dstip      = (dstip      or "").strip()
    dstcountry = (dstcountry or "").strip()

    if dstcountry == "Reserved":
        return "Internal"
    if dstip and is_private_ip(dstip):
        return "Internal"
    return "External"


# ===== FILE HELPERS =====

def list_log_files():
    """Return all .log files in input/ (ignores archive/ sub-folder)."""
    return sorted([f for f in INPUT_DIR.glob("*.log") if f.is_file()])


def select_file(files):
    """Interactive CLI prompt — returns the chosen Path or None."""
    if not files:
        print("No .log files found in 'input/'.")
        return None

    print("\nAvailable files in 'input/':")
    for idx, f in enumerate(files, start=1):
        print(f"  {idx} – {f.name}")

    while True:
        choice = input("\nEnter the file number to process: ").strip()
        if not choice.isdigit():
            print("Invalid input. Please enter a number.")
            continue
        idx = int(choice)
        if 1 <= idx <= len(files):
            return files[idx - 1]
        print("Number out of range. Try again.")


def parse_fortigate_line(line: str) -> dict | None:
    """
    Parse a single Fortigate log line of the form:
        key1=value1 key2=value2 key3="value with spaces" ...

    Returns a dict of key -> value, or None for blank/unparseable lines.
    """
    line = line.strip()
    if not line:
        return None

    fields = {}
    for part in line.split():
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        fields[key] = value.strip('"')

    return fields if fields else None


# ===== ADVANCED METRICS =====

def aggregate_metrics(records: list[dict]) -> dict:
    """
    Compute per-device, per-app, per-domain, category, direction,
    hourly consumption, and Shadow-IT metrics from a list of log records.
    """
    by_device    = {}
    by_app       = {}
    by_domain    = {}
    by_category  = defaultdict(int)
    direction    = {"Internal": 0, "External": 0}
    hourly       = defaultdict(int)
    shadow_it    = defaultdict(lambda: {"bytes": 0, "ips": set()})

    # Baseline approved-application list (edit to match your environment)
    APPROVED_APPS = [
        "Teams", "Outlook", "SharePoint", "OneDrive",
        "YouTube", "Google.Services", "Windows.Update",
        "iCloud", "WhatsApp", "Instagram", "Facebook",
    ]

    for r in records:
        srcip      = r.get("srcip")
        dstip      = r.get("dstip")
        app        = r.get("app")
        appcat     = r.get("appcat")
        hostname   = r.get("hostname")
        dstcountry = r.get("dstcountry")
        sessionid  = r.get("sessionid")
        date       = r.get("date")
        time_      = r.get("time")

        sent         = int(r.get("sent") or 0)
        rcvd         = int(r.get("rcvd") or 0)
        total_bytes  = sent + rcvd

        # Category
        category = classify_category(app, appcat)
        by_category[category] += total_bytes

        # Traffic direction
        traffic_dir = classify_traffic_direction(dstip, dstcountry)
        direction[traffic_dir] += total_bytes

        # Per device (srcip)
        if srcip:
            dev = by_device.setdefault(srcip, {
                "total_bytes": 0,
                "apps":        Counter(),
                "domains":     Counter(),
                "sessions":    set(),
            })
            dev["total_bytes"] += total_bytes
            if app:
                dev["apps"][app] += total_bytes
            if hostname:
                dev["domains"][hostname] += total_bytes
            if sessionid:
                dev["sessions"].add(sessionid)

        # Per app
        if app:
            a = by_app.setdefault(app, {
                "total_bytes": 0,
                "ips":         set(),
                "sessions":    set(),
                "category":    category,
            })
            a["total_bytes"] += total_bytes
            if srcip:
                a["ips"].add(srcip)
            if sessionid:
                a["sessions"].add(sessionid)

        # Per domain (hostname)
        if hostname:
            d = by_domain.setdefault(hostname, {
                "total_bytes": 0,
                "ips":         set(),
                "apps":        set(),
                "sessions":    set(),
            })
            d["total_bytes"] += total_bytes
            if srcip:
                d["ips"].add(srcip)
            if app:
                d["apps"].add(app)
            if sessionid:
                d["sessions"].add(sessionid)

        # Hourly consumption
        if date and time_:
            hour_key = f"{date} {time_[:2]}:00"
            hourly[hour_key] += total_bytes

        # Shadow IT: apps not in the approved list
        if app:
            approved = any(p.lower() in app.lower() for p in APPROVED_APPS)
            if not approved:
                s = shadow_it[app]
                s["bytes"] += total_bytes
                if srcip:
                    s["ips"].add(srcip)

    # ---- Serialize to JSON-safe structures ----
    total_bytes_all = sum(by_category.values()) or 1

    devices_out = []
    for ip, info in by_device.items():
        devices_out.append({
            "ip":           ip,
            "total_bytes":  info["total_bytes"],
            "total_gb":     info["total_bytes"] / (1024 ** 3),
            "apps":         dict(info["apps"].most_common(10)),
            "domains":      dict(info["domains"].most_common(10)),
            "qtd_sessoes":  len(info["sessions"]),
        })

    apps_out = []
    for app, info in by_app.items():
        apps_out.append({
            "app":         app,
            "category":    info["category"],
            "total_bytes": info["total_bytes"],
            "total_gb":    info["total_bytes"] / (1024 ** 3),
            "qtd_ips":     len(info["ips"]),
            "qtd_sessoes": len(info["sessions"]),
        })

    domains_out = []
    for dom, info in by_domain.items():
        domains_out.append({
            "domain":      dom,
            "total_bytes": info["total_bytes"],
            "total_gb":    info["total_bytes"] / (1024 ** 3),
            "qtd_ips":     len(info["ips"]),
            "qtd_apps":    len(info["apps"]),
            "qtd_sessoes": len(info["sessions"]),
        })

    categories_out = []
    for cat, b in by_category.items():
        categories_out.append({
            "categoria":   cat,
            "total_bytes": b,
            "total_gb":    b / (1024 ** 3),
            "percentual":  (b / total_bytes_all) * 100,
        })

    direction_out = []
    for tipo, b in direction.items():
        direction_out.append({
            "tipo":        tipo,
            "total_bytes": b,
            "total_gb":    b / (1024 ** 3),
            "percentual":  (b / total_bytes_all) * 100,
        })

    hourly_out = []
    for hour, b in sorted(hourly.items()):
        hourly_out.append({
            "hora":        hour,
            "total_bytes": b,
            "total_gb":    b / (1024 ** 3),
        })

    shadow_out = []
    for app, info in shadow_it.items():
        shadow_out.append({
            "app":         app,
            "total_bytes": info["bytes"],
            "total_gb":    info["bytes"] / (1024 ** 3),
            "qtd_ips":     len(info["ips"]),
        })

    return {
        "por_dispositivo":  devices_out,
        "por_app":          apps_out,
        "por_dominio":      domains_out,
        "por_categoria":    categories_out,
        "interno_externo":  direction_out,
        "consumo_por_hora": hourly_out,
        "shadow_it":        shadow_out,
    }


# ===== MAIN PROCESSING =====

def process_file(log_path: Path) -> dict:
    """
    Read a Fortigate .log file line by line, aggregate all metrics,
    and return a summary dict ready for JSON serialization.
    """
    print(f"\nProcessing: {log_path.name}\n")

    total_lines   = 0
    valid_records = 0
    examples      = []

    # Basic aggregations
    devices = defaultdict(lambda: {"bytes": 0, "sent": 0, "rcvd": 0,
                                    "apps": Counter(), "hosts": Counter()})
    apps    = defaultdict(lambda: {"bytes": 0, "sent": 0, "rcvd": 0,
                                    "devices": Counter()})
    hosts   = defaultdict(lambda: {"bytes": 0, "sent": 0, "rcvd": 0,
                                    "apps": Counter(), "devices": Counter()})
    hours   = defaultdict(lambda: {"bytes": 0, "sent": 0, "rcvd": 0})

    # Full record list for advanced metrics
    records = []

    with log_path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            total_lines += 1
            data = parse_fortigate_line(line)
            if not data:
                continue

            valid_records += 1

            date       = data.get("date")
            time_str   = data.get("time")
            srcip      = data.get("srcip") or data.get("src")
            dstip      = data.get("dstip")
            app        = data.get("app")
            appcat     = data.get("appcat")
            sessionid  = data.get("sessionid")
            dstcountry = data.get("dstcountry")
            srcintfrole = data.get("srcintfrole")
            dstintfrole = data.get("dstintfrole")
            sent       = int(data.get("sentbyte") or data.get("sent") or 0)
            rcvd       = int(data.get("rcvdbyte") or data.get("rcvd") or 0)
            srcname    = data.get("srcname")
            srcmac     = data.get("srcmac")
            hostname   = data.get("hostname")
            policyname = data.get("policyname")

            record = {
                "date": date, "time": time_str, "srcip": srcip,
                "dstip": dstip, "app": app, "appcat": appcat,
                "sessionid": sessionid, "dstcountry": dstcountry,
                "srcintfrole": srcintfrole, "dstintfrole": dstintfrole,
                "sent": sent, "rcvd": rcvd, "srcname": srcname,
                "srcmac": srcmac, "hostname": hostname,
                "policyname": policyname,
            }
            records.append(record)

            if len(examples) < 5:
                examples.append(record)

            dev_key = srcip or "UNKNOWN"
            total   = sent + rcvd

            # Aggregate by device
            devices[dev_key]["bytes"] += total
            devices[dev_key]["sent"]  += sent
            devices[dev_key]["rcvd"]  += rcvd
            if app:
                devices[dev_key]["apps"][app] += total
            if hostname:
                devices[dev_key]["hosts"][hostname] += total
            devices[dev_key]["srcname"] = srcname
            devices[dev_key]["srcmac"]  = srcmac

            # Aggregate by app
            if app:
                apps[app]["bytes"] += total
                apps[app]["sent"]  += sent
                apps[app]["rcvd"]  += rcvd
                if srcip:
                    apps[app]["devices"][srcip] += total

            # Aggregate by hostname
            if hostname:
                hosts[hostname]["bytes"] += total
                hosts[hostname]["sent"]  += sent
                hosts[hostname]["rcvd"]  += rcvd
                if app:
                    hosts[hostname]["apps"][app] += total
                if srcip:
                    hosts[hostname]["devices"][srcip] += total

            # Aggregate by hour
            if date and time_str:
                try:
                    hour    = time_str.split(":")[0]
                    hk      = f"{date} {hour}:00"
                    hours[hk]["bytes"] += total
                    hours[hk]["sent"]  += sent
                    hours[hk]["rcvd"]  += rcvd
                except Exception:
                    pass

    print(f"Total lines read    : {total_lines}")
    print(f"Valid records parsed: {valid_records}\n")
    print("Sample records (up to 5):")
    for i, ex in enumerate(examples, start=1):
        print(f"\n--- Record {i} ---")
        for k, v in ex.items():
            print(f"  {k}: {v}")

    # Build serializable summary
    summary = {
        "arquivo":         log_path.name,
        "total_linhas":    total_lines,
        "total_registros": valid_records,
        "generated_at":    datetime.now().isoformat(timespec="seconds"),
        "dispositivos":    {},
        "apps":            {},
        "hosts":           {},
        "horas":           {},
    }

    for dev, info in devices.items():
        summary["dispositivos"][dev] = {
            "bytes":   info["bytes"],
            "sent":    info["sent"],
            "rcvd":    info["rcvd"],
            "srcname": info.get("srcname"),
            "srcmac":  info.get("srcmac"),
            "apps":    dict(info["apps"].most_common(10)),
            "hosts":   dict(info["hosts"].most_common(10)),
        }

    for app_name, info in apps.items():
        summary["apps"][app_name] = {
            "bytes":   info["bytes"],
            "sent":    info["sent"],
            "rcvd":    info["rcvd"],
            "devices": dict(info["devices"].most_common(10)),
        }

    for host, info in hosts.items():
        summary["hosts"][host] = {
            "bytes":   info["bytes"],
            "sent":    info["sent"],
            "rcvd":    info["rcvd"],
            "apps":    dict(info["apps"].most_common(10)),
            "devices": dict(info["devices"].most_common(10)),
        }

    for h, info in hours.items():
        summary["horas"][h] = {
            "bytes": info["bytes"],
            "sent":  info["sent"],
            "rcvd":  info["rcvd"],
        }

    # Advanced metrics
    summary["metricas_avancadas"] = aggregate_metrics(records)

    return summary


def archive_file(path: Path):
    """Move a processed log to the archive/ sub-folder."""
    dest = ARCHIVE_DIR / path.name
    try:
        path.rename(dest)
        print(f"\nFile archived to: {dest}")
    except Exception as e:
        print(f"\n[WARNING] Could not move file to archive: {e}")


def save_summary(summary: dict):
    """Persist the current summary as a named file and as last_summary.json."""
    named_file = OUTPUT_DIR / f"summary_{summary['arquivo']}.json"
    with named_file.open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    with SUMMARY_FILE.open("w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"\nSummary saved to  : {named_file}")
    print(f"Reference summary : {SUMMARY_FILE}")


def load_previous_summary() -> dict | None:
    """Return the last saved summary dict, or None on first run."""
    if not SUMMARY_FILE.exists():
        return None
    try:
        with SUMMARY_FILE.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def generate_text_report(summary: dict, previous: dict | None = None, top_n: int = 20) -> str:
    """
    Build a detailed plain-text report, optionally comparing with
    the previous week's summary.
    """
    lines = []
    lines.append("WEEKLY TRAFFIC REPORT – FortiAnalyzer")
    lines.append(f"File    : {summary['arquivo']}")
    lines.append(f"Generated: {summary['generated_at']}")
    lines.append("")

    # ---- Top Devices ----
    lines.append("=== TOP DEVICES (by bytes) ===")
    devs = sorted(
        summary["dispositivos"].items(),
        key=lambda x: x[1]["bytes"],
        reverse=True
    )[:top_n]

    for i, (dev, info) in enumerate(devs, start=1):
        name    = info.get("srcname") or "-"
        mac     = info.get("srcmac")  or "-"
        total_gb = info["bytes"] / (1024 ** 3)
        lines.append(f"{i}. {dev} ({name}) [{mac}] – {total_gb:.2f} GB")

        top_apps = list(info["apps"].items())[:3]
        if top_apps:
            s = ", ".join(f"{a} ({b/(1024**3):.2f} GB)" for a, b in top_apps)
            lines.append(f"   Top apps   : {s}")

        top_hosts = list(info["hosts"].items())[:3]
        if top_hosts:
            s = ", ".join(f"{h} ({b/(1024**3):.2f} GB)" for h, b in top_hosts)
            lines.append(f"   Top domains: {s}")

    lines.append("")

    # ---- Top Apps ----
    lines.append("=== TOP APPLICATIONS (by bytes) ===")
    apps_sorted = sorted(
        summary["apps"].items(),
        key=lambda x: x[1]["bytes"],
        reverse=True
    )[:top_n]

    for i, (app, info) in enumerate(apps_sorted, start=1):
        total_gb    = info["bytes"] / (1024 ** 3)
        qtd_devices = len(info["devices"])
        lines.append(f"{i}. {app} – {total_gb:.2f} GB – {qtd_devices} devices")

    lines.append("")

    # ---- Top Domains ----
    lines.append("=== TOP DOMAINS (by bytes) ===")
    hosts_sorted = sorted(
        summary["hosts"].items(),
        key=lambda x: x[1]["bytes"],
        reverse=True
    )[:top_n]

    for i, (host, info) in enumerate(hosts_sorted, start=1):
        total_gb = info["bytes"] / (1024 ** 3)
        lines.append(f"{i}. {host} – {total_gb:.2f} GB")
        top_apps = list(info["apps"].items())[:3]
        if top_apps:
            s = ", ".join(f"{a} ({b/(1024**3):.2f} GB)" for a, b in top_apps)
            lines.append(f"   Top apps: {s}")

    lines.append("")

    # ---- Hourly Peaks ----
    lines.append("=== PEAK HOURS ===")
    hours_sorted = sorted(
        summary["horas"].items(),
        key=lambda x: x[1]["bytes"],
        reverse=True
    )[:top_n]

    for h, info in hours_sorted:
        total_gb = info["bytes"] / (1024 ** 3)
        lines.append(f"{h} – {total_gb:.2f} GB")

    lines.append("")

    # ---- Anomaly Detection ----
    lines.append("=== ANOMALIES DETECTED ===")
    THRESHOLD_GB = 10
    anomaly_found = False
    for dev, info in devs:
        total_gb = info["bytes"] / (1024 ** 3)
        if total_gb >= THRESHOLD_GB:
            name = info.get("srcname") or "-"
            lines.append(
                f"ALERT: {dev} ({name}) consumed {total_gb:.2f} GB "
                f"(threshold: {THRESHOLD_GB} GB)."
            )
            anomaly_found = True

    if not anomaly_found:
        lines.append("No anomalies detected under current thresholds.")

    lines.append("")

    # ---- Week-over-week comparison ----
    if previous:
        lines.append("=== WEEK-OVER-WEEK – APPLICATIONS ===")
        apps_prev = previous.get("apps", {})
        for app, info in apps_sorted[:top_n]:
            cur_gb  = info["bytes"] / (1024 ** 3)
            prev_gb = apps_prev.get(app, {}).get("bytes", 0) / (1024 ** 3)
            delta   = cur_gb - prev_gb
            lines.append(
                f"{app}: current {cur_gb:.2f} GB | previous {prev_gb:.2f} GB | delta {delta:+.2f} GB"
            )

        lines.append("")
        lines.append("=== WEEK-OVER-WEEK – DEVICES ===")
        devs_prev = previous.get("dispositivos", {})
        for dev, info in devs[:top_n]:
            cur_gb  = info["bytes"] / (1024 ** 3)
            prev_gb = devs_prev.get(dev, {}).get("bytes", 0) / (1024 ** 3)
            delta   = cur_gb - prev_gb
            lines.append(
                f"{dev}: current {cur_gb:.2f} GB | previous {prev_gb:.2f} GB | delta {delta:+.2f} GB"
            )
    else:
        lines.append("No previous summary found (first run).")

    report = "\n".join(lines)

    report_file = OUTPUT_DIR / f"report_{summary['arquivo']}.txt"
    with report_file.open("w", encoding="utf-8") as f:
        f.write(report)

    print(f"\nReport saved to: {report_file}")
    return report


def main():
    print("=" * 55)
    print("   FortiAnalyzer – Fortigate Traffic Log Analyzer")
    print("=" * 55)

    files = list_log_files()
    chosen = select_file(files)
    if not chosen:
        return

    summary  = process_file(chosen)
    previous = load_previous_summary()

    generate_text_report(summary, previous, top_n=20)

    # Keep a backup of the previous summary before overwriting
    prev_file = OUTPUT_DIR / "previous_summary.json"
    if SUMMARY_FILE.exists():
        try:
            old = load_previous_summary()
            if old:
                with prev_file.open("w", encoding="utf-8") as f:
                    json.dump(old, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    save_summary(summary)
    archive_file(chosen)

    print("\nAdvanced metrics completed.\n")


if __name__ == "__main__":
    main()
