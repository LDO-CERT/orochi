import json
import re
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots


def parse_body_line(line):
    parts = line.strip().strip("|").split("|")
    plugin_description = parts[0].strip()
    if len(parts) >= 5 and (
        "-" in parts[1]
        or "/" in parts[1]
        or "\\" in parts[1]
        or parts[0] in ("0", "")
        or len(parts[0]) == 32
    ):
        plugin_description = parts[1].strip()

    if "-" in plugin_description:
        plugin, description = plugin_description.split("-", 1)
        plugin = plugin.strip()
        description = description.strip()
    elif plugin_description.startswith("[") and "]" in plugin_description:
        bracket_idx = plugin_description.index("]")
        plugin = plugin_description[1:bracket_idx].strip()
        description = plugin_description[bracket_idx + 1 :].strip()
    else:
        plugin = "Unknown"
        description = plugin_description

    def _to_epoch(val_str):
        try:
            v = int(str(val_str).strip())
            return v if v > 0 else None
        except (ValueError, TypeError):
            return None

    atime = None
    mtime = None
    ctime = None
    crtime = None

    if len(parts) >= 4:
        atime = _to_epoch(parts[-4])
        mtime = _to_epoch(parts[-3])
        ctime = _to_epoch(parts[-2])
        crtime = _to_epoch(parts[-1])

    m_char = "M" if mtime else "."
    a_char = "A" if atime else "."
    c_char = "C" if ctime else "."
    b_char = "B" if crtime else "."
    macb = f"{m_char}{a_char}{c_char}{b_char}"
    if macb == "....":
        macb = None

    # SleuthKit bodyfile v3 timestamp columns: ...|atime|mtime|ctime|crtime
    # Primary timestamp: prefer crtime (Born), then ctime (Change), then mtime (Modify), then atime (Access)
    ts_val = crtime or ctime or mtime or atime
    if not ts_val:
        candidates = parts[-4:] if len(parts) >= 4 else parts[-1:]
        for candidate in reversed(candidates):
            v = _to_epoch(candidate)
            if v:
                ts_val = v
                break

    date = None
    if ts_val and ts_val > 0:
        try:
            date = datetime.fromtimestamp(ts_val, timezone.utc).replace(tzinfo=None)
        except (ValueError, OverflowError, OSError):
            date = None

    return {
        "Plugin": plugin,
        "Description": description,
        "Date": date,
        "macb": macb,
        "mtime": mtime,
        "atime": atime,
        "ctime": ctime,
        "crtime": crtime,
    }


def clean_bodywork(file_path=None, values=None, title=None):
    data = []
    if file_path:
        p = Path(file_path)
        if p.exists():
            with open(p, "r", errors="ignore") as file:
                for idx, line in enumerate(file):
                    if line.strip():
                        parsed_data = parse_body_line(line)
                        if parsed_data["Date"] is not None:
                            parsed_data["id"] = f"bf-{idx}"
                            data.append(parsed_data)
    elif values:
        for idx, v in enumerate(values):
            val_id = None
            val_dict = v
            if hasattr(v, "value"):
                val_id = v.pk
                val_dict = v.value
            elif isinstance(v, dict) and "value" in v and isinstance(v["value"], dict):
                val_id = v.get("id") or idx
                val_dict = v["value"]
            elif isinstance(v, dict):
                val_id = v.get("id") or idx
                val_dict = v

            date_val = (
                val_dict.get("Created Date")
                or val_dict.get("Modified Date")
                or val_dict.get("Accessed Date")
                or val_dict.get("Changed Date")
                or val_dict.get("Date")
            )
            if isinstance(date_val, (int, float)):
                try:
                    date_val = datetime.fromtimestamp(date_val, timezone.utc).replace(
                        tzinfo=None
                    )
                except Exception:
                    pass
            if date_val:
                data.append(
                    {
                        "id": val_id,
                        "Plugin": val_dict.get("Plugin", "Unknown"),
                        "Description": val_dict.get("Description", ""),
                        "Date": date_val,
                        "dump_name": val_dict.get("dump_name", "Memory Dump"),
                    }
                )

    if not data:
        return ""

    df = pd.DataFrame(data)
    df["Date"] = pd.to_datetime(df["Date"], errors="coerce")
    df = df.dropna(subset=["Date"]).sort_values("Date")
    if df.empty:
        return ""

    # Truncate descriptions slightly for hover performance on large datasets
    df["HoverDesc"] = df["Description"].astype(str).str.slice(0, 150)
    df["Category"] = df.apply(
        lambda r: categorize_event(r["Plugin"], r["Description"]), axis=1
    )

    # Compute timespan
    min_dt = df["Date"].min()
    max_dt = df["Date"].max()
    timespan_seconds = (
        max((max_dt - min_dt).total_seconds(), 0)
        if pd.notnull(min_dt) and pd.notnull(max_dt)
        else 0
    )

    # Dynamic incident-adaptive range selector buttons
    if timespan_seconds <= 300:  # <= 5 minutes
        range_buttons = [
            dict(count=10, label="10s", step="second", stepmode="backward"),
            dict(count=30, label="30s", step="second", stepmode="backward"),
            dict(count=1, label="1m", step="minute", stepmode="backward"),
            dict(count=2, label="2m", step="minute", stepmode="backward"),
            dict(step="all", label="All"),
        ]
    elif timespan_seconds <= 3600:  # <= 1 hour
        range_buttons = [
            dict(count=1, label="1m", step="minute", stepmode="backward"),
            dict(count=5, label="5m", step="minute", stepmode="backward"),
            dict(count=15, label="15m", step="minute", stepmode="backward"),
            dict(count=30, label="30m", step="minute", stepmode="backward"),
            dict(step="all", label="All"),
        ]
    elif timespan_seconds <= 86400:  # <= 24 hours
        range_buttons = [
            dict(count=15, label="15m", step="minute", stepmode="backward"),
            dict(count=1, label="1h", step="hour", stepmode="backward"),
            dict(count=4, label="4h", step="hour", stepmode="backward"),
            dict(count=12, label="12h", step="hour", stepmode="backward"),
            dict(step="all", label="All"),
        ]
    else:  # Multi-day
        range_buttons = [
            dict(count=1, label="1h", step="hour", stepmode="backward"),
            dict(count=6, label="6h", step="hour", stepmode="backward"),
            dict(count=1, label="1d", step="day", stepmode="backward"),
            dict(count=7, label="7d", step="day", stepmode="backward"),
            dict(step="all", label="All"),
        ]

    # Dual subplot: Row 1 Activity Density Histogram, Row 2 Timeline by Plugin
    fig = make_subplots(
        rows=2,
        cols=1,
        shared_xaxes=True,
        row_heights=[0.28, 0.72],
        vertical_spacing=0.12,
        subplot_titles=(
            "Activity Density (Event Spikes)",
            "Timeline by Plugin",
        ),
    )

    # Subplot 1: Volume Histogram
    fig.add_trace(
        go.Histogram(
            x=df["Date"],
            name="Activity Spikes",
            marker_color="rgba(59, 130, 246, 0.75)",
            showlegend=False,
            hovertemplate="Time Range: %{x}<br>Event Count: %{y}<extra></extra>",
        ),
        row=1,
        col=1,
    )

    # Subplot 2: Plugin Scatter with Outlier-Preserving Decimation & Category Palette
    PRIORITY_CATEGORIES = {"command", "process", "network", "registry"}
    groups = list(df.groupby("Plugin"))
    # Sort groups so high-risk/priority categories are evaluated first
    groups.sort(
        key=lambda item: (
            0
            if any(cat in PRIORITY_CATEGORIES for cat in item[1]["Category"].unique())
            else 1
        )
    )

    for plugin_name, group in groups:
        is_priority = any(
            cat in PRIORITY_CATEGORIES for cat in group["Category"].unique()
        )
        n = len(group)
        limit = min(n, 500) if is_priority else min(n, 250)

        if n > limit:
            plot_group = group.sample(n=limit, random_state=42).sort_values("Date")
        else:
            plot_group = group

        dominant_cat = (
            plot_group["Category"].mode().iloc[0] if not plot_group.empty else "system"
        )
        cat_info = CATEGORY_DEFINITIONS.get(
            dominant_cat, CATEGORY_DEFINITIONS["system"]
        )
        marker_color = cat_info["color"]

        fig.add_trace(
            go.Scatter(
                x=plot_group["Date"],
                y=plot_group["Plugin"],
                mode="markers",
                name=str(plugin_name),
                text=plot_group["HoverDesc"],
                hovertemplate=f"<b>%{{y}}</b> ({cat_info['name']})<br>Date: %{{x}}<br>%{{text}}<extra></extra>",
                marker=dict(size=7, opacity=0.8, color=marker_color),
            ),
            row=2,
            col=1,
        )

    fig.update_layout(
        title=title
        or "Interactive Event Timeline from Volatility Body File (Detailed)",
        height=650,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#94a3b8"),
        hovermode="closest",
        legend=dict(
            title=dict(text="Plugin", font=dict(color="#cbd5e1")),
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
            font=dict(color="#94a3b8"),
        ),
        xaxis2=dict(
            title="Date",
            type="date",
            gridcolor="rgba(148, 163, 184, 0.15)",
            rangeselector=dict(
                buttons=range_buttons,
                bgcolor="rgba(30, 41, 59, 0.8)",
                activecolor="rgba(59, 130, 246, 0.8)",
                font=dict(color="#e2e8f0"),
            ),
            rangeslider=dict(visible=True, bgcolor="rgba(15, 23, 42, 0.5)"),
        ),
        xaxis=dict(
            gridcolor="rgba(148, 163, 184, 0.15)",
        ),
        yaxis=dict(
            title="Spikes",
            gridcolor="rgba(148, 163, 184, 0.15)",
        ),
        yaxis2=dict(
            title="Plugin",
            type="category",
            categoryorder="array",
            categoryarray=sorted(
                df["Plugin"].unique(), key=lambda x: len(df[df["Plugin"] == x])
            ),
            range=[-0.5, len(df["Plugin"].unique()) - 0.3],
            automargin=True,
            gridcolor="rgba(148, 163, 184, 0.15)",
        ),
        margin=dict(l=60, r=40, t=80, b=40),
    )

    return fig.to_html(
        full_html=False,
        include_plotlyjs=False,
        default_height=650,
        default_width=None,
        config={"responsive": True},
    )


# ---------------------------------------------------------------------------
# Timesketch-like Navigable Timeline Processing Engine
# ---------------------------------------------------------------------------

CATEGORY_DEFINITIONS = {
    "process": {
        "name": "Process Activity",
        "icon": "fa-solid fa-gears",
        "color": "#a855f7",
        "badge_bg": "bg-purple-100 dark:bg-purple-950/60",
        "badge_text": "text-purple-700 dark:text-purple-300",
        "border": "border-purple-300 dark:border-purple-800",
    },
    "network": {
        "name": "Network Sockets",
        "icon": "fa-solid fa-network-wired",
        "color": "#3b82f6",
        "badge_bg": "bg-blue-100 dark:bg-blue-950/60",
        "badge_text": "text-blue-700 dark:text-blue-300",
        "border": "border-blue-300 dark:border-blue-800",
    },
    "filesystem": {
        "name": "Filesystem & MFT",
        "icon": "fa-solid fa-file-lines",
        "color": "#10b981",
        "badge_bg": "bg-emerald-100 dark:bg-emerald-950/60",
        "badge_text": "text-emerald-700 dark:text-emerald-300",
        "border": "border-emerald-300 dark:border-emerald-800",
    },
    "command": {
        "name": "Command Shell",
        "icon": "fa-solid fa-terminal",
        "color": "#f43f5e",
        "badge_bg": "bg-rose-100 dark:bg-rose-950/60",
        "badge_text": "text-rose-700 dark:text-rose-300",
        "border": "border-rose-300 dark:border-rose-800",
    },
    "registry": {
        "name": "Registry & Persistence",
        "icon": "fa-solid fa-key",
        "color": "#f59e0b",
        "badge_bg": "bg-amber-100 dark:bg-amber-950/60",
        "badge_text": "text-amber-700 dark:text-amber-300",
        "border": "border-amber-300 dark:border-amber-800",
    },
    "system": {
        "name": "System & Memory",
        "icon": "fa-solid fa-microchip",
        "color": "#71717a",
        "badge_bg": "bg-zinc-100 dark:bg-zinc-800",
        "badge_text": "text-zinc-700 dark:text-zinc-300",
        "border": "border-zinc-300 dark:border-zinc-700",
    },
}


def categorize_event(plugin_name, description):
    p = str(plugin_name).lower()
    d = str(description).lower()
    if (
        any(
            k in p
            for k in [
                "pslist",
                "pstree",
                "psscan",
                "thrdscan",
                "sessions",
                "ldrmodules",
            ]
        )
        or "process" in d
    ):
        return "process"
    if any(
        k in p for k in ["netscan", "netstat", "connscan", "sockets", "sockscan"]
    ) or any(
        k in d
        for k in ["socket", "connection", "port", "established", "listen", "tcp", "udp"]
    ):
        return "network"
    if any(
        k in p
        for k in ["filescan", "mftscan", "mft", "cachedfiles", "files", "handles"]
    ) or any(k in d for k in ["file", "inode", "mft", "directory", "\\"]):
        return "filesystem"
    if any(k in p for k in ["bash", "cmdline", "consoles"]) or any(
        k in d for k in ["bash", "cmd.exe", "command line", "powershell"]
    ):
        return "command"
    if any(
        k in p
        for k in ["userassist", "registry", "shimcache", "amcache", "certificates"]
    ) or any(k in d for k in ["hkey", "registry", "hive", "key:"]):
        return "registry"
    return "system"


def format_relative_delta(seconds):
    if seconds < 0:
        return f"-{format_relative_delta(abs(seconds)).lstrip('+')}"
    if seconds < 60:
        if (
            isinstance(seconds, float)
            and 0 < seconds < 10
            and (seconds != int(seconds))
        ):
            return f"+{seconds:.2f}s"
        return f"+{int(seconds)}s"
    if seconds < 3600:
        m = int(seconds // 60)
        s = int(seconds % 60)
        return f"+{m}m {s}s"
    if seconds < 86400:
        h = int(seconds // 3600)
        m = int((seconds % 3600) // 60)
        return f"+{h}h {m}m"
    d = int(seconds // 86400)
    h = int((seconds % 86400) // 3600)
    return f"+{d}d {h}h"


def format_timespan(seconds):
    if seconds < 60:
        return f"{int(seconds)} seconds"
    if seconds < 3600:
        return f"{int(seconds // 60)} minutes"
    if seconds < 86400:
        h = int(seconds // 3600)
        m = int((seconds % 3600) // 60)
        return f"{h} hours, {m} mins"
    d = int(seconds // 86400)
    h = int((seconds % 86400) // 3600)
    return f"{d} days, {h} hours"


def extract_timeline_entries(
    file_path=None, values=None, dump_name=None, dump_index=None, dump_color=None
):
    entries = []
    if file_path:
        p = Path(file_path)
        if p.exists():
            with open(p, "r", errors="ignore") as f:
                for idx, line in enumerate(f):
                    if line.strip():
                        item = parse_body_line(line)
                        if item.get("Date") is not None:
                            item["id"] = f"bf-{idx}"
                            item["dump_name"] = dump_name or "Memory Dump"
                            item["dump_index"] = dump_index or ""
                            item["dump_color"] = dump_color or "#3b82f6"
                            entries.append(item)
    elif values:
        for idx, v in enumerate(values):
            val_id = None
            if hasattr(v, "value"):
                val_id = v.pk
                val_dict = v.value
            elif isinstance(v, dict) and "value" in v and isinstance(v["value"], dict):
                val_id = v.get("id") or idx
                val_dict = v["value"]
            elif isinstance(v, dict):
                val_id = v.get("id") or idx
                val_dict = v
            else:
                continue

            m_val = val_dict.get("Modified Date")
            a_val = val_dict.get("Accessed Date")
            c_val = val_dict.get("Changed Date")
            b_val = val_dict.get("Created Date")

            date_val = b_val or m_val or a_val or c_val or val_dict.get("Date")
            if date_val:
                m_c = "M" if m_val else "."
                a_c = "A" if a_val else "."
                c_c = "C" if c_val else "."
                b_c = "B" if b_val else "."
                macb = f"{m_c}{a_c}{c_c}{b_c}"
                if macb == "....":
                    macb = val_dict.get("macb")

                entries.append(
                    {
                        "id": val_id,
                        "value_id": val_id,
                        "Plugin": val_dict.get("Plugin", "Unknown"),
                        "Description": val_dict.get("Description", ""),
                        "Date": date_val,
                        "macb": macb,
                        "dump_name": dump_name or "Memory Dump",
                        "dump_index": dump_index or "",
                        "dump_color": dump_color or "#3b82f6",
                    }
                )
    return entries


def build_timeline_feed(entries, limit=5000, threat_findings=None, secrets=None):
    if not entries:
        return {
            "events": [],
            "compact_events": [],
            "compact_events_json": "[]",
            "histogram": [],
            "categories": [],
            "stats": {
                "total_events": 0,
                "earliest_date": None,
                "latest_date": None,
                "timespan_display": "0s",
                "categories_count": 0,
                "max_density": 0,
                "threat_count": 0,
            },
        }

    # Index threat rules for fast pattern matching against timeline events
    threat_rules = []
    if threat_findings:
        for tf in threat_findings:
            keywords = []
            entity = getattr(tf, "entity", "") or ""
            if entity:
                keywords.append(str(entity).lower().strip())
                pid_match = re.search(
                    r"\b(?:pid\s*[:=]?\s*)?(\d+)\b", str(entity).lower()
                )
                if pid_match:
                    keywords.append(pid_match.group(1))

            raw_data = getattr(tf, "raw_data", None)
            if isinstance(raw_data, dict):
                for k in ["pid", "PID", "Process", "process", "cmdline", "CommandLine"]:
                    val = raw_data.get(k)
                    if val:
                        keywords.append(str(val).lower().strip())

            threat_rules.append(
                {
                    "severity": getattr(tf, "severity", "High"),
                    "rule_name": getattr(tf, "rule_name", "Anomalous Triage Finding"),
                    "mitre": getattr(tf, "mitre_technique", "") or "",
                    "entity": entity,
                    "keywords": [kw for kw in set(keywords) if len(kw) >= 2],
                }
            )

    if secrets:
        for s in secrets:
            keywords = []
            if getattr(s, "pid", None):
                keywords.append(str(s.pid))
            if getattr(s, "process_name", None):
                keywords.append(str(s.process_name).lower().strip())
            threat_rules.append(
                {
                    "severity": "High",
                    "rule_name": f"Secret Leak: {getattr(s, 'rule_name', 'Credential')}",
                    "mitre": "T1552",
                    "entity": getattr(s, "process_name", "")
                    or str(getattr(s, "pid", "")),
                    "keywords": [kw for kw in set(keywords) if len(kw) >= 2],
                }
            )

    threat_pattern = None
    keyword_to_threat = {}
    if threat_rules:
        all_kws = []
        for tr in threat_rules:
            for kw in tr["keywords"]:
                all_kws.append(kw)
                if kw not in keyword_to_threat:
                    keyword_to_threat[kw] = tr
        if all_kws:
            all_kws.sort(key=len, reverse=True)
            threat_pattern = re.compile("|".join(re.escape(k) for k in all_kws))

    parsed_events = []
    for item in entries:
        dt = item.get("Date")
        if isinstance(dt, str):
            try:
                s = dt.replace("Z", "+00:00")
                dt = datetime.fromisoformat(s)
                if dt.tzinfo is not None:
                    dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            except Exception:
                try:
                    dt = pd.to_datetime(dt).to_pydatetime()
                    if dt.tzinfo is not None:
                        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
                except Exception:
                    continue
        elif isinstance(dt, (int, float)):
            try:
                dt = datetime.fromtimestamp(dt, timezone.utc).replace(tzinfo=None)
            except Exception:
                continue

        if not isinstance(dt, datetime):
            continue

        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)

        plugin_name = str(item.get("Plugin", "Unknown"))
        description = str(item.get("Description", ""))
        cat_key = categorize_event(plugin_name, description)
        cat_def = CATEGORY_DEFINITIONS[cat_key]

        desc_lower = description.lower()
        matched_threat = None
        if threat_pattern:
            m = threat_pattern.search(desc_lower)
            if m:
                tr = keyword_to_threat.get(m.group(0))
                if tr:
                    matched_threat = {
                        "severity": tr["severity"],
                        "rule_name": tr["rule_name"],
                        "mitre": tr["mitre"],
                        "entity": tr["entity"],
                    }

        parsed_events.append(
            {
                "id": item.get("id"),
                "value_id": item.get("value_id"),
                "dump_name": item.get("dump_name", "Memory Dump"),
                "dump_index": item.get("dump_index", ""),
                "dump_color": item.get("dump_color", "#3b82f6"),
                "date": dt,
                "timestamp_iso": dt.isoformat(),
                "timestamp_display": dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "plugin": plugin_name,
                "category": cat_key,
                "category_name": cat_def["name"],
                "category_icon": cat_def["icon"],
                "category_color": cat_def["color"],
                "category_bg": cat_def["badge_bg"],
                "category_text": cat_def["badge_text"],
                "category_border": cat_def["border"],
                "description": description,
                "macb": item.get("macb"),
                "threat": matched_threat,
            }
        )

    if not parsed_events:
        return {
            "events": [],
            "compact_events": [],
            "compact_events_json": "[]",
            "histogram": [],
            "categories": [],
            "stats": {
                "total_events": 0,
                "earliest_date": None,
                "latest_date": None,
                "timespan_display": "0s",
                "categories_count": 0,
                "max_density": 0,
                "threat_count": 0,
            },
        }

    # Sort chronologically
    parsed_events.sort(key=lambda x: x["date"])
    min_date = parsed_events[0]["date"]
    max_date = parsed_events[-1]["date"]
    timespan_seconds = max((max_date - min_date).total_seconds(), 0)

    for ev in parsed_events:
        delta_s = (ev["date"] - min_date).total_seconds()
        ev["relative_delta"] = format_relative_delta(delta_s)
        ev["delta_seconds"] = delta_s

    # Adaptive Histogram Buckets
    if timespan_seconds == 0:
        num_buckets = 1
        bucket_duration = 1.0
    elif timespan_seconds <= 60:
        # High-density short window (e.g. 29s): 1 bucket per second
        num_buckets = max(int(timespan_seconds) + 1, 1)
        bucket_duration = 1.0
    elif timespan_seconds <= 1800:
        # Medium window (1 to 30 mins): 30 buckets
        num_buckets = 30
        bucket_duration = timespan_seconds / num_buckets
    else:
        # Long window: 30 buckets
        num_buckets = 30
        bucket_duration = timespan_seconds / num_buckets

    buckets = []
    for b_idx in range(num_buckets):
        b_start = min_date.timestamp() + (b_idx * bucket_duration)
        b_end = b_start + bucket_duration
        b_start_dt = datetime.fromtimestamp(b_start, timezone.utc).replace(tzinfo=None)
        b_end_dt = datetime.fromtimestamp(b_end, timezone.utc).replace(tzinfo=None)

        if timespan_seconds <= 60:
            label = (
                b_start_dt.strftime("%H:%M:%S") + f" (+{int(b_idx * bucket_duration)}s)"
            )
        elif timespan_seconds < 86400:
            label = b_start_dt.strftime("%H:%M:%S")
        else:
            label = b_start_dt.strftime("%m-%d %H:%M")

        buckets.append(
            {
                "index": b_idx,
                "start": label,
                "start_iso": b_start_dt.isoformat(),
                "end_iso": b_end_dt.isoformat(),
                "start_ts": b_start,
                "end_ts": b_end,
                "count": 0,
                "category_counts": {},
                "has_threat": False,
                "threat_count": 0,
            }
        )

    for ev in parsed_events:
        if timespan_seconds == 0:
            b_idx = 0
        else:
            b_idx = min(
                int((ev["date"] - min_date).total_seconds() / bucket_duration),
                num_buckets - 1,
            )
        buckets[b_idx]["count"] += 1
        cat = ev["category"]
        buckets[b_idx]["category_counts"][cat] = (
            buckets[b_idx]["category_counts"].get(cat, 0) + 1
        )
        if ev.get("threat"):
            buckets[b_idx]["has_threat"] = True
            buckets[b_idx]["threat_count"] += 1

    max_bucket_count = max((b["count"] for b in buckets), default=1)
    for b in buckets:
        b["height_pct"] = (
            max(int((b["count"] / max(max_bucket_count, 1)) * 100), 6)
            if b["count"] > 0
            else 0
        )

    cat_counts = {}
    for ev in parsed_events:
        k = ev["category"]
        cat_counts[k] = cat_counts.get(k, 0) + 1

    categories_list = []
    for k, count in sorted(cat_counts.items(), key=lambda x: x[1], reverse=True):
        c_def = CATEGORY_DEFINITIONS.get(k, CATEGORY_DEFINITIONS["system"])
        categories_list.append(
            {
                "key": k,
                "name": c_def["name"],
                "count": count,
                "icon": c_def["icon"],
                "color": c_def["color"],
                "badge_bg": c_def["badge_bg"],
                "badge_text": c_def["badge_text"],
                "border": c_def["border"],
            }
        )

    stats = {
        "total_events": len(parsed_events),
        "earliest_date": min_date.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "latest_date": max_date.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "timespan_display": format_timespan(timespan_seconds),
        "categories_count": len(categories_list),
        "max_density": max_bucket_count,
        "threat_count": sum(1 for ev in parsed_events if ev.get("threat")),
    }

    # Ultra-compact JSON for fast client-side streaming (up to 50k events)
    compact_events = []
    for ev in parsed_events[:50000]:
        compact_events.append(
            {
                "id": ev["id"],
                "vid": ev["value_id"],
                "dump": ev["dump_name"],
                "didx": ev["dump_index"],
                "dcol": ev["dump_color"],
                "t": ev["date"].timestamp(),
                "ts": ev["timestamp_display"],
                "rel": ev["relative_delta"],
                "delta": ev["delta_seconds"],
                "p": ev["plugin"],
                "c": ev["category"],
                "desc": ev["description"],
                "m": ev.get("macb"),
                "th": ev.get("threat"),
            }
        )

    compact_events_json = json.dumps(compact_events, default=str).replace("</", "<\\/")

    return {
        "events": parsed_events[:limit],
        "compact_events": compact_events,
        "compact_events_json": compact_events_json,
        "histogram": buckets,
        "categories": categories_list,
        "stats": stats,
    }
