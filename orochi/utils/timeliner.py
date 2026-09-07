from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots


def parse_body_line(line):
    parts = line.strip().strip("|").split("|")
    plugin_description = parts[0].strip()
    if "-" in plugin_description:
        plugin, description = plugin_description.split("-", 1)
        plugin = plugin.strip()
        description = description.strip()
    else:
        plugin = "Unknown"
        description = plugin_description

    date = None
    # SleuthKit bodyfile v3 timestamp columns: ...|atime|mtime|ctime|crtime
    # Inspect trailing fields in reverse order to find the first valid epoch timestamp
    candidates = parts[-4:] if len(parts) >= 4 else parts[-1:]
    ts_val = None
    for candidate in reversed(candidates):
        try:
            val = int(candidate.strip())
            if val > 0:
                ts_val = val
                break
        except (ValueError, TypeError):
            continue

    if ts_val and ts_val > 0:
        try:
            date = datetime.fromtimestamp(ts_val, timezone.utc).replace(tzinfo=None)
        except (ValueError, OverflowError, OSError):
            date = None

    return {"Plugin": plugin, "Description": description, "Date": date}


def clean_bodywork(file_path=None, values=None, title=None):
    data = []
    if file_path:
        p = Path(file_path)
        if p.exists():
            with open(p, "r", errors="ignore") as file:
                for line in file:
                    if line.strip():
                        parsed_data = parse_body_line(line)
                        if parsed_data["Date"] is not None:
                            data.append(parsed_data)
    elif values:
        for v in values:
            date_val = (
                v.get("Created Date")
                or v.get("Modified Date")
                or v.get("Accessed Date")
                or v.get("Changed Date")
                or v.get("Date")
            )
            if date_val:
                data.append(
                    {
                        "Plugin": v.get("Plugin", "Unknown"),
                        "Description": v.get("Description", ""),
                        "Date": date_val,
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

    # Subplot 2: Plugin Scatter
    # Sample up to 1000 points per plugin to ensure responsive browser rendering
    for plugin_name, group in df.groupby("Plugin"):
        plot_group = group
        if len(group) > 1000:
            plot_group = group.sample(n=1000, random_state=42).sort_values("Date")

        fig.add_trace(
            go.Scatter(
                x=plot_group["Date"],
                y=plot_group["Plugin"],
                mode="markers",
                name=str(plugin_name),
                text=plot_group["HoverDesc"],
                hovertemplate="<b>%{y}</b><br>Date: %{x}<br>%{text}<extra></extra>",
                marker=dict(size=6, opacity=0.75),
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
                buttons=[
                    dict(count=1, label="1m", step="month", stepmode="backward"),
                    dict(count=6, label="6m", step="month", stepmode="backward"),
                    dict(count=1, label="YTD", step="year", stepmode="todate"),
                    dict(count=1, label="1y", step="year", stepmode="backward"),
                    dict(step="all"),
                ],
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
