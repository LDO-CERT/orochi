from datetime import datetime

import pandas as pd
import plotly.express as px
from django.views.generic.base import TemplateView


def parse_body_line(line):
    parts = line.strip("|").split("|")  # Split the line using '|' as the delimiter
    plugin_description = parts[0].strip()
    if "-" in plugin_description:
        # Split on the first hyphen
        plugin, description = plugin_description.split("-", 1)
        plugin = plugin.strip()
        description = description.strip()
    else:
        plugin = "Unknown"
        description = plugin_description
    try:
        timestamp = int(parts[-1].strip())
        date = datetime.utcfromtimestamp(timestamp) if timestamp > 0 else None
    except ValueError:
        date = None
    return {"Plugin": plugin, "Description": description, "Date": date}


def clean_bodywork(file_path):
    data = []
    with open(file_path, "r") as file:
        for line in file:
            if line.strip():
                parsed_data = parse_body_line(line)
                if parsed_data["Date"] is not None:
                    data.append(parsed_data)
    df = pd.DataFrame(data)
    df["Date"] = pd.to_datetime(df["Date"])
    fig = px.scatter(
        df,
        x="Date",
        y="Plugin",
        color="Plugin",
        hover_data=["Description"],
        title="Interactive Event Timeline from Volatility Body File (Detailed)",
        labels={"Date": "Date", "Plugin": "Plugin Type"},
        template="plotly_white",
    )
    fig.update_traces(
        marker=dict(size=6, opacity=0.8)
    )  # Adjust marker size and opacity
    fig.update_layout(
        xaxis_title="Date",
        yaxis_title="Plugin Type",
        legend_title="Plugin",
        xaxis=dict(
            rangeselector=dict(
                buttons=list(
                    [
                        dict(count=1, label="1m", step="month", stepmode="backward"),
                        dict(count=6, label="6m", step="month", stepmode="backward"),
                        dict(count=1, label="YTD", step="year", stepmode="todate"),
                        dict(count=1, label="1y", step="year", stepmode="backward"),
                        dict(step="all"),
                    ]
                )
            ),
            rangeslider=dict(visible=True),
            type="date",
        ),
        yaxis=dict(
            title="Plugin Type",
            categoryorder="total ascending",  # Order categories alphabetically or by event count
        ),
        hovermode="closest",  # Improve hover interactions
        height=600,  # Adjust the height for better visibility
    )
    return fig.to_html(full_html=False, default_height=500, default_width=700)
