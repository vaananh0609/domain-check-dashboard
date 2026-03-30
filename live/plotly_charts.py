from typing import Dict

import pandas as pd
import plotly.express as px

from .constants import STATUS_BLOCKED, STATUS_DEAD, STATUS_LEAKED, STATUS_PARKED


def live_pie_chart(summary: Dict[str, int]):
    data = pd.DataFrame({"Trạng thái": list(summary.keys()), "Số lượng": list(summary.values())})
    color_map = {
        STATUS_BLOCKED: "#2e7d32",
        STATUS_LEAKED: "#c62828",
        STATUS_PARKED: "#fbc02d",
        STATUS_DEAD: "#9e9e9e",
    }

    fig = px.pie(
        data,
        names="Trạng thái",
        values="Số lượng",
        color="Trạng thái",
        color_discrete_map=color_map,
        title="Tỷ lệ kiểm thử live Gateway",
    )
    fig.update_traces(textposition="inside", textinfo="percent+label")
    try:
        fig.update_layout(font=dict(family="Helvetica"), margin=dict(l=10, r=10, t=60, b=10))
    except Exception:
        fig.update_layout(margin=dict(l=10, r=10, t=60, b=10))
    return fig
