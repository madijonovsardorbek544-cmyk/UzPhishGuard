import os
import sqlite3
import pandas as pd
import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output
import plotly.express as px

# Dash ilovasini yaratish
app = dash.Dash(
    __name__,
    meta_tags=[{"name": "viewport", "content": "width=device-width, initial-scale=1"}]
)
app.title = "UzPhishGuard SOC v2 — Threat Map"
server = app.server  # Render loyihasi ishga tushishi uchun majburiy qism

DB_NAME = "phish_guard.db"

# ==========================================
# 🎨 KIBER-SOC DARK DIZAYN (STYLES)
# ==========================================
DARK_BG = "#0f111a"
CARD_BG = "#161925"
TEXT_COLOR = "#ffffff"
ACCENT_CYAN = "#00f0ff"
ACCENT_RED = "#ff0055"

app.layout = html.Div(
    style={"backgroundColor": DARK_BG, "color": TEXT_COLOR, "fontFamily": "Segoe UI, Roboto, sans-serif", "padding": "20px"},
    children=[
        # Auto-refresh xizmati (Har 10 soniyada dashboardni AI bazasidan jonli yangilaydi)
        dcc.Interval(id="live-interval", interval=10000, n_intervals=0),
        
        # Sarlavha paneli
        html.Div(
            style={"textAlign": "center", "borderBottom": f"2px solid {ACCENT_CYAN}", "paddingBottom": "20px", "marginBottom": "30px"},
            children=[
                html.H1("🛡️ UzPhishGuard SOC v2 Dashboard", style={"color": ACCENT_CYAN, "fontWeight": "bold", "margin": "0"}),
                html.P("Next-Gen Llama-3 AI & Global Threat Intel Live Monitoring", style={"color": "#8a91ad", "margin": "5px 0 0 0"}),
            ]
        ),
        
        # 3-BOSQICH: MULTI-TENANT FILTER (Guruhlar bo'yicha saralash paneli)
        html.Div(
            style={"backgroundColor": CARD_BG, "padding": "20px", "borderRadius": "10px", "marginBottom": "20px", "boxShadow": "0 4px 15px rgba(0,0,0,0.5)"},
            children=[
                html.Label("🌐 Monitoring qilinayotgan Guruhni tanlang:", style={"color": ACCENT_CYAN, "fontWeight": "bold", "marginBottom": "10px", "display": "block"}),
                dcc.Dropdown(
                    id="group-dropdown",
                    options=[{"label": "Barcha Guruhlar (Global)", "value": "ALL"}],
                    value="ALL",
                    clearable=False,
                    style={"backgroundColor": "#1f2335", "color": "#000000", "borderRadius": "5px"}
                )
            ]
        ),
        
        # Statisika Kartalari (Counters)
        html.Div(
            className="row",
            style={"display": "flex", "flexWrap": "wrap", "gap": "20px", "marginBottom": "20px"},
            children=[
                html.Div(id="card-total", style={"flex": "1", "minWidth": "220px", "backgroundColor": CARD_BG, "padding": "20px", "borderRadius": "10px", "textAlign": "center", "borderLeft": "5px solid #00ff66"}),
                html.Div(id="card-blocked", style={"flex": "1", "minWidth": "220px", "backgroundColor": CARD_BG, "padding": "20px", "borderRadius": "10px", "textAlign": "center", "borderLeft": f"5px solid {ACCENT_RED}"}),
                html.Div(id="card-risk", style={"flex": "1", "minWidth": "220px", "backgroundColor": CARD_BG, "padding": "20px", "borderRadius": "10px", "textAlign": "center", "borderLeft": f"5px solid #ffaa00"}),
            ]
        ),
        
        # Jonli Interaktiv Kiber Xarita (Threat Map)
        html.Div(
            style={"backgroundColor": CARD_BG, "padding": "20px", "borderRadius": "10px", "marginBottom": "30px", "boxShadow": "0 4px 15px rgba(0,0,0,0.5)"},
            children=[
                html.H3("🗺️ Live Cyber Threat Map (Hujumlar Koordinatalari)", style={"color": ACCENT_CYAN, "fontSize": "18px", "marginBottom": "15px"}),
                dcc.Graph(id="threat-map", config={"displayModeBar": False})
            ]
        ),
        
        # Oxirgi kiber-hodisalar jadvali (Incident Logs)
        html.Div(
            style={"backgroundColor": CARD_BG, "padding": "20px", "borderRadius": "10px", "boxShadow": "0 4px 15px rgba(0,0,0,0.5)"},
            children=[
                html.H3("🚨 Real-Time Incident Response Logs", style={"color": ACCENT_RED, "fontSize": "18px", "marginBottom": "15px"}),
                html.Div(id="table-container")
            ]
        )
    ]
)

# ==========================================
# ⚡ LACKEND CALLBACK MANTIQI
# ==========================================
@app.callback(
    [
        Output("group-dropdown", "options"),
        Output("card-total", "children"),
        Output("card-blocked", "children"),
        Output("card-risk", "children"),
        Output("threat-map", "figure"),
        Output("table-container", "children")
    ],
    [Input("group-dropdown", "value"), Input("live-interval", "n_intervals")]
)
def update_dashboard(selected_group, n):
    # 1. Ma'lumotlarni bazadan o'qish
    if not os.path.exists(DB_NAME):
        # Agar baza hali yaratilmagan bo'lsa bo'sh framework qaytaradi
        return [{"label": "Barcha Guruhlar (Global)", "value": "ALL"}], "", "", "", px.scatter_mapbox(), "Baza topilmadi."
    
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query("SELECT * FROM scanned_links ORDER BY id DESC", conn)
    conn.close()
    
    if df.empty:
        return [{"label": "Barcha Guruhlar (Global)", "value": "ALL"}], "0", "0", "0%", px.scatter_mapbox(), "Hozircha kiber-hujumlar aniqlanmadi."

    # Dropdown guruhlar ro'yxatini yangilash (Multi-tenant xususiyati)
    unique_groups = df["chat_title"].dropna().unique()
    dropdown_options = [{"label": "Barcha Guruhlar (Global)", "value": "ALL"}]
    for g in unique_groups:
        dropdown_options.append({"label": str(g), "value": str(g)})
        
    # 2. Tanlangan guruh bo'yicha filterlash
    if selected_group != "ALL":
        filtered_df = df[df["chat_title"] == selected_group]
    else:
        filtered_df = df

    # 3. Hisoblagichlarni hisoblash (Metrics)
    total_scans = len(filtered_df)
    blocked_count = len(filtered_df[filtered_df["status"].str.contains("BLOCKED", na=False)])
    avg_risk = f"{int(filtered_df['risk_score'].mean())}%" if total_scans > 0 else "0%"
    
    card_total_content = [html.H5("JAMI TEKSHIRILDI", style={"color": "#8a91ad", "fontSize": "14px", "margin": "0"}), html.H2(str(total_scans), style={"color": "#00ff66", "margin": "5px 0 0 0", "fontWeight": "bold"})]
    card_blocked_content = [html.H5("BLOKLANDI (FISHING)", style={"color": "#8a91ad", "fontSize": "14px", "margin": "0"}), html.H2(str(blocked_count), style={"color": ACCENT_RED, "margin": "5px 0 0 0", "fontWeight": "bold"})]
    card_risk_content = [html.H5("O'RTAChA XAVF", style={"color": "#8a91ad", "fontSize": "14px", "margin": "0"}), html.H2(avg_risk, style={"color": "#ffaa00", "margin": "5px 0 0 0", "fontWeight": "bold"})]

    # 4. Kiber Xaritani chizish (Mapbox Plotly)
    # Faqat koordinatalari aniq bo'lgan (0.0 bo'lmagan) nuqtalarni xaritaga chiqaramiz
    map_df = filtered_df[(filtered_df["latitude"] != 0.0) & (filtered_df["longitude"] != 0.0)]
    
    if map_df.empty:
        # Agar koordinata bo'lmasa, standart O'zbekiston markazi ko'rsatiladi
        fig = px.scatter_mapbox(lat=[41.311081], lon=[69.240562], zoom=2)
    else:
        fig = px.scatter_mapbox(
            map_df,
            lat="latitude",
            lon="longitude",
            hover_name="url",
            hover_data={"chat_title": True, "username": True, "ip_address": True, "country": True, "risk_score": True, "latitude": False, "longitude": False},
            color="risk_score",
            color_continuous_scale=["#00ff66", "#ffaa00", "#ff0055"],
            size=[12] * len(map_df),
            zoom=2
        )
        
    fig.update_layout(
        mapbox_style="carto-darkmatter", # Professional to'q kiber-uslub
        margin={"r": 0, "t": 0, "l": 0, "b": 0},
        paper_bgcolor=CARD_BG,
        plot_bgcolor=CARD_BG,
        font_color=TEXT_COLOR,
        coloraxis_showscale=False
    )

    # 5. Incidentlar jadvalini generatsiya qilish
    table = dash_table.DataTable(
        data=filtered_df.to_dict("records"),
        columns=[
            {"name": "Sana", "id": "scan_date"},
            {"name": "Guruh", "id": "chat_title"},
            {"name": "Foydalanuvchi", "id": "username"},
            {"name": "Havola (URL)", "id": "url"},
            {"name": "Tizim Qarori", "id": "status"},
            {"name": "Server IP", "id": "ip_address"},
            {"name": "Davlat", "id": "country"}
        ],
        style_header={
            "backgroundColor": "#1f2335",
            "color": ACCENT_CYAN,
            "fontWeight": "bold",
            "border": "1px solid #2e344f"
        },
        style_data={
            "backgroundColor": CARD_BG,
            "color": TEXT_COLOR,
            "border": "1px solid #2e344f"
        },
        style_cell={
            "textAlign": "left",
            "padding": "10px",
            "overflow": "hidden",
            "textOverflow": "ellipsis",
            "maxWidth": 200
        },
        page_size=10
    )

    return dropdown_options, card_total_content, card_blocked_content, card_risk_content, fig, table


if __name__ == "__main__":
    # Render platformasida portni avtomat moslashtirish
    port = int(os.environ.get("PORT", 8050))
    app.run_server(host="0.0.0.0", port=port)
