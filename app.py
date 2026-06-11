import json
import os
import re
from datetime import datetime
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st
from dotenv import load_dotenv
from google import genai


load_dotenv()

APP_TITLE = "AI Network Log Analyzer"
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

DNS_PATTERNS = [
    r"\bdns\b.*\b(fail|failed|failure|timeout|unreachable|refused|servfail|nxdomain)\b",
    r"\b(server can't find|temporary failure in name resolution|name or service not known)\b",
    r"\b(nxdomain|servfail|dns_probe_finished)\b",
]

AUTH_PATTERNS = [
    r"\b(auth|authentication|login|ssh|radius|vpn)\b.*\b(fail|failed|failure|denied|invalid|unauthorized|rejected)\b",
    r"\b(failed password|invalid user|access denied|401 unauthorized|403 forbidden)\b",
]

TIMEOUT_PATTERNS = [
    r"\b(timeout|timed out|request timeout|connection timeout|read timeout|i/o timeout)\b",
    r"\b(no response from|deadline exceeded)\b",
]

PACKET_LOSS_PATTERNS = [
    r"\b(packet loss|packets lost|loss=\d+%|\d+% packet loss)\b",
    r"\bicmp_seq=.*\b(unreachable|timeout)\b",
    r"\b(rx errors|tx errors|dropped packets|drops)\b",
]


def read_uploaded_file(uploaded_file) -> str:
    raw = uploaded_file.read()
    for encoding in ("utf-8", "utf-16", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def match_any(text: str, patterns: list[str]) -> bool:
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def parse_timestamp(line: str):
    candidates = [
        r"(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})",
        r"(?P<ts>\d{2}/\d{2}/\d{4}[ T]\d{2}:\d{2}:\d{2})",
        r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
    ]
    for pattern in candidates:
        match = re.search(pattern, line)
        if not match:
            continue
        value = match.group("ts")
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%m/%d/%Y %H:%M:%S", "%b %d %H:%M:%S"):
            try:
                parsed = datetime.strptime(value, fmt)
                if parsed.year == 1900:
                    parsed = parsed.replace(year=datetime.now().year)
                return parsed
            except ValueError:
                pass
    return None


def classify_line(line: str) -> dict:
    lower = line.lower()
    findings = {
        "DNS failure": match_any(lower, DNS_PATTERNS),
        "Authentication failure": match_any(lower, AUTH_PATTERNS),
        "Timeout error": match_any(lower, TIMEOUT_PATTERNS),
        "Packet loss": match_any(lower, PACKET_LOSS_PATTERNS),
    }
    severity = "Info"
    if findings["Authentication failure"]:
        severity = "High"
    if findings["DNS failure"] or findings["Timeout error"]:
        severity = "Medium" if severity != "High" else severity
    if findings["Packet loss"]:
        percent_match = re.search(r"(\d+(?:\.\d+)?)%\s*packet loss|loss=(\d+(?:\.\d+)?)%", lower)
        loss_value = max([float(value) for value in percent_match.groups() if value] or [0]) if percent_match else 0
        severity = "Critical" if loss_value >= 25 else max_severity(severity, "Medium")
    if "critical" in lower or "emergency" in lower or "fatal" in lower:
        severity = "Critical"
    if "error" in lower and severity == "Info":
        severity = "Low"
    return {**findings, "severity": severity}


def max_severity(left: str, right: str) -> str:
    order = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    return left if order[left] >= order[right] else right


def analyze_logs(log_text: str) -> tuple[pd.DataFrame, dict]:
    rows = []
    for line_number, line in enumerate(log_text.splitlines(), start=1):
        clean_line = line.strip()
        if not clean_line:
            continue
        classified = classify_line(clean_line)
        rows.append(
            {
                "line_number": line_number,
                "timestamp": parse_timestamp(clean_line),
                "severity": classified["severity"],
                "dns_failure": classified["DNS failure"],
                "authentication_failure": classified["Authentication failure"],
                "timeout_error": classified["Timeout error"],
                "packet_loss": classified["Packet loss"],
                "message": clean_line,
            }
        )

    df = pd.DataFrame(rows)
    if df.empty:
        summary = empty_summary()
        return df, summary

    issue_columns = ["dns_failure", "authentication_failure", "timeout_error", "packet_loss"]
    df["issue_count"] = df[issue_columns].sum(axis=1)
    relevant = df[df["issue_count"] > 0]
    summary = {
        "total_lines": int(len(df)),
        "flagged_events": int(len(relevant)),
        "dns_failures": int(df["dns_failure"].sum()),
        "authentication_failures": int(df["authentication_failure"].sum()),
        "timeout_errors": int(df["timeout_error"].sum()),
        "packet_loss_events": int(df["packet_loss"].sum()),
        "highest_severity": highest_severity(df["severity"].tolist()),
        "severity_counts": df["severity"].value_counts().to_dict(),
        "top_events": relevant[["line_number", "severity", "message"]].head(20).to_dict(orient="records"),
    }
    return df, summary


def empty_summary() -> dict:
    return {
        "total_lines": 0,
        "flagged_events": 0,
        "dns_failures": 0,
        "authentication_failures": 0,
        "timeout_errors": 0,
        "packet_loss_events": 0,
        "highest_severity": "Info",
        "severity_counts": {},
        "top_events": [],
    }


def highest_severity(values: list[str]) -> str:
    order = ["Info", "Low", "Medium", "High", "Critical"]
    return max(values or ["Info"], key=lambda item: order.index(item))


def local_recommendations(summary: dict) -> list[str]:
    recommendations = []
    if summary["dns_failures"]:
        recommendations.append("Verify resolver reachability, DNS server health, search domains, and recent zone changes.")
    if summary["authentication_failures"]:
        recommendations.append("Review failed login sources, lockout events, VPN/RADIUS status, and credential rotation activity.")
    if summary["timeout_errors"]:
        recommendations.append("Check route latency, firewall state tables, service health, and upstream dependency response times.")
    if summary["packet_loss_events"]:
        recommendations.append("Inspect interface counters, duplex settings, WAN utilization, cabling, and provider edge metrics.")
    if not recommendations:
        recommendations.append("No targeted issue pattern was detected. Expand the time window or upload more verbose logs if symptoms persist.")
    return recommendations


def gemini_analysis(summary: dict, sample_events: list[dict]) -> dict:
    api_key = os.getenv("GEMINI_API_KEY")
    fallback = {
        "executive_summary": "Gemini analysis is unavailable because GEMINI_API_KEY is not configured or the API request failed.",
        "recommendations": local_recommendations(summary),
        "next_steps": ["Add GEMINI_API_KEY to your environment for AI-generated analysis."],
        "used_gemini": False,
    }
    if not api_key:
        return fallback

    prompt = f"""
You are a senior network reliability engineer. Analyze this structured network log summary.
Return strict JSON with keys: executive_summary, probable_causes, recommendations, next_steps.
Keep recommendations practical and prioritized.

Summary:
{json.dumps(summary, indent=2)}

Representative events:
{json.dumps(sample_events[:20], indent=2)}
"""
    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(model=GEMINI_MODEL, contents=prompt)
        text = response.text.strip()
        if text.startswith("```"):
            text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.IGNORECASE | re.DOTALL).strip()
        parsed = json.loads(text)
        parsed["used_gemini"] = True
        return parsed

    except Exception as exc:
        st.error(f"GEMINI ERROR: {type(exc).__name__}: {exc}")
        fallback["executive_summary"] = f"Gemini analysis failed, so local recommendations are shown instead. Error: {exc}"
        return fallback
def render_metric_grid(summary: dict) -> None:
    cols = st.columns(6)
    cols[0].metric("Lines", summary["total_lines"])
    cols[1].metric("Flagged", summary["flagged_events"])
    cols[2].metric("DNS", summary["dns_failures"])
    cols[3].metric("Auth", summary["authentication_failures"])
    cols[4].metric("Timeouts", summary["timeout_errors"])
    cols[5].metric("Packet loss", summary["packet_loss_events"])


def render_charts(df: pd.DataFrame) -> None:
    if df.empty:
        st.info("Upload a log file or use the sample input to begin analysis.")
        return

    left, right = st.columns(2)
    severity_counts = df["severity"].value_counts().rename_axis("severity").reset_index(name="count")
    with left:
        st.plotly_chart(
            px.bar(
                severity_counts,
                x="severity",
                y="count",
                color="severity",
                category_orders={"severity": ["Info", "Low", "Medium", "High", "Critical"]},
                title="Severity distribution",
            ),
            use_container_width=True,
        )

    issue_counts = pd.DataFrame(
        [
            {"issue": "DNS failures", "count": int(df["dns_failure"].sum())},
            {"issue": "Authentication failures", "count": int(df["authentication_failure"].sum())},
            {"issue": "Timeout errors", "count": int(df["timeout_error"].sum())},
            {"issue": "Packet loss", "count": int(df["packet_loss"].sum())},
        ]
    )
    with right:
        st.plotly_chart(px.pie(issue_counts, names="issue", values="count", title="Detected issue mix"), use_container_width=True)

    timed = df.dropna(subset=["timestamp"])
    if not timed.empty:
        timeline = (
            timed.set_index("timestamp")
            .resample("5min")
            .agg(events=("message", "count"), flagged=("issue_count", "sum"))
            .reset_index()
        )
        st.plotly_chart(px.line(timeline, x="timestamp", y=["events", "flagged"], title="Event timeline"), use_container_width=True)


def main() -> None:
    st.set_page_config(page_title=APP_TITLE, page_icon="🛰️", layout="wide")
    st.title(APP_TITLE)
    st.caption("Upload network logs, detect common failure patterns, and generate Gemini-powered troubleshooting guidance.")

    with st.sidebar:
        st.header("Input")
        uploaded_files = st.file_uploader(
            "Upload log files",
            type=["log", "txt", "csv"],
            accept_multiple_files=True,
        )
        use_sample = st.checkbox("Use bundled sample logs", value=not uploaded_files)
        st.divider()
        st.caption(f"Gemini model: {GEMINI_MODEL}")
        st.caption("Set GEMINI_API_KEY to enable AI recommendations.")

    log_chunks = []
    if uploaded_files:
        for uploaded_file in uploaded_files:
            log_chunks.append(f"--- {uploaded_file.name} ---\n{read_uploaded_file(uploaded_file)}")

    if use_sample:
        sample_dir = Path(__file__).parent / "sample_logs"
        for sample_file in sorted(sample_dir.glob("*.log")):
            log_chunks.append(f"--- {sample_file.name} ---\n{sample_file.read_text(encoding='utf-8')}")

    log_text = "\n".join(log_chunks)
    editable_logs = st.text_area("Log content", value=log_text, height=260, placeholder="Paste network logs here...")

    df, summary = analyze_logs(editable_logs)
    render_metric_grid(summary)

    severity = summary["highest_severity"]
    severity_type = {
        "Critical": "error",
        "High": "error",
        "Medium": "warning",
        "Low": "info",
        "Info": "success",
    }[severity]
    getattr(st, severity_type)(f"Highest severity: {severity}")

    tabs = st.tabs(["Overview", "Events", "AI Recommendations", "Raw Data"])
    with tabs[0]:
        render_charts(df)

    with tabs[1]:
        if df.empty:
            st.info("No log events found.")
        else:
            issue_filter = st.multiselect(
                "Issue filters",
                ["dns_failure", "authentication_failure", "timeout_error", "packet_loss"],
                default=["dns_failure", "authentication_failure", "timeout_error", "packet_loss"],
            )
            filtered = df[df[issue_filter].any(axis=1)] if issue_filter else df
            st.dataframe(
                filtered[["line_number", "timestamp", "severity", *issue_filter, "message"]],
                use_container_width=True,
                hide_index=True,
            )

    with tabs[2]:
        ai_result = gemini_analysis(summary, summary["top_events"])
        if ai_result.get("used_gemini"):
            st.success("Gemini analysis completed.")
        else:
            st.warning("Using local fallback recommendations. Configure GEMINI_API_KEY for Gemini analysis.")
        st.subheader("Summary")
        st.write(ai_result.get("executive_summary", "No summary returned."))
        for label in ("probable_causes", "recommendations", "next_steps"):
            values = ai_result.get(label, [])
            if values:
                st.subheader(label.replace("_", " ").title())
                for item in values:
                    st.write(f"- {item}")

    with tabs[3]:
        if df.empty:
            st.info("No parsed data to display.")
        else:
            st.dataframe(df, use_container_width=True, hide_index=True)
            st.download_button(
                "Download analysis CSV",
                data=df.to_csv(index=False).encode("utf-8"),
                file_name="network_log_analysis.csv",
                mime="text/csv",
            )


if __name__ == "__main__":
    main()
