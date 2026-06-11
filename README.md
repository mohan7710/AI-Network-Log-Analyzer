# AI Network Log Analyzer

A complete Streamlit project for uploading and analyzing network logs. The app detects common operational issues with rule-based parsing and uses the Gemini API to generate troubleshooting recommendations.

## Features

- Upload one or more `.log`, `.txt`, or `.csv` log files
- Paste or edit log content directly in the app
- Analyze network log events with Pandas
- Detect DNS failures
- Detect authentication failures
- Detect timeout errors
- Detect packet loss
- Classify severity from `Info` through `Critical`
- Visualize issue distribution and severity with Plotly
- Generate troubleshooting recommendations with Gemini
- Fall back to local recommendations when `GEMINI_API_KEY` is not configured

## Project Structure

```text
AI-Network-Log-Analyzer/
├── app.py
├── requirements.txt
├── README.md
├── .env.example
└── sample_logs/
    ├── branch_office.log
    └── vpn_gateway.log
```

## Setup

Create and activate a virtual environment:

```bash
python -m venv .venv
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Configure Gemini:

```bash
copy .env.example .env
```

Edit `.env` and set:

```text
GEMINI_API_KEY=your_gemini_api_key_here
```

## Run

```bash
streamlit run app.py
```

Then open the local URL shown by Streamlit.

## Notes

The app starts without a Gemini key and shows local fallback recommendations. Add `GEMINI_API_KEY` to enable AI-generated analysis.
