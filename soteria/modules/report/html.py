"""Soteria — HTML template renderer for executive reports."""
from datetime import datetime

SEVERITY_COLORS = {
    "Critical": "#dc2626",
    "High": "#ea580c",
    "Medium": "#eab308",
    "Low": "#16a34a",
    "Info": "#6b7280",
}


def render_html(report: dict) -> str:
    """Render the report dict as a self-contained HTML file."""
    counts = report["counts"]
    findings = report["findings"]
    top_risks = report["top_risks"]
    recs = report["recommendations"]

    severity_cards = "".join(
        f"""
        <div class="card" style="border-left: 4px solid {SEVERITY_COLORS[sev]};">
          <div class="card-label">{sev}</div>
          <div class="card-value">{counts[sev]}</div>
        </div>
        """
        for sev in ["Critical", "High", "Medium", "Low"]
    )

    top_risk_rows = ""
    for f in top_risks:
        sev = f.get("severity", "Info")
        color = SEVERITY_COLORS.get(sev, "#6b7280")
        top_risk_rows += f"""
        <div class="risk">
          <div class="risk-header">
            <span class="risk-sev" style="background: {color};">{sev}</span>
            <strong>{_esc(f.get('title', 'Untitled'))}</strong>
          </div>
          <div class="risk-url">{_esc(f.get('url', ''))}</div>
          <div class="risk-desc">{_esc((f.get('description') or '')[:300])}</div>
        </div>
        """

    all_findings_rows = ""
    for f in findings:
        sev = f.get("severity", "Info")
        color = SEVERITY_COLORS.get(sev, "#6b7280")
        curl = f.get("curl_command") or ""
        all_findings_rows += f"""
        <tr>
          <td><span class="sev-pill" style="background: {color};">{sev}</span></td>
          <td>{_esc(f.get('type', ''))}</td>
          <td>{_esc(f.get('title', ''))}</td>
          <td class="url-cell">{_esc(f.get('url', ''))}</td>
          <td class="curl-cell"><code>{_esc(curl[:120])}</code></td>
        </tr>
        """

    recs_html = "".join(f"<li>{_esc(r)}</li>" for r in recs)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Soteria Executive Report — {_esc(report['org_name'])}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #f9fafb;
    color: #111827;
    margin: 0;
    padding: 40px 20px;
    line-height: 1.5;
  }}
  .container {{ max-width: 1000px; margin: 0 auto; }}
  .header {{
    background: linear-gradient(135deg, #1e3a8a, #0f172a);
    color: white;
    padding: 40px;
    border-radius: 12px;
    margin-bottom: 30px;
  }}
  .header h1 {{ margin: 0 0 8px 0; font-size: 28px; }}
  .header p {{ margin: 4px 0; opacity: 0.85; font-size: 14px; }}
  .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 30px; }}
  .card {{
    background: white;
    border-radius: 8px;
    padding: 20px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.06);
  }}
  .card-label {{ font-size: 12px; text-transform: uppercase; color: #6b7280; letter-spacing: 0.5px; }}
  .card-value {{ font-size: 32px; font-weight: 700; margin-top: 8px; }}
  .section {{ background: white; border-radius: 12px; padding: 30px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.06); }}
  .section h2 {{ margin: 0 0 20px 0; font-size: 20px; color: #111827; }}
  .risk {{ padding: 16px 0; border-bottom: 1px solid #f3f4f6; }}
  .risk:last-child {{ border-bottom: none; }}
  .risk-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }}
  .risk-sev {{ color: white; font-size: 11px; padding: 3px 8px; border-radius: 4px; text-transform: uppercase; letter-spacing: 0.5px; }}
  .risk-url {{ color: #6b7280; font-family: monospace; font-size: 13px; margin-bottom: 4px; }}
  .risk-desc {{ font-size: 14px; color: #374151; }}
  ul {{ padding-left: 20px; }}
  li {{ margin-bottom: 8px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ text-align: left; padding: 10px; border-bottom: 2px solid #e5e7eb; color: #6b7280; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }}
  td {{ padding: 12px 10px; border-bottom: 1px solid #f3f4f6; vertical-align: top; }}
  .sev-pill {{ color: white; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
  .url-cell, .curl-cell {{ font-family: monospace; font-size: 12px; color: #4b5563; word-break: break-all; }}
  .curl-cell code {{ background: #f3f4f6; padding: 2px 6px; border-radius: 3px; }}
  .footer {{ text-align: center; color: #9ca3af; font-size: 12px; margin-top: 40px; }}
  @media print {{
    body {{ background: white; padding: 0; }}
    .section, .card, .header {{ box-shadow: none; }}
  }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>Soteria Security Report</h1>
    <p><strong>{_esc(report['org_name'])}</strong></p>
    <p>Period: {report['period_start']} → {report['period_end']} ({report['period_days']} days)</p>
    <p>Generated: {report['generated_at']}</p>
  </div>

  <div class="grid">
    {severity_cards}
  </div>

  <div class="section">
    <h2>Summary</h2>
    <p>Soteria ran continuous external attack surface testing for <strong>{_esc(report['org_name'])}</strong> over the last {report['period_days']} days.
    A total of <strong>{report['total_findings']} finding(s)</strong> were validated across the external attack surface.</p>
    {f'<p>Mean Time To Remediate (MTTR): <strong>{report["mttr"]:.1f} days</strong></p>' if report.get('mttr') else ''}
  </div>

  <div class="section">
    <h2>Top Risks</h2>
    {top_risk_rows if top_risk_rows else '<p>No findings in this period.</p>'}
  </div>

  <div class="section">
    <h2>Recommendations</h2>
    <ul>{recs_html}</ul>
  </div>

  <div class="section">
    <h2>All Findings</h2>
    <table>
      <thead>
        <tr><th>Severity</th><th>Type</th><th>Title</th><th>Endpoint</th><th>Reproduction</th></tr>
      </thead>
      <tbody>
        {all_findings_rows if all_findings_rows else '<tr><td colspan="5">No findings.</td></tr>'}
      </tbody>
    </table>
  </div>

  <div class="footer">
    Generated by Soteria — Continuous protection. Proven findings.
  </div>
</div>
</body>
</html>
"""


def _esc(s: str) -> str:
    """Escape HTML special characters."""
    if s is None:
        return ""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
