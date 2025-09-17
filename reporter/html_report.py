# reporter/html_report.py
from jinja2 import Template
from datetime import datetime, timezone, timedelta   # <<< MODIFIED: use timezone/timedelta for Beijing time

TEMPLATE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Scan Report - {{ target }}</title></head>
<body>
<h1>Web Scanner Report</h1>
<p><strong>Target:</strong> {{ target }}</p>
<p><strong>Scan time:</strong> {{ time }}</p>
<h2>Findings</h2>
{% for f in findings %}
<div>
  <h3>{{ f.type }} - {{ f.url }}</h3>
  <p>Param: {{ f.param }}</p>
  <p>Payload: {{ f.payload }}</p>
  <p>Evidence: {{ f.evidence }}</p>
  <p>Severity: {{ f.severity }}</p>
</div>
{% endfor %}
</body></html>"""

class HTMLReport:
    def __init__(self, target, pages_count, findings):
        self.target = target
        self.pages_count = pages_count
        self.findings = findings

    def generate(self, output_path="report.html"):
        # <<< MODIFIED: format time in Beijing (UTC+8)
        beijing_tz = timezone(timedelta(hours=8))
        now = datetime.now(timezone.utc).astimezone(beijing_tz).strftime("%Y-%m-%d %H:%M:%S %Z")
        template = Template(TEMPLATE)
        html = template.render(target=self.target, time=now, findings=self.findings)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        return output_path
