# reporter/pdf_report.py
"""
将 HTML 报告转换为 PDF 的轻量封装（可选）。
尝试使用 pdfkit（wkhtmltopdf 作为底层），如果不可用就抛出异常并给出提示。
该脚本不在默认流程中调用（scanner.py 仍生成 HTML），但你可以在需要时调用：
from reporter.pdf_report import html_to_pdf
html_to_pdf("report.html", "report.pdf")
"""

import os

def html_to_pdf(html_path, pdf_path):
    try:
        import pdfkit
    except Exception:
        raise RuntimeError("pdfkit is not installed. Install with 'pip install pdfkit' and ensure wkhtmltopdf is available in PATH.")

    if not os.path.exists(html_path):
        raise FileNotFoundError(f"HTML file not found: {html_path}")

    # Simple conversion - respects default options
    try:
        pdfkit.from_file(html_path, pdf_path)
    except Exception as e:
        raise RuntimeError(f"Failed to convert HTML to PDF: {e}")

    return pdf_path
