import logging
import html
import traceback
from datetime import datetime

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self, target_url, vulnerabilities):
        self.target_url = target_url
        self.vulnerabilities = vulnerabilities

    def consolidate_vulnerabilities(self):
        """Menggabungkan vulnerabilities dengan tipe yang sama"""
        consolidated = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')  # Fallback ke 'Unknown' jika 'type' hilang
            if not isinstance(vuln_type, str):
                logger.warning(f"Invalid 'type' in vulnerability, converting to string: {vuln}")
                vuln_type = str(vuln_type)
            if vuln_type not in consolidated:
                # Inisialisasi entri baru dengan semua field
                consolidated[vuln_type] = {
                    'type': vuln_type,  # Pastikan 'type' disimpan
                    'severity': vuln.get('severity', 'Unknown'),
                    'description': vuln.get('description', 'No description'),
                    'reproduce': [],
                    'mitigation': vuln.get('mitigation', 'No mitigation')
                }
            # Tambahkan langkah reproduce, hindari duplikat
            repro = vuln.get('reproduce', 'No steps')
            if isinstance(repro, str):
                repro_steps = repro.split('\n') if '\n' in repro else [repro]
            elif isinstance(repro, list):
                repro_steps = repro
            else:
                repro_steps = [str(repro)]
            for step in repro_steps:
                step = step.strip()
                if step and step not in consolidated[vuln_type]['reproduce']:
                    consolidated[vuln_type]['reproduce'].append(step)
            # Update severity jika lebih tinggi (High > Medium > Unknown)
            current_severity = consolidated[vuln_type]['severity']
            new_severity = vuln.get('severity', 'Unknown')
            if new_severity == 'High' or (new_severity == 'Medium' and current_severity == 'Unknown'):
                consolidated[vuln_type]['severity'] = new_severity
        return list(consolidated.values())

    def generate_html(self):
        """Generate a colorful HTML report with consolidated vulnerabilities"""
        logger.info("Starting HTML report generation")
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            consolidated_vulns = self.consolidate_vulnerabilities()
            total_findings = len(consolidated_vulns)

            html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'none'; style-src 'self' 'unsafe-inline';">
    <title>ApiXploit Security Report</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 20px; 
            background-color: #f0f4f8 !important; 
        }
        h1 { 
            color: #2c3e50 !important; 
            font-size: 28px; 
            text-align: center; 
            margin-bottom: 20px; 
        }
        p { 
            font-size: 16px; 
            color: #34495e !important; 
        }
        strong { 
            color: #2980b9 !important; 
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin-top: 20px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
        }
        th, td { 
            border: 2px solid #7f8c8d !important; 
            padding: 12px; 
            text-align: left; 
            vertical-align: top; 
        }
        th { 
            background-color: #3498db !important; 
            color: white !important; 
            font-weight: bold; 
        }
        tr:nth-child(even) { 
            background-color: #ecf0f1 !important; 
        }
        tr:nth-child(odd) { 
            background-color: #ffffff !important; 
        }
        tr:hover { 
            background-color: #dfe6e9 !important; 
        }
        .high { 
            color: #c0392b !important; 
            font-weight: bold; 
        }
        .medium { 
            color: #f39c12 !important; 
            font-weight: bold; 
        }
        .unknown {
            color: #7f8c8d !important;
            font-weight: bold;
        }
        .steps { 
            font-family: "Courier New", monospace; 
            white-space: pre-wrap; 
            word-wrap: break-word; 
            background-color: #f9f9f9; 
            padding: 5px; 
            border-radius: 3px; 
        }
    </style>
</head>
<body>
    <h1>ApiXploit Security Report</h1>
    <p><strong>Target:</strong> """ + html.escape(str(self.target_url)) + """</p>
    <p><strong>Timestamp:</strong> """ + html.escape(timestamp) + """</p>
    <p><strong>Total Findings:</strong> """ + str(total_findings) + """</p>
    <table>
        <tr>
            <th>Type</th>
            <th>Severity</th>
            <th>Description</th>
            <th>Steps to Reproduce</th>
            <th>Mitigation</th>
        </tr>
"""

            for vuln in consolidated_vulns:
                try:
                    vuln_type = html.escape(vuln['type'])  # 'type' selalu ada dari consolidate
                    severity = html.escape(str(vuln['severity']))
                    description = html.escape(str(vuln['description']))
                    reproduce_steps = '\n'.join([html.escape(step) for step in vuln['reproduce']])
                    mitigation = html.escape(str(vuln['mitigation']))
                    severity_class = severity.lower() if severity in ['High', 'Medium', 'Unknown'] else 'unknown'

                    html_content += """        <tr>
            <td>""" + vuln_type + """</td>
            <td class=""" + f'"{severity_class}"' + """>""" + severity + """</td>
            <td>""" + description + """</td>
            <td><div class="steps">""" + reproduce_steps + """</div></td>
            <td>""" + mitigation + """</td>
        </tr>
"""
                except Exception as e:
                    logger.error(f"Error processing vulnerability: {str(e)}")
                    continue

            html_content += """    </table>
</body>
</html>
"""

            with open('security_report.html', 'w', encoding='utf-8') as f:
                f.write(html_content)
            print("Report saved as security_report.html")
            logger.info("HTML report generated successfully")

        except Exception as e:
            error_msg = f"Failed to generate HTML report: {str(e)}\n{traceback.format_exc()}"
            logger.error(error_msg)
            print(f"[ERROR] {error_msg}")
            raise