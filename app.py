from flask import Flask, render_template_string, request
from analyzer import (
    check_security_headers, 
    check_ssl_expiry, 
    check_exposed_paths, 
    check_sql_error,
    scan_common_ports, 
)

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Web Security Auditor</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f4f6f9; color: #333; }
        .container { max-width: 900px; margin: auto; background: white; padding: 25px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        input[type="text"] { width: 70%; padding: 10px; font-size: 16px; border: 1px solid #ccc; border-radius: 4px; }
        button { padding: 10px 20px; font-size: 16px; background-color: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
        
        .card { padding: 15px; margin-top: 15px; border-left: 5px solid; border-radius: 4px; background-color: #fafafa; }
        .tech-card { padding: 15px; margin-top: 15px; border-radius: 4px; background-color: #e9ecef; border-left: 5px solid #6c757d; }
        .grid { display: flex; gap: 20px; margin-top: 20px; }
        .col { flex: 1; }
        
        /* Dynamic Border Color Mappings */
        .PASS, .SAFE, .SECURE { border-left-color: #28a745; }
        .FAIL, .HIGH, .VULNERABLE { border-left-color: #dc3545; }
        .ERROR, .INFO { border-left-color: #17a2b8; }
        .LOW, .OPEN, .RESTRICTED { border-left-color: #ffc107; }
        
        /* Badges */
        .badge { display: inline-block; padding: 3px 7px; font-weight: bold; border-radius: 3px; color: white; font-size: 11px; text-transform: uppercase; }
        .badge-PASS, .badge-SAFE, .badge-SECURE { background-color: #28a745; }
        .badge-FAIL, .badge-HIGH, .badge-VULNERABLE { background-color: #dc3545; }
        .badge-EXPOSED { background-color: #fd7e14; }
        .badge-RESTRICTED { background-color: #ffc107; color: #333; }
        .badge-INFO { background-color: #17a2b8; }
        .badge-OPEN { background-color: #ffc107; color: #333; }
        .badge-CLOSED { background-color: #6c757d; }

        .tech-item { margin: 5px 0; font-size: 15px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Web Security Configuration & Vulnerability Auditor</h2>
        <p>Enter a target URL to check security parameters, open ports, and infrastructure components.</p>
        <form method="POST">
            <input type="text" name="target_url" placeholder="example.com" required>
            <button type="submit">Audit Site</button>
        </form>

        {% if headers_results %}
            <h3>Audit Results for: {{ url }}</h3>

            <div class="tech-card">
                <strong>Inferred Technology Fingerprints:</strong>
                <div style="margin-top: 10px;">
                    {% for tech in tech_stack %}
                        <div class="tech-item"> <strong>{{ tech.type }}:</strong> {{ tech.value }}</div>
                    {% endfor %}
                </div>
            </div>

            <div class="card {{ sql_results.severity }}">
                <strong>Database Query Analysis (SQLi Check):</strong> 
                <span class="badge badge-{{ sql_results.status }}">{{ sql_results.status }}</span>
                <p>{{ sql_results.details }}</p>
            </div>

            <div class="card {{ ssl_results.status }}">
                <strong>SSL/TLS Certificate Status:</strong> 
                <span class="badge badge-{{ ssl_results.status }}">{{ ssl_results.status }}</span>
                <p>{{ ssl_results.details }}</p>
            </div>

            <div class="grid">
                <div class="col">
                    <h3>Port Scan Auditing</h3>
                    {% for p in port_results %}
                        <div class="card {{ p.status }}">
                            <strong>Port {{ p.port }}</strong> ({{ p.service }})
                            <span class="badge badge-{{ p.status }}">{{ p.status }}</span>
                        </div>
                    {% endfor %}
                </div>

                <div class="col">
                    <h3>Exposed Path Reconnaissance</h3>
                    {% for path in path_results %}
                        <div class="card {{ path.severity }}">
                            <strong>Path: {{ path.path }}</strong> 
                            <span class="badge badge-{{ path.status }}">{{ path.status }}</span>
                            <p>{{ path.details }}</p>
                        </div>
                    {% endfor %}
                </div>
            </div>

            <h3>Security Header Metrics</h3>
            {% for result in headers_results %}
                <div class="card {{ result.status }}">
                    <strong>{{ result.header }}</strong>: 
                    <span class="badge badge-{{ result.status }}">{{ result.status }}</span>
                    <p>{{ result.details }}</p>
                </div>
            {% endfor %}
        {% endif %}
    </div>
</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def home():
    headers_results, ssl_results, tech_stack, path_results, port_results, sql_results = [None] * 6
    url = ""

    if request.method == "POST":
        url = request.form.get("target_url")
        
        # Execute scanning engine pipelines
        headers_results, tech_stack = check_security_headers(url)
        ssl_results = check_ssl_expiry(url)
        path_results = check_exposed_paths(url)
        port_results = scan_common_ports(url)
        sql_results = check_sql_error(url)

    return render_template_string(
        HTML_TEMPLATE, 
        headers_results=headers_results, 
        ssl_results=ssl_results,
        tech_stack=tech_stack,
        path_results=path_results, 
        port_results=port_results,
        sql_results=sql_results,
        url=url
    )

if __name__ == "__main__":
    app.run(debug=True, port=5000)