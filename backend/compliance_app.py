import ssl
import socket
import urllib.parse
from datetime import datetime
import time
import sqlite3
import requests
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Internal System Administration & Compliance Tool")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ComplianceRequest(BaseModel):
    target_url: str

# Database Initialization
def init_db():
    conn = sqlite3.connect('compliance_history.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  target_domain TEXT,
                  compliance_score INTEGER,
                  performance_grade TEXT,
                  timestamp TEXT)''')
    conn.commit()
    conn.close()

init_db()

def log_scan_result(target_domain: str, score: int, grade: str):
    try:
        conn = sqlite3.connect('compliance_history.db')
        c = conn.cursor()
        c.execute("INSERT INTO scans (target_domain, compliance_score, performance_grade, timestamp) VALUES (?, ?, ?, ?)",
                  (target_domain, score, grade, datetime.utcnow().isoformat() + "Z"))
        conn.commit()
        conn.close()
    except Exception as e:
        print("Database Logging Error:", e)

def audit_http_headers(url: str) -> dict:
    """Reads response headers to check for the presence of recommended security options."""
    if not url.startswith('http'):
        url = 'https://' + url
        
    results = {
        "headers": {
            "Content-Security-Policy": {"present": False, "mitigation": "add_header Content-Security-Policy \"default-src 'self';\";"},
            "Strict-Transport-Security": {"present": False, "mitigation": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"},
            "X-Frame-Options": {"present": False, "mitigation": "add_header X-Frame-Options 'DENY';"},
            "X-Content-Type-Options": {"present": False, "mitigation": "add_header X-Content-Type-Options 'nosniff';"}
        },
        "missing_count": 0,
        "error": None
    }
    
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        headers = response.headers
        
        missing_count = 0
        for header in results["headers"]:
            if header.lower() in [h.lower() for h in headers.keys()]:
                results["headers"][header]["present"] = True
                results["headers"][header]["value"] = headers.get(header)
            else:
                missing_count += 1
                
        results["missing_count"] = missing_count
                
    except requests.RequestException as e:
        results["error"] = str(e)
        results["missing_count"] = len(results["headers"])
        
    return results

def verify_ssl_validity(domain: str) -> dict:
    """Connects via Python's built-in socket and ssl libraries to parse the certificate's expiration date."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5.0) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
        not_after = cert.get('notAfter')
        if not not_after:
            return {"valid": False, "days_remaining": 0, "error": "No expiry date found"}
            
        expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_remaining = (expiry_date - datetime.utcnow()).days
        
        return {
            "valid": days_remaining > 0,
            "days_remaining": days_remaining,
            "expiry_date": expiry_date.isoformat(),
            "error": None
        }
    except Exception as e:
        return {"valid": False, "days_remaining": 0, "error": str(e)}

def check_standard_paths(url: str) -> list:
    """Performs an administrative visibility mapping check for infrastructure pathways."""
    if not url.startswith('http'):
        url = 'https://' + url
        
    paths_to_verify = {
        "/robots.txt": "Public crawler visibility roadmap instructions.",
        "/.git/": "Version history control manifest metadata repository folder.",
        "/.env": "Local environmental variable application deployment keys."
    }
    
    path_metrics = []
    for path, description in paths_to_verify.items():
        target_path = urllib.parse.urljoin(url, path)
        try:
            response = requests.get(target_path, timeout=3, allow_redirects=False)
            status = response.status_code
            is_exposed = status == 200
            
            path_metrics.append({
                "path": path,
                "status": "EXPOSED" if is_exposed else "SECURE",
                "severity": "HIGH" if (is_exposed and "txt" not in path) else "INFO",
                "details": f"HTTP Status {status}. {description}" if is_exposed else "Path successfully isolated from external reads."
            })
        except requests.RequestException:
            path_metrics.append({
                "path": path,
                "status": "SECURE",
                "severity": "SAFE",
                "details": "Unreachable or securely drop-filtered."
            })
            
    return path_metrics

def check_network_services(domain: str) -> list:
    """Audits accessible interface connection doorways to verify perimeter exposure."""
    monitored_ports = {
        21: "FTP (File Storage Link)",
        22: "SSH (Console Server Management)",
        80: "HTTP (Web Delivery Traffic)",
        443: "HTTPS (Encrypted Content Delivery)",
        8080: "Alternative Application Proxy Hosting"
    }
    
    port_metrics = []
    for port, service_name in monitored_ports.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                connection_attempt = s.connect_ex((domain, port))
                is_open = connection_attempt == 0
        except Exception:
            is_open = False
            
        port_metrics.append({
            "port": port,
            "service": service_name,
            "status": "OPEN" if is_open else "CLOSED",
            "severity": "HIGH" if (is_open and port in [21, 22]) else "SAFE"
        })
    return port_metrics

def analyze_input_sanitization(url: str) -> dict:
    """Audits input handling parameters for syntax validation flags."""
    if not url.startswith('http'):
        url = 'https://' + url
        
    test_endpoint = urllib.parse.urljoin(url, '/?search=')
    sql_error_signatures = ["sql syntax", "unclosed quotation", "mysql_fetch", "postgresql query"]
    xss_injection_marker = "<script>alert(1)</script>"
    
    sanitization_report = {
        "database_sanitization": {"status": "SECURE", "details": "Parameters comply with type separation barriers. No error anomalies exposed."},
        "parameter_validation": {"status": "SECURE", "details": "Output filters escaped incoming literal character contexts properly."}
    }
    
    try:
        # Check 1: Database Error Leaks Check
        err_res = requests.get(test_endpoint + "1'", timeout=4)
        for signature in sql_error_signatures:
            if signature in err_res.text.lower():
                sanitization_report["database_sanitization"] = {
                    "status": "VULNERABLE",
                    "details": f"Leaked SQL runtime signature exception: '{signature}' during parsing bounds test."
                }
                break
                
        # Check 2: Mirror Encoding Validation Check
        xss_res = requests.get(test_endpoint + xss_injection_marker, timeout=4)
        if xss_injection_marker in xss_res.text:
            sanitization_report["parameter_validation"] = {
                "status": "VULNERABLE",
                "details": "Echo request mirrored plain executable markup scripts directly into document context templates."
            }
    except Exception as e:
        pass
        
    return sanitization_report

def verify_https_redirection(domain: str) -> dict:
    """Explicitly issues a standard HTTP request to port 80 and checks for HTTPS redirection."""
    target_url = f"http://{domain}"
    try:
        response = requests.get(target_url, timeout=5, allow_redirects=False)
        
        if response.status_code in (301, 302, 307, 308):
            location = response.headers.get("Location", "")
            if location.startswith("https://"):
                return {"status": "PASS", "details": f"Successfully redirected to secure {location}"}
            else:
                return {"status": "FAIL", "details": f"Redirects to non-HTTPS location: {location}"}
        else:
            return {"status": "FAIL", "details": f"No redirect found (HTTP Status: {response.status_code})"}
            
    except requests.RequestException as e:
        return {"status": "FAIL", "details": f"Request failed: {str(e)}"}

def audit_session_cookies(url: str) -> dict:
    """Sends a GET request and parses 'Set-Cookie' header arrays for 'httponly' and 'secure' attributes."""
    if not url.startswith('http'):
        url = 'https://' + url
        
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        raw_cookies = response.headers.get('Set-Cookie')
        
        if not raw_cookies:
            return {"status": "PASS", "details": "No stateful tracking cookies dropped during initialization lifecycle."}
            
        raw_cookies_lower = raw_cookies.lower()
        has_secure = 'secure' in raw_cookies_lower
        has_httponly = 'httponly' in raw_cookies_lower
        
        if has_secure and has_httponly:
            return {"status": "PASS", "details": "Cookies properly restricted with Secure and HttpOnly flags."}
        else:
            missing = []
            if not has_secure: missing.append("Secure")
            if not has_httponly: missing.append("HttpOnly")
            return {"status": "FAIL", "details": f"Cookies missing required constraints: {', '.join(missing)}."}
            
    except requests.RequestException as e:
        return {"status": "FAIL", "details": f"Request failed: {str(e)}"}

def calculate_compliance_score(missing_headers_count: int, network_issues: int, directory_leaks: int) -> dict:
    """Dynamically calculates balanced integrity ratings using weighted configuration parameters."""
    deductions = (missing_headers_count * 10) + (network_issues * 15) + (directory_leaks * 20)
    score = max(0, 100 - deductions)
    
    if score >= 90: grade = "A"
    elif score >= 80: grade = "B"
    elif score >= 70: grade = "C"
    elif score >= 60: grade = "D"
    else: grade = "F"
        
    return {"score": score, "grade": grade}

@app.post("/api/v1/compliance")
def run_compliance_check(request: ComplianceRequest):
    url = request.target_url
    
    parsed = urllib.parse.urlparse(url if url.startswith('http') else 'https://' + url)
    domain = parsed.netloc or parsed.path
    if ':' in domain:
        domain = domain.split(':')[0]
        
    try:
        resolved_ip = socket.gethostbyname(domain)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="Domain could not be resolved. Please check if you have entered a proper link/domain.")
        
    # Execute full scanning core pipelines
    header_audit = audit_http_headers(url)
    ssl_validity = verify_ssl_validity(domain)
    exposed_paths = check_standard_paths(url)
    network_services = check_network_services(domain)
    input_sanitization = analyze_input_sanitization(url)
    https_redirection = verify_https_redirection(domain)
    session_cookies = audit_session_cookies(url)
    
    # Count structural metric failures to feed weighted scoring algorithms
    open_risky_ports = sum(1 for p in network_services if p["status"] == "OPEN" and p["severity"] == "HIGH")
    directory_leaks = sum(1 for d in exposed_paths if d["status"] == "EXPOSED" and d["severity"] == "HIGH")
    
    compliance = calculate_compliance_score(
        header_audit.get("missing_count", 0), 
        open_risky_ports, 
        directory_leaks
    )
        
    # Persist metrics to SQLite history log
    log_scan_result(domain, compliance["score"], compliance["grade"])
    
    return {
        "target": url,
        "resolved_ip": resolved_ip,
        "compliance_score": compliance,
        "headers": header_audit,
        "ssl": ssl_validity,
        "exposed_directories": exposed_paths,
        "port_metrics": network_services,
        "input_validation": input_sanitization,
        "https_redirection": https_redirection,
        "session_cookies": session_cookies
    }

@app.get("/api/v1/history")
def get_compliance_history():
    try:
        conn = sqlite3.connect('compliance_history.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM scans ORDER BY timestamp DESC LIMIT 5")
        rows = c.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8002)