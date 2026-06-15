import socket
import ssl
import requests
from datetime import datetime


def scan_common_ports(domain):
    clean_domain = domain.replace("https://", "").replace("http://", "").split('/')[0]

    ports_to_scan = {
        21: "FTP (File Transfer)",
        22: "SSH (Secure Shell Control)",
        80: "HTTP (Web Server)",
        443: "HTTPS (Secure Web Server)",
        3306: "MySQL Database Server",
        8080: "Alternative Web Port"
    }

    port_results = []
    
    for port, service in ports_to_scan.items():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            result = s.connect_ex((clean_domain, port))

            if result == 0:
                port_results.append({
                    "port": port,
                    "service": service,
                    "status": "OPEN",
                    "severity": "HIGH" if port in [21, 22, 3306] else "INFO"
                })
            else:
                port_results.append({
                    "port": port,
                    "service": service,
                    "status": "CLOSED",
                    "severity": "SAFE"
                })
    return port_results

def check_sql_error(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    
    sql_errors = [
        "you have an error in your sql syntax",
        "unclosed quotation mark after the character string",
        "oracle error",
        "postgreSQL query failed",
        "dbo.odbc"
    ]
    if "?" in url:
        malicious_url = url + "'"
    else:
        malicious_url = url.rstrip('/') + "/?search='"

    try:
        response = requests.get(malicious_url, timeout=5)
        page_content = response.text.lower()

        for error in sql_errors:
            if error in page_content:
                return{
                    "status": "VULNERABLE",
                    "severity": "HIGH",
                    "details": f"Potential SQL Injection Found! The server leaked a raw database error: '{error}'."
                }
            return{
                "status": "SECURE",
                "severity": "SAGE",
                "details": "No common database syntax errors exposed when fuzzed."
            }
    except Exception as e:
        return{
            "status": "ERROR",
            "severity": "LOW",
            "details": f"Scan failed: {e}"
        }
    
def check_hsts_preload(domain):
    clean_domain = domain.replace("https://", "").replace("http://", "").split('/')[0]

    api_url = f"https;//hstspreload.org/api/v2/status?domain={clean_domain}"
    try:
        response = requests.get(api_url, timeout=5)
        if response.status_code == 200:
            data = response.json()

            if data.get("status") == "preloaded":
                return True
    except Exception:
        pass
    return False

def detect_technology(headers, url):
    detected_tech = []
    server = headers.get("Server")
    if server:
        detected_tech.append({"type": "Web Server", "value": server})
    
    powerer_by = headers.get("X-Powered-By")
    if powerer_by:
        detected_tech.append({"type": "Language/Framework", "value": powerer_by})

    set_cookie = headers.get("Set-Cookies", "").lower()
    if set_cookie:
        cookie_fingerprints = {
            "phpessid": ("Language", "PHP"),
            "wp-settings": ("CMS", "WordPress"),
            "csrftoken": ("Framework", "Django (Python)"),
            "aspsessionid": ("Framework", "ASP.NET"),
            "sails.sid": ("Framework", "Sails.js (Node.js)"),
            "laravel_session": ("Framework", "Laravel (PHP)")
        }
        for cookie_name, (tech_type, tech_name) in cookie_fingerprints.items():
            if cookie_name in set_cookie:
                detected_tech.append({"type": tech_type, "value": tech_name})
    
    clean_domain = url.replace("https//", "").replace("http://", "").split('/')[0]
    if "google.com" in clean_domain:
        detected_tech.append({"type": "Web Server", "value": "GWS (Google Web Server)"})
    
    if not detected_tech:
        detected_tech.append({"type": "Notice", "value": "No tech stack banners exposed (Good Security Practice!)"})
    
    return detected_tech

def check_security_headers(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        headers = response.headers

        important_headers = {
            "Content-Security-Policy": "Prevents Cross-Site Scripting (XSS) attacks.",
            "Strict-Transport-Security": "Forces connections over secure HTTPS.",
            "X-Frame-Options": "Prevents Clickjacking attacks by controlling if the site can be framed.",
            "X-Content-Type-Options": "Prevents the browser from guessing MIME types incorrectly."
        }

        results = []
        for header, description in important_headers.items():
            if header in headers:
                results.append({
                    "header": header,
                    "status": "PASS",
                    "details": f"Present. {description}" 
                })
            
            elif header == "Strict-Transport-Security" and check_hsts_preload(url):
                results.append({
                    "header": header,
                    "status": "PASS",
                    "details": "PASS (Preloaded)! Header missing, but domain is hardcoded into browsers via the HSTS Preload List."
                })
        
            else:
                results.append({
                    "header": header,
                    "status": "FAIL",
                    "details": f"Missing! {description}"
                })
        tech_stack = detect_technology(headers, url)

        return results, tech_stack
    except requests.exceptions.RequestException as e:
        return [{"header": "Connection Error", "status": "ERROR", "details": str(e)}], [{"type": "Error", "value": "Could not fetch tech stack due to connection failure."}]
    
def check_ssl_expiry(domain):
    clean_domain  =  domain.replace("https://", "").replace("http://", "").split('/')[0]

    context = ssl.create_default_context()
    try:
        with socket.create_connection((clean_domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=clean_domain) as sscock:
                cert = sscock.getpeercert()
                
                if not cert:
                    return {
                        "status": "ERROR",
                        "details": "SSL certificate could not be retrieved (empty certificate)."
                    }

                expire_date_str = cert.get('notAfter')
                if not isinstance(expire_date_str, str):
                    return {
                        "status": "ERROR",
                        "details": "SSL certificate 'notAfter' field is not a string."
                    }
                if not expire_date_str:
                    return {
                        "status": "ERROR",
                        "details": "SSL certificate is missing 'notAfter' field."
                    }

                # Typical format from ssl: 'Jun 13 12:00:00 2026 GMT'
                expire_date = None
                for fmt in ('%b %d %H:%M:%S %Y %Z', '%b %d %H:%M:%S %Y %Z '):
                    try:
                        expire_date = datetime.strptime(expire_date_str, fmt)
                        break
                    except ValueError:
                        continue

                if not expire_date:
                    return {
                        "status": "ERROR",
                        "details": f"Could not parse SSL certificate expiry date: {expire_date_str}"
                    }

                remaining_days = (expire_date - datetime.utcnow()).days

                if remaining_days > 0:
                    return {
                        "status": "PASS",
                        "details": f"SSL certificate is valid. It expires in {remaining_days} days in {expire_date.date()}."
                    }
                else:
                    return {
                        "status": "FAIL",
                        "details": "SSL certificate has expired!!"
                    }
    except Exception as e:
        return{
                        "status": "ERROR",
                        "details": f"Could not retrieve SSL Certificate: {e}"
                    }

def check_exposed_paths(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    
    base_url = url.rstrip('/')

    paths_to_check = {
        "/robot.txt": "Public crawler instructions. Check if it leaks sensitive admin or backup paths.",
        "/.git/": "CRITICAL RISK: Exposed Git Repository. Can allow complete source code theft.",
        "/.env": "CRITICAL RISK: Environment configuration file. Frequently leaks database credentials."
    }

    exposed_results = []

    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}

    for path, description in paths_to_check.items():
        target_path = base_url + path
        try:
            response = requests.head(target_path, headers=headers, timeout=4, allow_redirects=False)

            if response.status_code == 200:
                exposed_results.append({
                    "path": path,
                    "status": "EXPOSED",
                    "severity": "HIGH" if "txt" not in path else "INFO",
                    "details": f"Accessible! {description}"
                })
            elif response.status_code == 403:
                exposed_results.append({
                    "path": path,
                    "status": "RESTRICTED",
                    "severity": "LOW",
                    "details": "File detected, but access is correctly denied by the server configurations."
                })
            else:
                exposed_results.append({
                    "path": path,
                    "status": "SECURE",
                    "severity": "SAFE",
                    "details": "Not Found or Securely Hidden."
                })
        except Exception:
            pass
    return exposed_results