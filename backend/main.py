import os
import time
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from backend.scanner.network import resolve_target_context, scan_common_ports, check_ssl_expiry
from backend.scanner.passive import check_security_headers, check_exposed_paths
from backend.scanner.dast import advanced_sqli_check, check_reflected_xss
from backend.scanner.scoring import calculate_risk_score

app = FastAPI(title="Enterprise Security Assessment Framework API")

class ScanRequest(BaseModel):
    url: str

@app.post("/api/v1/scan")
def run_scan(request: ScanRequest):
    target_url = request.url
    start_time = time.time()
    
    # 1. Network & Context
    context = resolve_target_context(target_url)
    domain = context.get("domain", "")
    
    ports = {}
    ssl_info = {}
    if domain:
        ports = scan_common_ports(domain)
        ssl_info = check_ssl_expiry(domain)
        
    # 2. Passive Checks
    headers = check_security_headers(target_url)
    paths = check_exposed_paths(target_url)
    
    # 3. Active DAST Checks
    sqli = advanced_sqli_check(target_url)
    xss = check_reflected_xss(target_url)
    
    end_time = time.time()
    scan_duration = int(end_time - start_time)
    
    # 4. Scoring
    passive_results = {
        "security_headers": headers,
        "exposed_paths": paths
    }
    dast_results = {
        "sqli": sqli,
        "xss": xss
    }
    
    score = calculate_risk_score(dast_results, passive_results)
    
    # Grade mapping
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"
        
    return {
        "metadata": {
            "target_url": target_url,
            "domain": domain,
            "ip_address": context.get("ip", ""),
            "scan_duration_seconds": scan_duration,
            "score": score,
            "grade": grade,
            "server_banner": headers.get("server", "Unknown")
        },
        "network": {
            "ports": ports,
            "ssl": ssl_info
        },
        "passive": passive_results,
        "dast": dast_results
    }

# Mount static files from parent directory to serve the frontend
frontend_path = os.path.join(os.path.dirname(__file__), "..")
app.mount("/assets", StaticFiles(directory=frontend_path), name="static")

@app.get("/")
def serve_index():
    return FileResponse(os.path.join(frontend_path, "index.html"))

@app.get("/{filename}")
def serve_root_files(filename: str):
    file_path = os.path.join(frontend_path, filename)
    if os.path.isfile(file_path):
        return FileResponse(file_path)
    return FileResponse(os.path.join(frontend_path, "index.html"))
