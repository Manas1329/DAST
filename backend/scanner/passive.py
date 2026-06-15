import requests
from urllib.parse import urljoin

def check_security_headers(url: str) -> dict:
    """
    Inspects HTTP response headers using the `requests` library. 
    Tracks CSP, HSTS, X-Frame-Options, and X-Content-Type-Options.
    """
    if not url.startswith('http'):
        url = 'https://' + url
        
    results = {
        "server": "Unknown",
        "headers": {
            "Content-Security-Policy": {"present": False, "mitigation": "add_header Content-Security-Policy \"default-src 'self';\";"},
            "Strict-Transport-Security": {"present": False, "mitigation": "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"},
            "X-Frame-Options": {"present": False, "mitigation": "add_header X-Frame-Options 'DENY';"},
            "X-Content-Type-Options": {"present": False, "mitigation": "add_header X-Content-Type-Options 'nosniff';"}
        },
        "error": None
    }
    
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        headers = response.headers
        
        results["server"] = headers.get("Server", "Unknown")
        
        for header in results["headers"]:
            if header.lower() in [h.lower() for h in headers.keys()]:
                results["headers"][header]["present"] = True
                results["headers"][header]["value"] = headers.get(header)
                
    except requests.RequestException as e:
        results["error"] = str(e)
        
    return results

def check_exposed_paths(url: str) -> dict:
    """Uses fast HTTP requests to check if common sensitive paths exist or are blocked."""
    if not url.startswith('http'):
        url = 'https://' + url
        
    paths_to_check = ['/robots.txt', '/.git/config', '/.env']
    results = {}
    
    for path in paths_to_check:
        target_url = urljoin(url, path)
        try:
            response = requests.get(target_url, timeout=3, allow_redirects=False)
            results[path] = {
                "status_code": response.status_code,
                "exposed": response.status_code == 200
            }
        except requests.RequestException:
            results[path] = {
                "status_code": 0,
                "exposed": False,
                "error": "Connection Failed"
            }
            
    return results
