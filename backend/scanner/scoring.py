def calculate_risk_score(dast_results: dict, passive_results: dict) -> int:
    """
    Calculates the overall risk score out of 100 based on scanning results.
    Weights:
    - Active SQLi: -35
    - Active XSS: -25
    - Missing Security Header: -5 each
    - Exposed sensitive path: -10 each
    """
    score = 100
    
    # Process DAST (Active) Results
    if dast_results.get("sqli", {}).get("vulnerable", False):
        score -= 35
        
    if dast_results.get("xss", {}).get("vulnerable", False):
        score -= 25
        
    # Process Passive Results
    headers = passive_results.get("security_headers", {}).get("headers", {})
    for header, data in headers.items():
        if not data.get("present", False):
            score -= 5
            
    exposed_paths = passive_results.get("exposed_paths", {})
    for path, data in exposed_paths.items():
        if data.get("exposed", False):
            score -= 10
            
    # Ensure score doesn't drop below 0
    return max(0, score)
