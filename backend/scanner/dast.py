import requests
import time
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

def advanced_sqli_check(url: str) -> dict:
    """
    Performs a safe GET request fuzzing audit by appending a single quote.
    Checks for classic SQL syntax error strings and basic differential sleep.
    """
    if not url.startswith('http'):
        url = 'https://' + url
        
    results = {
        "vulnerable": False,
        "syntax_error_found": False,
        "timing_anomaly_detected": False,
        "error": None
    }
    
    # Classic SQLi error signatures
    sql_errors = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
        "pg_query(): query failed"
    ]
    
    try:
        # 1. Syntax Error Check
        parsed_url = urlparse(url)
        params = parse_qsl(parsed_url.query)
        
        # If no params, append a dummy one to test
        if not params:
            params = [("id", "1")]
            
        # Fuzz the first parameter
        fuzzed_params = params.copy()
        fuzzed_params[0] = (fuzzed_params[0][0], fuzzed_params[0][1] + "'")
        
        fuzzed_query = urlencode(fuzzed_params)
        fuzzed_url = urlunparse(parsed_url._replace(query=fuzzed_query))
        
        response = requests.get(fuzzed_url, timeout=5)
        response_text = response.text.lower()
        
        for error in sql_errors:
            if error in response_text:
                results["syntax_error_found"] = True
                results["vulnerable"] = True
                break
                
        # 2. Differential Sleep Check (Mock)
        # In a real scanner, we'd inject pg_sleep(), SLEEP(), WAITFOR DELAY
        # Here we just measure the baseline and a mock delayed request.
        start_baseline = time.time()
        requests.get(url, timeout=5)
        baseline_duration = time.time() - start_baseline
        
        # Mock timing payload (e.g., id=1 AND SLEEP(3))
        sleep_params = params.copy()
        sleep_params[0] = (sleep_params[0][0], sleep_params[0][1] + " AND SLEEP(3)")
        sleep_query = urlencode(sleep_params)
        sleep_url = urlunparse(parsed_url._replace(query=sleep_query))
        
        start_sleep = time.time()
        requests.get(sleep_url, timeout=10)
        sleep_duration = time.time() - start_sleep
        
        # If the sleep request took significantly longer than baseline + expected sleep
        if sleep_duration > (baseline_duration + 2.5):
            results["timing_anomaly_detected"] = True
            results["vulnerable"] = True

    except requests.RequestException as e:
        results["error"] = str(e)
        
    return results

def check_reflected_xss(url: str) -> dict:
    """Evaluates if an appended script tag payload is reflected raw in the response HTML."""
    if not url.startswith('http'):
        url = 'https://' + url
        
    results = {
        "vulnerable": False,
        "payload_reflected": False,
        "error": None
    }
    
    payload = "<script>alert('DAST_XSS_TEST')</script>"
    
    try:
        parsed_url = urlparse(url)
        params = parse_qsl(parsed_url.query)
        
        if not params:
            params = [("q", "test")]
            
        # Inject payload into first parameter
        fuzzed_params = params.copy()
        fuzzed_params[0] = (fuzzed_params[0][0], fuzzed_params[0][1] + payload)
        
        fuzzed_query = urlencode(fuzzed_params)
        fuzzed_url = urlunparse(parsed_url._replace(query=fuzzed_query))
        
        response = requests.get(fuzzed_url, timeout=5)
        
        # Check if the exact payload is reflected in the raw response
        if payload in response.text:
            # Basic validation to see if it's rendered as HTML (content-type check)
            content_type = response.headers.get("Content-Type", "")
            if "text/html" in content_type.lower():
                results["payload_reflected"] = True
                results["vulnerable"] = True
                
    except requests.RequestException as e:
        results["error"] = str(e)
        
    return results
