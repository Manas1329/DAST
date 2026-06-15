import socket
import ssl
import urllib.parse
from datetime import datetime

def resolve_target_context(url: str) -> dict:
    """Resolves a domain string to its IP address safely."""
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc or parsed.path
        if ':' in domain:
            domain = domain.split(':')[0]
            
        if not domain:
            return {"domain": "", "ip": "", "error": "Invalid URL provided"}

        ip = socket.gethostbyname(domain)
        return {"domain": domain, "ip": ip, "error": None}
    except socket.gaierror:
        return {"domain": domain, "ip": "", "error": "DNS Resolution failed"}
    except Exception as e:
        return {"domain": "", "ip": "", "error": str(e)}

def scan_common_ports(domain: str) -> dict:
    """Attempts fast 1-second TCP connections to ports 21, 22, 80, 443, and 8080."""
    target_ports = [21, 22, 80, 443, 8080]
    results = {}
    
    for port in target_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)
                result = s.connect_ex((domain, port))
                if result == 0:
                    results[str(port)] = "OPEN"
                else:
                    results[str(port)] = "CLOSED"
        except Exception:
            results[str(port)] = "ERROR"
            
    return results

def check_ssl_expiry(domain: str) -> dict:
    """Connects via SSL context to fetch certificate validity and calculate days remaining."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3.0) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
        not_after = cert.get('notAfter')
        if not not_after:
            return {"valid": False, "days_remaining": 0, "error": "No expiry date found"}
            
        # Parse date format like "Oct 14 12:00:00 2026 GMT"
        expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_remaining = (expiry_date - datetime.utcnow()).days
        
        return {
            "valid": days_remaining > 0,
            "days_remaining": days_remaining,
            "expiry_date": expiry_date.isoformat(),
            "error": None
        }
    except ssl.SSLError as e:
        return {"valid": False, "days_remaining": 0, "error": f"SSL Error: {str(e)}"}
    except (socket.timeout, socket.gaierror, ConnectionRefusedError):
        return {"valid": False, "days_remaining": 0, "error": "Connection failed on port 443"}
    except Exception as e:
        return {"valid": False, "days_remaining": 0, "error": str(e)}
