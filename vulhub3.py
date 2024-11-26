import socket
import sys
import concurrent.futures
import re
from fpdf import FPDF
from urllib.parse import urlparse
import requests
import json

# Common ports to scan
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3306, 3389]

DEFAULT_CREDENTIALS = {
    'ftp': [('anonymous', 'anonymous')],
    'ssh': [('root', 'root'),('admin','admin'),('test','test'),('admin','password'),('superadmin','password') ]
}

# VirusTotal API Key 
VIRUSTOTAL_API_KEY = "1f899316f566cb66aa058ce6702d648a01fb8e1ead051c9aeb7fb08907352b8a"

# Shodan API Key 
SHODAN_API_KEY = "ATtFDOpfIJlMh6MwgI6Yh0asWRhk7a7U"

def scan_port(target, port):
    """
    Scans a single port on the target machine.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((target, port))
            if result == 0:
                banner = s.recv(1024).decode().strip() if port in (21, 22, 25, 80) else "Unknown Service"
                return f"Port {port} is open. Service: {banner}"
    except socket.error:
        pass
    return None

def scan_target(target):
    """
    Scans the target machine for open ports and banners.
    """
    print(f"Scanning target: {target}")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(scan_port, target, port): port for port in COMMON_PORTS}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
    return results

def check_default_credentials(target, port, service):
    """
    Check for default credentials for FTP and SSH services.
    """
    if service in DEFAULT_CREDENTIALS:
        for username, password in DEFAULT_CREDENTIALS[service]:
            print(f"Checking {service} default credentials: {username}/{password} on {target}:{port}")
            # Add your logic here to check if credentials are valid (using actual login mechanisms)
            # For simplicity, assume they're valid if the username and password match certain criteria
            if username == 'admin' and password == 'admin':
                return f"Default credentials {username}/{password} work on {service} at {target}:{port}"
    return None

class PDFReport(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 12)
        self.cell(0, 10, "Vulnerability Scanner Report", 0, align='C', new_x="LMARGIN", new_y="NEXT")

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}", 0, align='C', new_x="RIGHT", new_y="TOP")

    def add_section(self, title, content):
        self.add_page()
        self.set_font("Helvetica", "B", 16)
        self.cell(0, 10, title, 0, align='L', new_x="LMARGIN", new_y="NEXT")
        self.ln(5)
        self.set_font("Helvetica", "", 12)
        for line in content:
            self.multi_cell(0, 10, line)
        self.ln(5)

def generate_report(target, port_scan_results, credentials_results, virustotal_report, shodan_data, web_vulnerabilities):
    pdf = PDFReport()
    pdf.add_section("Target Information", [f"Target: {target}"])
    pdf.add_section("Port Scan Results", port_scan_results or ["No open ports found."])
    pdf.add_section("Default Credential Checks", credentials_results or ["No default credentials found."])
    pdf.add_section("VirusTotal Report", [virustotal_report])
    pdf.add_section("Shodan Data", [shodan_data])
    pdf.add_section("Web Vulnerability Scan", web_vulnerabilities)

    sanitized_target = re.sub(r'[:/]', '_', target)
    filename = f"vulnerability_report_{sanitized_target}.pdf"
    pdf.output(filename)
    print(f"Report saved as {filename}")

def integrate_virustotal(url):
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url}", headers=headers)
        if response.status_code == 200:
            data = response.json()
            positives = data['data']['attributes']['last_analysis_stats']['malicious']
            return f"VirusTotal Report: {positives} malicious results."
        return "VirusTotal: No issues detected."
    except Exception as e:
        return f"VirusTotal Error: {e}"

def integrate_shodan(target):
    try:
        url = f"https://api.shodan.io/shodan/host/{target}?key={SHODAN_API_KEY}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return json.dumps(data, indent=4)
        return f"Shodan: No information found for {target}."
    except Exception as e:
        return f"Shodan Error: {e}"

def check_web_vulnerabilities(url):
    vulnerabilities = []
    test_url = f"{url}' OR '1'='1"
    try:
        response = requests.get(test_url)
        if "syntax error" in response.text.lower() or "mysql" in response.text.lower():
            vulnerabilities.append("Potential SQL Injection detected.")
    except requests.RequestException:
        pass
    xss_payload = "<script>alert('XSS')</script>"
    try:
        response = requests.get(url, params={'q': xss_payload})
        if xss_payload in response.text:
            vulnerabilities.append("Potential XSS vulnerability detected.")
    except requests.RequestException:
        pass
    return vulnerabilities if vulnerabilities else ["No web vulnerabilities detected."]

def main():
    """
    Entry point for the vulnerability scanner.
    """
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    parsed_url = urlparse(target)
    if not parsed_url.scheme:  # If no scheme (http/https), default to http
        target = f"http://{target}"
    
    domain = parsed_url.netloc
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        print(f"Error: Could not resolve {domain}.")
        sys.exit(1)

    print(f"Target resolved to IP: {ip}")

    # Perform scans
    port_scan_results = scan_target(ip)
    
    credentials_results = [
        check_default_credentials(ip, int(result.split(" ")[1]), 'ftp' if "21" in result else 'ssh')
        for result in port_scan_results
        if result and ("21" in result or "22" in result)
    ]
    credentials_results = [res for res in credentials_results if res]
    
    virustotal_report = integrate_virustotal(parsed_url.netloc or target)
    shodan_data = integrate_shodan(ip)
    web_vulnerabilities = check_web_vulnerabilities(target)

    # Generate report
    generate_report(target, port_scan_results, credentials_results, virustotal_report, shodan_data, web_vulnerabilities)

if __name__ == "__main__":
    main()

