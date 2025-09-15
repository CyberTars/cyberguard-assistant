# app.py (Backend - Python Flask)
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests
import json
import re
from datetime import datetime, timedelta
import random
import nvdlib
import sqlite3
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)
CORS(app)

# Initialize scheduler for background tasks
scheduler = BackgroundScheduler()
scheduler.start()

# API configurations
VIRUSTOTAL_API_KEY = "c53becc13f932b68efb264e204ceae341f7eabcc007805cd17b9bc0d38884f37"  # Replace with your key
NVD_API_KEY = None  # Optional: Get from https://nvd.nist.gov/developers/request-an-api-key

# Known Exploited Vulnerabilities catalog (CISA KEV)
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Initialize SQLite database for CVE caching
def init_db():
    conn = sqlite3.connect('cve_cache.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS cves
                 (id TEXT PRIMARY KEY, severity TEXT, description TEXT, 
                  published_date TEXT, last_modified TEXT, kev_status INTEGER)''')
    conn.commit()
    conn.close()

# Call database initialization
init_db()

# Simulated database for demo purposes (fallback)
CVE_DATABASE = {
    "CVE-2024-3094": {
        "severity": "Critical (9.8/10)",
        "description": "Backdoor in XZ Utils discovered in versions 5.6.0 and 5.6.1. Allows remote code execution.",
        "recommendation": "Immediately downgrade to version 5.4.x or apply patches if available.",
        "kev_status": True
    },
    "CVE-2021-44228": {
        "severity": "Critical (10.0/10)",
        "description": "Log4Shell vulnerability in Apache Log4j allowing remote code execution.",
        "recommendation": "Update Log4j to version 2.17.1 or later.",
        "kev_status": True
    },
    "CVE-2021-34527": {
        "severity": "Critical (9.0/10)",
        "description": "Windows Print Spooler Remote Code Execution Vulnerability (PrintNightmare).",
        "recommendation": "Apply Windows updates for Print Spooler.",
        "kev_status": True
    },
    "CVE-2022-41082": {
        "severity": "High (8.8/10)",
        "description": "Microsoft Exchange Server Elevation of Privilege Vulnerability.",
        "recommendation": "Apply latest Exchange Server updates.",
        "kev_status": False
    }
}

LOG_DATA = [
    {"timestamp": "2024-05-01 08:23:45", "event": "Failed login", "user": "admin", "ip": "192.168.1.15"},
    {"timestamp": "2024-05-01 08:24:12", "event": "Failed login", "user": "admin", "ip": "192.168.1.15"},
    {"timestamp": "2024-05-01 08:24:45", "event": "Failed login", "user": "admin", "ip": "192.168.1.15"},
    {"timestamp": "2024-05-01 09:15:22", "event": "Successful login", "user": "jdoe", "ip": "10.0.0.42"},
    {"timestamp": "2024-05-01 10:32:11", "event": "Firewall rule modified", "user": "admin", "ip": "192.168.1.10"},
    {"timestamp": "2024-05-01 11:45:33", "event": "Failed login", "user": "root", "ip": "103.23.45.67"},
    {"timestamp": "2024-05-01 12:15:08", "event": "File uploaded", "user": "jdoe", "ip": "10.0.0.42"}
]

# Function to update CVE database from NVD
def update_cve_database():
    """Update CVE database from NVD API"""
    try:
        # Get recent CVEs (last 30 days)
        end_date = datetime.now()
        start_date = end_date - timedelta(days=30)
        
        # Format dates for NVD API
        start_str = start_date.strftime("%Y-%m-%dT%H:%M:%S:000 UTC-00:00")
        end_str = end_date.strftime("%Y-%m-%dT%H:%M:%S:000 UTC-00:00")
        
        # Fetch CVEs from NVD
        r = nvdlib.searchCVE(pubStartDate=start_str, pubEndDate=end_str)
        
        # Connect to database
        conn = sqlite3.connect('cve_cache.db')
        c = conn.cursor()
        
        # Process and store CVEs
        for cve in r:
            # Check if CVE is in KEV catalog
            kev_status = check_kev_catalog(cve.id)
            
            # Insert or replace CVE in database
            c.execute('''INSERT OR REPLACE INTO cves 
                         (id, severity, description, published_date, last_modified, kev_status)
                         VALUES (?, ?, ?, ?, ?, ?)''',
                     (cve.id, str(cve.score[1]) if cve.score else "Unknown", 
                      cve.descriptions[0].value if cve.descriptions else "No description available",
                      cve.published, cve.lastModified, 1 if kev_status else 0))
        
        conn.commit()
        conn.close()
        print("CVE database updated successfully")
    except Exception as e:
        print(f"Error updating CVE database: {str(e)}")

# Function to check if CVE is in KEV catalog
def check_kev_catalog(cve_id):
    """Check if a CVE is in CISA's Known Exploited Vulnerabilities catalog"""
    try:
        response = requests.get(CISA_KEV_URL, timeout=10)
        if response.status_code == 200:
            kev_data = response.json()
            vulnerabilities = kev_data.get('vulnerabilities', [])
            for vuln in vulnerabilities:
                if vuln.get('cveID') == cve_id:
                    return True
        return False
    except Exception as e:
        print(f"Error checking KEV catalog: {str(e)}")
        return False

# Schedule daily updates
scheduler.add_job(update_cve_database, 'interval', hours=24)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/chat', methods=['POST'])
def chat():
    user_message = request.json.get('message', '')
    response = process_message(user_message)
    return jsonify({'response': response})

def process_message(message):
    message = message.lower().strip()
    
    # CVE lookup
    if message.startswith('check cve-'):
        cve_id = extract_cve_id(message)
        if cve_id:
            return process_cve_query(cve_id)
        else:
            return "⚠️ Please provide a valid CVE ID (e.g., CVE-2024-3094)"
    
    # Product vulnerability search
    elif message.startswith('check vulnerabilities for '):
        product = message.replace('check vulnerabilities for ', '').strip()
        return search_vulnerabilities_by_product(product)
    
    # Threat analysis with VirusTotal (requires API key)
    elif 'analyze' in message and 'hash' in message:
        file_hash = extract_hash(message)
        if file_hash:
            return analyze_file_hash(file_hash)
        else:
            return "⚠️ Please provide a valid file hash for analysis."
    
    # Log summary
    elif 'login' in message and 'anomal' in message:
        return generate_login_anomalies_report()
    
    # Block IPs countermeasure
    elif message.startswith('block ip'):
        ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', message)
        if ip_match:
            ip = ip_match.group()
            return f"✅ Command executed: Blocked IP {ip} in firewall. [SIMULATION]"
        else:
            return "⚠️ Please specify a valid IP address to block."
    
    # Default response
    else:
        return "🤖 I can help with: 1) CVE lookup (e.g., 'Check CVE-2024-3094') 2) Product vulnerability search (e.g., 'Check vulnerabilities for Apache') 3) Threat analysis (e.g., 'Analyze hash abc123') 4) Log summaries (e.g., 'Show login anomalies')"

def process_cve_query(cve_id):
    """Process CVE query with multiple data sources"""
    try:
        # First try to get from NVD API
        try:
            results = nvdlib.searchCVE(cveId=cve_id)
            if results:
                cve_data = results[0]
                kev_status = check_kev_catalog(cve_id)
                
                response = f"""
🔎 {cve_id}
Severity: {cve_data.score[1] if cve_data.score else "Unknown"} ({cve_data.score[0] if cve_data.score else "N/A"})
Published: {cve_data.published}
Description: {cve_data.descriptions[0].value if cve_data.descriptions else "No description available"}
"""
                if kev_status:
                    response += "🚨 This vulnerability is in CISA's Known Exploited Vulnerabilities catalog\n"
                
                # Add recommendation based on severity
                if cve_data.score and cve_data.score[0] >= 7.0:
                    response += "🔴 Recommendation: Patch immediately - this is a high severity vulnerability\n"
                elif cve_data.score and cve_data.score[0] >= 4.0:
                    response += "🟡 Recommendation: Plan to patch soon - medium severity vulnerability\n"
                
                return response
        except Exception as e:
            print(f"NVD API error: {str(e)}")
        
        # Fallback to local database
        if cve_id in CVE_DATABASE:
            cve_data = CVE_DATABASE[cve_id]
            kev_status = "🚨 Known Exploited Vulnerability" if cve_data.get('kev_status') else ""
            return f"🔎 {cve_id}\nSeverity: {cve_data['severity']}\nDescription: {cve_data['description']}\nRecommendation: {cve_data['recommendation']}\n{kev_status}"
        
        # Final fallback
        return f"ℹ️ CVE {cve_id} not found in database. It might be a new vulnerability or you may need to check official sources."
    
    except Exception as e:
        return f"⚠️ Error processing CVE query: {str(e)}"

def search_vulnerabilities_by_product(product_name):
    """Search for vulnerabilities by product name"""
    try:
        results = nvdlib.searchCVE(keywordSearch=product_name, keywordExactMatch=False)
        
        if not results:
            return f"ℹ️ No vulnerabilities found for {product_name}"
        
        response = f"🔍 Found {len(results)} vulnerabilities for {product_name}:\n\n"
        
        # Show top 5 most severe vulnerabilities
        sorted_results = sorted(results, key=lambda x: x.score[0] if x.score else 0, reverse=True)
        
        for i, cve in enumerate(sorted_results[:5]):
            response += f"{i+1}. {cve.id} - {cve.score[1] if cve.score else 'Unknown'} ({cve.score[0] if cve.score else 'N/A'})\n"
        
        response += "\nUse 'Check CVE-XXXX-XXXX' for details on a specific vulnerability."
        return response
    
    except Exception as e:
        return f"⚠️ Error searching for product vulnerabilities: {str(e)}"

def analyze_file_hash(file_hash):
    """Analyze file hash using VirusTotal"""
    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            stats = result['data']['attributes']['last_analysis_stats']
            return f"🔍 Analysis for hash {file_hash}:\nMalicious: {stats['malicious']} | Suspicious: {stats['suspicious']}\nUndetected: {stats['undetected']} | Harmless: {stats['harmless']}"
        else:
            return f"❌ Could not analyze hash {file_hash}. Error: {response.status_code}"
    except Exception as e:
        return f"⚠️ API error: {str(e)}. Using simulated response. Hash {file_hash} shows 5/70 engines detected as malicious."

def generate_login_anomalies_report():
    """Generate login anomalies report"""
    failed_logins = [log for log in LOG_DATA if log['event'] == 'Failed login']
    summary = f"📊 Today's login anomalies: {len(failed_logins)} failed login attempts.\n"
    
    for i, log in enumerate(failed_logins[:3]):  # Show top 3
        summary += f"{i+1}. {log['timestamp']} - {log['user']} from {log['ip']}\n"
    
    if len(failed_logins) > 3:
        summary += f"... and {len(failed_logins) - 3} more attempts."
    
    # Add a simple countermeasure option
    suspicious_ips = set(log['ip'] for log in failed_logins if log['ip'].startswith('103.'))
    if suspicious_ips:
        summary += f"\n🚨 Recommendation: Block suspicious IPs: {', '.join(suspicious_ips)} [BLOCK_IPS]"
    
    return summary

def extract_cve_id(text):
    match = re.search(r'cve-\d{4}-\d+', text, re.IGNORECASE)
    return match.group().upper() if match else None

def extract_hash(text):
    # Look for MD5, SHA-1, or SHA-256 hashes
    patterns = [
        r'\b[a-fA-F0-9]{32}\b',  # MD5
        r'\b[a-fA-F0-9]{40}\b',  # SHA-1
        r'\b[a-fA-F0-9]{64}\b'   # SHA-256
    ]
    
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group()
    return None

if __name__ == '__main__':
    # Perform initial CVE database update
    update_cve_database()
    app.run(debug=True)