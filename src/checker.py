import requests
import os
import time
import base64
from dotenv import load_dotenv
from colorama import Fore, Style, init

# Initialize color output
init(autoreset=True)
load_dotenv()

class URLReputationChecker:
    def __init__(self):
        self.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.google_api_key = os.getenv("GOOGLE_SAFEBROWSING_API_KEY")
        self.urlscan_api_key = os.getenv("URLSCAN_API_KEY")
        
    def _virustotal_check(self, url):
        """Check URL reputation using VirusTotal v3 API"""
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            headers = {"x-apikey": self.virustotal_api_key}
            
            response = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                return {
                    "source": "VirusTotal",
                    "harmless": stats["harmless"],
                    "malicious": stats["malicious"],
                    "suspicious": stats["suspicious"],
                    "undetected": stats["undetected"]
                }
            return {"error": f"HTTP {response.status_code}: {response.text}"}
            
        except Exception as e:
            return {"error": str(e)}

    def _google_safebrowsing_check(self, url):
        """Check URL against Google Safe Browsing API"""
        try:
            endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
            payload = {
                "client": {
                    "clientId": "URLRepChecker",
                    "clientVersion": "1.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(
                f"{endpoint}?key={self.google_api_key}",
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "source": "Google Safe Browsing",
                    "matches": len(data.get("matches", [])),
                    "threats": [match["threatType"] for match in data.get("matches", [])]
                }
            return {"error": f"HTTP {response.status_code}: {response.text}"}
            
        except Exception as e:
            return {"error": str(e)}

    def _urlscan_check(self, url):
        """Analyze URL using URLScan.io API"""
        try:
            headers = {"API-Key": self.urlscan_api_key}
            submission = requests.post(
                "https://urlscan.io/api/v1/scan/",
                headers=headers,
                json={"url": url, "visibility": "public"},
                timeout=15
            )
            
            if submission.status_code != 200:
                try:
                    error_data = submission.json()
                    error_msg = error_data.get("message", "Submission failed")
                except:
                    error_msg = f"HTTP error {submission.status_code}"
                return {"error": error_msg}
            
            scan_id = submission.json()["uuid"]
            
            print(f"\n{Fore.YELLOW}⏳ Waiting for URLScan analysis (20-30 seconds)...")
            time.sleep(25)
            
            result = requests.get(
                f"https://urlscan.io/api/v1/result/{scan_id}/",
                headers=headers,
                timeout=15
            )
            
            if result.status_code == 200:
                data = result.json()
                return {
                    "source": "URLScan.io",
                    "malicious": data["verdicts"]["overall"]["malicious"],
                    "score": data["verdicts"]["overall"]["score"],
                    "ip": data["page"]["ip"],
                    "server": data["page"]["server"],
                    "country": data["page"]["country"]
                }
            else:
                try:
                    error_data = result.json()
                    error_msg = error_data.get("message", "Result fetch failed")
                except:
                    error_msg = f"HTTP error {result.status_code}"
                return {"error": error_msg}
            
        except Exception as e:
            return {"error": str(e)}

    def check_url(self, url):
        """Main function to check URL across all services"""
        results = {}
        
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
            
        print(f"\n{Fore.CYAN}=== Scanning URL: {url} ===")
        
        results["virustotal"] = self._virustotal_check(url)
        results["google"] = self._google_safebrowsing_check(url)
        results["urlscan"] = self._urlscan_check(url)
        
        self._display_results(results)
        
    def _display_results(self, results):
        """Format and display results to user"""
        vt = results["virustotal"]
        if "error" not in vt:
            print(f"\n{Fore.WHITE}=== VirusTotal Results ===")
            print(f"✅ Harmless: {vt['harmless']}\t⚠️ Malicious: {vt['malicious']}")
            print(f"🔍 Suspicious: {vt['suspicious']}\t❔ Undetected: {vt['undetected']}")
        else:
            print(f"{Fore.RED}VirusTotal Error: {vt['error']}")
            
        gsb = results["google"]
        if "error" not in gsb:
            print(f"\n{Fore.WHITE}=== Google Safe Browsing ===")
            if gsb["matches"] > 0:
                print(f"{Fore.RED}❌ Dangerous - Detected threats:")
                for threat in gsb["threats"]:
                    print(f" - {threat.replace('_', ' ').title()}")
            else:
                print(f"{Fore.GREEN}✅ No threats detected")
        else:
            print(f"{Fore.RED}Google Safe Browsing Error: {gsb['error']}")
            
        us = results["urlscan"]
        if "error" not in us:
            print(f"\n{Fore.WHITE}=== URLScan.io Analysis ===")
            status = f"{Fore.RED}Malicious" if us["malicious"] else f"{Fore.GREEN}Clean"
            print(f"Status: {status} (Score: {us['score']}/100)")
            print(f"🌍 Country: {us['country']}\t🖥️ Server: {us['server']}")
            print(f"📡 IP Address: {us['ip']}")
        else:
            print(f"\n{Fore.RED}URLScan.io could not provide data. Reason: {us['error']}")

if __name__ == "__main__":
    checker = URLReputationChecker()
    url = input(f"{Fore.CYAN}Enter URL to check: ").strip()
    checker.check_url(url)