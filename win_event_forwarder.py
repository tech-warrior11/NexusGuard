import subprocess
import time
import httpx
import sys

API_URL = "https://nexusguard-771b.onrender.com/api/v1/logs/raw"

def get_latest_security_events():
    # PowerShell command to fetch recent Security event logs
    ps_command = (
        "Get-WinEvent -LogName Security -MaxEvents 5 | "
        "Select-Object Id, Message | "
        "ForEach-Object { 'Event ID: ' + $_.Id + ' - ' + $_.Message }"
    )
    
    try:
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            capture_output=True,
            text=True
        )
        
        if "UnauthorizedAccess" in result.stderr:
            print("[-] ERROR: Windows blocks access to 'Security' logs for normal users.")
            print("[-] ACTION REQUIRED: Please open your Terminal or Command Prompt as Administrator and run this script again.")
            time.sleep(10)
            return []
            
        if result.returncode == 0 and result.stdout.strip():
            # Split by Event ID: which denotes a new event (since Message can contain newlines)
            events = result.stdout.split("Event ID: ")
            parsed_events = []
            for ev in events:
                if ev.strip():
                    parsed_events.append("Event ID: " + ev.strip())
            return parsed_events
    except Exception as e:
        print(f"Error fetching logs: {e}")
    return []

def authenticate():
    try:
        import os, getpass
        username = os.environ.get("SOC_USERNAME") or input("Enter SOC Username: ")
        password = os.environ.get("SOC_PASSWORD") or getpass.getpass("Enter SOC Password: ")
        auth_url = API_URL.replace("/logs/raw", "/auth/login")
        response = httpx.post(auth_url, data={"username": username, "password": password}, timeout=5.0)
        if response.status_code == 200:
            return response.json().get("access_token")
        else:
            print(f"[-] Auth failed: {response.status_code}")
            return None
    except Exception as e:
        print(f"[-] Auth error: {e}")
        return None

def forward_log(log_content, token):
    payload = {
        "format": "windows_event",
        "content": log_content
    }
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = httpx.post(API_URL, json=payload, headers=headers, timeout=2.0)
        if response.status_code == 201:
            print("[+] Successfully forwarded real Windows Event Log to SIEM.")
        else:
            print(f"[-] Failed to forward: {response.status_code}")
    except Exception as e:
        print(f"[-] Connection error: {e}")

if __name__ == "__main__":
    print("=====================================================")
    print("🛡️ NexusGuard - Live Windows Event Log Forwarder")
    print("=====================================================")
    print(f"Target SIEM API: {API_URL}")
    print("Authenticating with SOC Backend...")
    
    token = None
    while not token:
        token = authenticate()
        if not token:
            print("Retrying authentication in 5s...")
            time.sleep(5)
            
    print("Authentication successful! Monitoring local Windows Security Events in real-time...\n")
    
    seen_events = set()
    
    while True:
        events = get_latest_security_events()
        for ev in reversed(events): # Forward oldest first
            if ev not in seen_events:
                forward_log(ev, token)
                seen_events.add(ev)
                
        # Keep seen_events set from growing indefinitely
        if len(seen_events) > 100:
            seen_events.clear()
            
        time.sleep(3)
