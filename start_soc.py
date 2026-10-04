"""
NexusGuard - One-Click Dual Server Launcher (FastAPI Backend + Vite Frontend)
"""
import subprocess
import sys
import os
import time

def main():
    root_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir = os.path.join(root_dir, "backend")
    frontend_dir = os.path.join(root_dir, "frontend")

    print("=" * 60)
    print("🛡️  STARTING SENTINELSOC THREAT DETECTION PLATFORM")
    print("=" * 60)
    print("Backend URL:   http://127.0.0.1:8000 (API Docs: /docs)")
    print("Frontend URL:  http://127.0.0.1:3000")
    print("=" * 60)

    # 1. Launch FastAPI Backend
    print("[1/2] Starting FastAPI Backend on port 8000...")
    backend_cmd = [sys.executable, "-m", "uvicorn", "app.main:app", "--reload", "--port", "8000"]
    backend_proc = subprocess.Popen(backend_cmd, cwd=backend_dir)

    time.sleep(2)

    # 2. Launch Vite Frontend
    print("[2/2] Starting Vite React Frontend on port 3000...")
    # Use npm.cmd on Windows, npm on Unix
    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
    frontend_proc = subprocess.Popen([npm_cmd, "run", "dev"], cwd=frontend_dir)

    print("\n✓ NexusGuard is now LIVE and monitoring events!")
    print("Press Ctrl+C to terminate both servers.\n")

    try:
        backend_proc.wait()
        frontend_proc.wait()
    except KeyboardInterrupt:
        print("\nStopping NexusGuard services...")
        backend_proc.terminate()
        frontend_proc.terminate()
        print("Done.")

if __name__ == "__main__":
    main()
