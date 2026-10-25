"""
Component A: Vulnerable Target Backend (target_app.py)
Simulates an internal microservice with intentional path traversal vulnerabilities.
"""

import os
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import PlainTextResponse
from rich.console import Console

console = Console()
app = FastAPI(title="Vulnerable Target App", version="1.0.0")

# Setup mock storage directory and system files
STORAGE_DIR = os.path.abspath("./mock_storage")
os.makedirs(os.path.join(STORAGE_DIR, "reports"), exist_ok=True)

# Create sample legitimate file
with open(os.path.join(STORAGE_DIR, "reports", "summary.pdf"), "w") as f:
    f.write("CONFIDENTIAL: Annual Financial Summary 2026. All rights reserved.")

# Create mock sensitive system file
SYSTEM_PASSWD_PATH = os.path.abspath("./mock_passwd.txt")
with open(SYSTEM_PASSWD_PATH, "w") as f:
    f.write("root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Admin User,,,:/home/admin:/bin/bash")


@app.get("/")
def read_root():
    return {"status": "Target Backend Online", "mode": "Vulnerable"}


@app.get("/api/v1/download")
def download_file(file: str = Query(..., description="Target file path relative or raw")):
    """
    VULNERABLE ENDPOINT: Unvalidated 'file' parameter allows path traversal sequences.
    """
    console.print(f"[yellow][TARGET] Received download request for parameter: '{file}'[/yellow]")
    
    target_path = os.path.join(STORAGE_DIR, file)
    
    try:
        # Check if request targets system file via path traversal
        if "passwd" in file or "../" in file or "..%2f" in file or "%2e%2e" in file:
            if os.path.exists(SYSTEM_PASSWD_PATH):
                with open(SYSTEM_PASSWD_PATH, "r") as sf:
                    content = sf.read()
                console.print("[bold red][TARGET VULNERABILITY EXPLOITED] Sensitive system file accessed![/bold red]")
                return PlainTextResponse(content, status_code=200)

        with open(target_path, "r") as target_file:
            content = target_file.read()
        return PlainTextResponse(content, status_code=200)
        
    except Exception as e:
        console.print(f"[red][TARGET ERROR] Access failed or file not found: {e}[/red]")
        raise HTTPException(status_code=404, detail="File not found or access denied by system policy.")


if __name__ == "__main__":
    import uvicorn
    console.print("[bold green]Starting Vulnerable Target Backend on http://127.0.0.1:8001[/bold green]")
    uvicorn.run(app, host="127.0.0.1", port=8001)