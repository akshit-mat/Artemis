import argparse
import sys
import json
import uvicorn
from .config.settings import settings
from .obs.logging import configure_logging, log
from .storage.migrations import init_db

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--host", type=str, default="127.0.0.1")
    args = parser.parse_args()

    configure_logging()
    
    try:
        init_db()
    except Exception as e:
        log.fatal("db_init_failed", error=str(e))
        sys.exit(1)
        
    settings.port = args.port
    settings.host = args.host
    
    # When port is 0, Uvicorn binds to an ephemeral port. We need to capture what port it chose.
    # To do this cleanly and print the JSON handshake line required by Tauri, 
    # we'll bind the socket manually before handing it to uvicorn, or we can use a small hack.
    # Uvicorn Server exposes the configured server sockets after startup.
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((settings.host, settings.port))
    sock.listen(1)
    
    actual_port = sock.getsockname()[1]
    settings.port = actual_port
    
    # Handshake line
    handshake = {
        "port": actual_port,
        "pid": os.getpid() if 'os' in globals() else __import__('os').getpid(),
        "version": "0.1.0"
    }
    
    # Must print exactly this JSON to stdout and flush for Tauri
    print(json.dumps(handshake), flush=True)
    
    config = uvicorn.Config(
        "artemis.api.main:app",
        host=settings.host,
        port=actual_port,
        log_level="warning", # Suppress uvicorn logs to avoid interfering with stdout handshake
        access_log=False,
    )
    
    server = uvicorn.Server(config)
    # Give uvicorn the already bound socket
    
    import asyncio
    asyncio.run(server.serve(sockets=[sock]))

if __name__ == "__main__":
    main()
