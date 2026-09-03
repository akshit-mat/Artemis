import argparse
import sys
import json
import os
import uvicorn
import socket

from .config.paths import Paths
from .config.schema import load_config
from .obs.logging import configure_logging, get_logger

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--host", type=str, default="127.0.0.1")
    args = parser.parse_args()

    paths = Paths.resolve()
    config, _ = load_config(paths)
    
    configure_logging(paths.log_dir, config.logging)
    log = get_logger("startup")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((args.host, args.port))
    sock.listen(1)
    
    actual_port = sock.getsockname()[1]
    
    # Pass to api/main.py via environ
    os.environ["ARTEMIS_PORT"] = str(actual_port)
    os.environ["ARTEMIS_HOST"] = args.host
    
    handshake = {
        "port": actual_port,
        "pid": os.getpid(),
        "version": "0.1.0"
    }
    # Must print exactly this JSON to stdout and flush for Tauri
    print(json.dumps(handshake), flush=True)
    
    uv_config = uvicorn.Config(
        "artemis.api.main:app",
        host=args.host,
        port=actual_port,
        log_level="warning", # Suppress uvicorn logs to avoid interfering with stdout handshake
        access_log=False,
        ws_max_size=262144, # 256 KB
    )
    
    server = uvicorn.Server(uv_config)
    
    import asyncio
    asyncio.run(server.serve(sockets=[sock]))

if __name__ == "__main__":
    main()
