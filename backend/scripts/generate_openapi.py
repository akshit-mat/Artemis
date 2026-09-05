import json
import sys
from pathlib import Path

# Need to add backend to sys.path so we can import artemis
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from artemis.api.main import app
from fastapi.openapi.utils import get_openapi
from artemis.api.models import (
    WSEnvelope, SessionReadyData, AgentDeltaData, AgentMessageData,
    AgentErrorData, SystemEchoData, AssistantStateData,
    ChatSendData, RunCancelData
)

from pydantic.json_schema import models_json_schema

def generate_openapi():
    schema = app.openapi()
    
    # Deliberately expose Pydantic models to OpenAPI schema without dummy routes
    models = [
        WSEnvelope, SessionReadyData, AgentDeltaData, AgentMessageData, 
        AgentErrorData, SystemEchoData, AssistantStateData,
        ChatSendData, RunCancelData
    ]
    
    _, top_level_schema = models_json_schema(
        [(m, "serialization") for m in models], 
        title="WebSocket Protocol"
    )
    
    if "components" not in schema:
        schema["components"] = {}
    if "schemas" not in schema["components"]:
        schema["components"]["schemas"] = {}
        
    for name, model_schema in top_level_schema.get("$defs", {}).items():
        schema["components"]["schemas"][name] = model_schema
        
    import json
    schema_str = json.dumps(schema)
    schema_str = schema_str.replace('"#/$defs/', '"#/components/schemas/')
    schema = json.loads(schema_str)
    
    output_path = backend_dir.parent / "apps" / "desktop" / "openapi.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(schema, f, indent=2)
    print(f"OpenAPI schema generated at {output_path}")

if __name__ == "__main__":
    generate_openapi()
