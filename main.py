"""
API Server for GPT-Engineer

This module provides a FastAPI server that exposes GPT-Engineer's functionality
through REST API endpoints and WebSockets, allowing code generation via HTTP requests
or WebSocket connections.
"""

import os
import json
import uuid
import logging
import tempfile
from typing import Dict, List, Optional, Any
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException, Depends, Request, status, WebSocket, WebSocketDisconnect
from fastapi.security.api_key import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from gpt_engineer.applications.cli.cli_agent import CliAgent
from gpt_engineer.core.ai import AI
from gpt_engineer.core.default.disk_execution_env import DiskExecutionEnv
from gpt_engineer.core.default.disk_memory import DiskMemory
from gpt_engineer.core.default.paths import memory_path
from gpt_engineer.core.default.steps import gen_code, gen_entrypoint
from gpt_engineer.core.preprompts_holder import PrepromptsHolder
from gpt_engineer.core.prompt import Prompt
from gpt_engineer.core.files_dict import FilesDict

from src.api_server.feedback import create_learning_data, store_request_metadata, process_feedback

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="GPT-Engineer API",
    description="API for generating code using GPT-Engineer",
    version="0.1.0",
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API key security
API_KEY_NAME = "x-api-key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

# Load API keys from environment
API_KEYS = os.environ.get("API_KEYS", "").split(",")
if not API_KEYS or API_KEYS == [""]:
    logger.warning("API_KEYS environment variable not set. API will be accessible without authentication.")


# Request and response models
class CodeGenerationRequest(BaseModel):
    payload: str
    model: Optional[str] = "gpt-4o"
    temperature: Optional[float] = 0.1
    collect_feedback: Optional[bool] = True


class FeedbackRequest(BaseModel):
    request_id: str
    ran: bool
    perfect: bool
    works: bool
    comments: Optional[str] = ""


class CodeGenerationResponse(BaseModel):
    request_id: str
    files: Dict[str, str]
    logs: Optional[Dict[str, str]] = None
    token_usage: Optional[Dict[str, int]] = None
    cost: Optional[float] = None
    mapped_directory: Optional[str] = None


class FeedbackResponse(BaseModel):
    request_id: str
    status: str


# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.active_connections[client_id] = websocket
        logger.info(f"WebSocket client connected: {client_id}")

    def disconnect(self, client_id: str):
        if client_id in self.active_connections:
            del self.active_connections[client_id]
            logger.info(f"WebSocket client disconnected: {client_id}")

    async def send_json(self, client_id: str, data: dict):
        if client_id in self.active_connections:
            await self.active_connections[client_id].send_json(data)


manager = ConnectionManager()


async def verify_api_key(api_key_header: str = Depends(api_key_header)):
    if not API_KEYS or API_KEYS == [""]:
        return True
    
    if api_key_header not in API_KEYS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key",
        )
    return True


async def verify_ws_api_key(api_key: str):
    if not API_KEYS or API_KEYS == [""]:
        return True
    
    if api_key not in API_KEYS:
        return False
    return True


async def generate_code_logic(request_data: dict):
    """Shared logic for code generation between HTTP and WebSocket endpoints"""
    try:
        payload = request_data.get("payload", "")
        model = request_data.get("model", "gpt-4o")
        temperature = request_data.get("temperature", 0.1)
        collect_feedback = request_data.get("collect_feedback", True)
        
        logger.info(f"Processing code generation request: {payload[:100]}...")
        
        # Create a unique project path for this request
        project_dir = tempfile.mkdtemp(prefix="gpte-", dir="/tmp")
        project_path = Path(project_dir)
        
        # Ensure proper permissions on the directory
        os.chmod(project_dir, 0o755)  # rwxr-xr-x
        
        logger.info(f"Created project directory: {project_path}")
        
        # Create prompt
        prompt = Prompt(payload)
        
        # Initialize AI
        ai = AI(
            model_name=model,
            temperature=temperature,
        )
        
        # Set up memory and execution environment
        memory = DiskMemory(memory_path(project_path))
        execution_env = DiskExecutionEnv()
        
        # Initialize agent
        agent = CliAgent.with_default_config(
            memory,
            execution_env,
            ai=ai,
            code_gen_fn=gen_code,
        )
        
        # Generate code (without execution)
        logger.info("Generating code...")
        files_dict = agent.code_gen_fn(
            agent.ai, prompt, agent.memory, agent.preprompts_holder
        )
        
        # Generate entrypoint
        entrypoint = gen_entrypoint(
            agent.ai, prompt, files_dict, agent.memory, agent.preprompts_holder
        )
        
        # Combine files
        combined_dict = {**files_dict, **entrypoint}
        files_dict = FilesDict(combined_dict)
        
        # Convert files_dict to a regular dictionary for JSON serialization
        files_output = {k: v for k, v in files_dict.items()}
        
        # Generate a unique request ID
        request_id = str(uuid.uuid4())
        
        # Collect token usage information
        token_usage = None
        cost = None
        if ai.token_usage_log:
            token_usage = {
                "total_tokens": ai.token_usage_log._cumulative_total_tokens,
                "prompt_tokens": ai.token_usage_log._cumulative_prompt_tokens,
                "completion_tokens": ai.token_usage_log._cumulative_completion_tokens
            }
            
            if ai.token_usage_log.is_openai_model():
                cost = ai.token_usage_log.usage_cost()
        
        # Collect logs
        logs = {}
        logs_dir = os.path.join(project_path, "memory", "logs")
        if os.path.exists(logs_dir):
            for log_file in os.listdir(logs_dir):
                if log_file.endswith(".log"):
                    with open(os.path.join(logs_dir, log_file), "r") as f:
                        logs[log_file] = f.read()
        
        # Store learning data if feedback collection is enabled
        if collect_feedback:
            config = ("gen_code", "none")
            learning_data = create_learning_data(prompt, model, temperature, config, memory)
            store_request_metadata(memory, request_id, learning_data)
        
        # Save files to mapped directory
        mapped_dir = save_files_to_mapped_directory(files_dict, request_id)
        
        # Store request ID directly in the project directory
        try:
            # Create memory directory if it doesn't exist
            memory_dir = os.path.join(project_path, "memory")
            os.makedirs(memory_dir, exist_ok=True)
            
            # Write request ID to a simple file for easier access
            with open(os.path.join(memory_dir, "request_id.txt"), "w") as f:
                f.write(request_id)
            
            logger.info(f"Stored request ID in file: {os.path.join(memory_dir, 'request_id.txt')}")
        except Exception as e:
            logger.warning(f"Failed to store request ID in file: {str(e)}")
        
        logger.info(f"Code generation completed successfully. Request ID: {request_id}")
        
        return {
            "request_id": request_id,
            "files": files_output,
            "logs": logs,
            "token_usage": token_usage,
            "cost": cost,
            "mapped_directory": mapped_dir
        }
        
    except Exception as e:
        logger.error(f"Error generating code: {str(e)}", exc_info=True)
        raise Exception(f"Error generating code: {str(e)}")


async def process_feedback_logic(feedback_data: dict):
    """Shared logic for feedback processing between HTTP and WebSocket endpoints"""
    try:
        request_id = feedback_data.get("request_id")
        logger.info(f"Processing feedback for request ID: {request_id}")
        
        status = process_feedback(
            request_id, 
            {
                "ran": feedback_data.get("ran"),
                "perfect": feedback_data.get("perfect"),
                "works": feedback_data.get("works"),
                "comments": feedback_data.get("comments", "")
            }
        )
        
        if not status:
            raise Exception(f"Request ID {request_id} not found or expired")
        
        return {
            "request_id": request_id,
            "status": "Feedback received successfully"
        }
        
    except Exception as e:
        logger.error(f"Error processing feedback: {str(e)}", exc_info=True)
        raise Exception(f"Error processing feedback: {str(e)}")


# HTTP Endpoints
@app.post("/api/getCodeCLI", response_model=CodeGenerationResponse)
async def generate_code(
    request: CodeGenerationRequest, authenticated: bool = Depends(verify_api_key)
):
    """Generate code based on a natural language prompt"""
    try:
        result = await generate_code_logic(request.dict())
        return CodeGenerationResponse(**result)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@app.post("/api/feedback", response_model=FeedbackResponse)
async def submit_feedback(
    feedback: FeedbackRequest, authenticated: bool = Depends(verify_api_key)
):
    """Submit feedback for previously generated code"""
    try:
        result = await process_feedback_logic(feedback.dict())
        return FeedbackResponse(**result)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}


# WebSocket Endpoints
@app.websocket("/ws/getCodeCLI")
async def ws_generate_code(websocket: WebSocket):
    """WebSocket endpoint for code generation"""
    client_id = str(uuid.uuid4())
    await manager.connect(websocket, client_id)
    
    try:
        while True:
            data = await websocket.receive_json()
            
            # Verify API key if provided
            api_key = data.get("api_key", "")
            if not await verify_ws_api_key(api_key):
                await websocket.send_json({"error": "Invalid API Key"})
                continue
            
            try:
                result = await generate_code_logic(data)
                await websocket.send_json(result)
            except Exception as e:
                await websocket.send_json({"error": str(e)})
    
    except WebSocketDisconnect:
        manager.disconnect(client_id)
    except Exception as e:
        logger.error(f"WebSocket error: {str(e)}", exc_info=True)
        manager.disconnect(client_id)


@app.websocket("/ws/feedback")
async def ws_submit_feedback(websocket: WebSocket):
    """WebSocket endpoint for submitting feedback"""
    client_id = str(uuid.uuid4())
    await manager.connect(websocket, client_id)
    
    try:
        while True:
            data = await websocket.receive_json()
            
            # Verify API key if provided
            api_key = data.get("api_key", "")
            if not await verify_ws_api_key(api_key):
                await websocket.send_json({"error": "Invalid API Key"})
                continue
            
            try:
                result = await process_feedback_logic(data)
                await websocket.send_json(result)
            except Exception as e:
                error_msg = str(e)
                logger.error(f"Error in feedback processing: {error_msg}")
                await websocket.send_json({
                    "error": error_msg,
                    "status": "failed",
                    "request_id": data.get("request_id", "unknown")
                })
    
    except WebSocketDisconnect:
        manager.disconnect(client_id)
    except Exception as e:
        logger.error(f"WebSocket error: {str(e)}", exc_info=True)
        manager.disconnect(client_id)


@app.websocket("/ws/health")
async def ws_health_check(websocket: WebSocket):
    """WebSocket endpoint for health check"""
    client_id = str(uuid.uuid4())
    await manager.connect(websocket, client_id)
    
    try:
        while True:
            # Wait for any message, but we don't need to use its content
            await websocket.receive_text()
            await websocket.send_json({"status": "healthy"})
    
    except WebSocketDisconnect:
        manager.disconnect(client_id)
    except Exception as e:
        logger.error(f"WebSocket error: {str(e)}", exc_info=True)
        manager.disconnect(client_id)


def save_files_to_mapped_directory(files_dict, request_id):
    """Save generated files to a directory that's mapped to the host system"""
    try:
        base_dir = Path("/tmp/generated_code")
        output_dir = base_dir / request_id
        
        # Create the base directory if it doesn't exist
        os.makedirs(base_dir, exist_ok=True)
        os.chmod(base_dir, 0o755)  # rwxr-xr-x
        
        # Create the request-specific directory
        os.makedirs(output_dir, exist_ok=True)
        os.chmod(output_dir, 0o755)  # rwxr-xr-x
        
        # Create memory directory and store request ID
        memory_dir = output_dir / "memory"
        os.makedirs(memory_dir, exist_ok=True)
        os.chmod(memory_dir, 0o755)  # rwxr-xr-x
        
        # Store request ID in a file
        with open(memory_dir / "request_id.txt", "w") as f:
            f.write(request_id)
        
        # Create any subdirectories needed
        for filename in files_dict.keys():
            # Get the directory part of the filename
            file_dir = os.path.dirname(filename)
            if file_dir:
                # Create the subdirectory if it doesn't exist
                subdir_path = output_dir / file_dir
                os.makedirs(subdir_path, exist_ok=True)
                os.chmod(subdir_path, 0o755)  # rwxr-xr-x
        
        # Now save the files
        for filename, content in files_dict.items():
            file_path = output_dir / filename
            with open(file_path, "w") as f:
                f.write(content)
            os.chmod(file_path, 0o644)  # rw-r--r--
        
        return str(output_dir)
    except PermissionError as e:
        logger.error(f"Permission error when saving files: {str(e)}")
        # Fall back to a different directory if needed
        fallback_dir = Path(f"/tmp/gpte_fallback_{request_id}")
        os.makedirs(fallback_dir, exist_ok=True)
        return str(fallback_dir)


if __name__ == "__main__":
    # Run the server
    port = int(os.environ.get("PORT", 4546))
    logger.info(f"Starting GPT-Engineer API server on port {port}")
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True) 