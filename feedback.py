"""
Feedback Collection Utility for GPT-Engineer API

This module provides utilities for collecting and processing feedback
on code generated through the GPT-Engineer API.
"""

import os
import json
import logging
import uuid
from typing import Dict, Optional, Any
from datetime import datetime
from pathlib import Path

from gpt_engineer.applications.cli.learning import Review, Learning
from gpt_engineer.core.default.disk_memory import DiskMemory

logger = logging.getLogger(__name__)


def store_request_metadata(memory: DiskMemory, request_id: str, learning_data: Dict[str, Any]):
    """
    Store request metadata for later feedback collection.
    
    Parameters
    ----------
    memory : DiskMemory
        The memory instance to store data in
    request_id : str
        The unique identifier for this request
    learning_data : Dict[str, Any]
        The learning data to store
    """
    try:
        # Check if memory has set method or uses __setitem__ instead
        if hasattr(memory, 'set'):
            memory.set("request_id", request_id)
            memory.set("learning", json.dumps(learning_data))
        else:
            # Use dictionary-style assignment
            memory["request_id"] = request_id
            memory["learning"] = json.dumps(learning_data)
        
        logger.info(f"Stored request metadata for ID: {request_id}")
    except Exception as e:
        logger.error(f"Failed to store request metadata: {str(e)}")


def create_learning_data(prompt, model, temperature, config, memory):
    """
    Create learning data without sending to RudderStack
    
    Parameters
    ----------
    prompt : str
        The initial prompt provided to the GPT Engineer
    model : str
        The name of the model used during the session
    temperature : float
        The temperature setting used for the model's responses
    config : Any
        Configuration parameters used for the learning session
    memory : DiskMemory
        An object representing the disk memory used during the session
        
    Returns
    -------
    Dict[str, Any]
        Dictionary containing learning data
    """
    try:
        return {
            "prompt": prompt.to_json() if hasattr(prompt, "to_json") else str(prompt),
            "model": model,
            "temperature": temperature,
            "config": json.dumps(config) if not isinstance(config, str) else config,
            "session": str(uuid.uuid4()),
            "logs": memory.to_json() if hasattr(memory, "to_json") else "{}",
            "review": None,
            "timestamp": datetime.utcnow().isoformat(),
            "version": "0.3"
        }
    except Exception as e:
        logger.error(f"Error creating learning data: {str(e)}")
        return {}


def process_feedback(request_id: str, feedback_data: Dict) -> Optional[str]:
    """
    Process feedback for a previously generated code.
    
    Parameters
    ----------
    request_id : str
        The unique identifier for the original request
    feedback_data : Dict
        Dictionary containing feedback information
        
    Returns
    -------
    Optional[str]
        Status message or None if processing failed
    """
    try:
        # Find the project directory for this request
        project_path = None
        
        # First check in the generated_code directory
        generated_code_dir = Path("/tmp/generated_code")
        if generated_code_dir.exists() and (generated_code_dir / request_id).exists():
            project_path = str(generated_code_dir / request_id)
            logger.info(f"Found request ID in generated_code directory: {project_path}")
        
        # If not found, check in the temp directories
        if not project_path:
            for dir_name in os.listdir("/tmp"):
                if dir_name.startswith("gpte-"):
                    temp_dir = os.path.join("/tmp", dir_name)
                    try:
                        memory_dir = os.path.join(temp_dir, "memory")
                        if os.path.exists(memory_dir):
                            memory = DiskMemory(memory_dir)
                            
                            # Check if memory has exists method or uses __contains__ instead
                            if hasattr(memory, 'exists'):
                                has_request_id = memory.exists("request_id")
                            else:
                                has_request_id = "request_id" in memory
                            
                            if has_request_id:
                                # Check if memory has get method or uses __getitem__ instead
                                if hasattr(memory, 'get'):
                                    stored_id = memory.get("request_id")
                                else:
                                    stored_id = memory["request_id"]
                                
                                if stored_id == request_id:
                                    project_path = temp_dir
                                    logger.info(f"Found request ID in temp directory: {project_path}")
                                    break
                    except (PermissionError, FileNotFoundError) as e:
                        # Skip directories we can't access
                        logger.debug(f"Skipping directory {temp_dir}: {str(e)}")
                        continue
        
        if not project_path:
            # As a last resort, create a new directory for the feedback
            fallback_dir = os.path.join("/tmp", f"feedback-{request_id}")
            os.makedirs(fallback_dir, exist_ok=True)
            os.makedirs(os.path.join(fallback_dir, "memory"), exist_ok=True)
            project_path = fallback_dir
            logger.warning(f"Request ID {request_id} not found, creating fallback: {fallback_dir}")
            
        # Load or create the memory for this project
        try:
            memory_dir = os.path.join(project_path, "memory")
            os.makedirs(memory_dir, exist_ok=True)
            memory = DiskMemory(memory_dir)
            
            # Create a Review object from the feedback
            review = {
                "ran": feedback_data.get("ran"),
                "perfect": feedback_data.get("perfect"),
                "works": feedback_data.get("works"),
                "comments": feedback_data.get("comments", ""),
                "raw": f"{feedback_data.get('ran')}, {feedback_data.get('perfect')}, {feedback_data.get('works')}"
            }
            
            # Store the review in memory
            if hasattr(memory, 'set'):
                memory.set("review", json.dumps(review))
            else:
                memory["review"] = json.dumps(review)
            
            logger.info(f"Stored feedback for request ID: {request_id}")
            return "Feedback processed successfully"
            
        except Exception as e:
            logger.error(f"Error storing feedback: {str(e)}")
            return None
            
    except Exception as e:
        logger.error(f"Error processing feedback: {str(e)}")
        return None 