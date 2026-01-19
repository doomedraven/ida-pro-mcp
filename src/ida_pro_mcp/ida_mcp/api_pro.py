"""Pro API Functions - IDA Pro/IDALib lifecycle management"""

import logging
from typing import Annotated, Optional
from pathlib import Path

import ida_pro
from .rpc import tool
from .idb_session import get_session_manager, HAS_IDALIB

logger = logging.getLogger(__name__)

@tool
def open_database(
    input_path: Annotated[str, "Path to the binary file to analyze"],
    run_auto_analysis: Annotated[bool, "Run automatic analysis on the binary"] = True,
    session_id: Annotated[Optional[str], "Custom session ID (auto-generated if not provided)"] = None,
) -> dict:
    """Open a binary file and create a new IDA session (idalib mode only)
    
    Opens a binary file for analysis and creates a new session. The binary will be
    analyzed in IDA's headless mode. If the file is already open, returns the existing
    session ID.
    
    Args:
        input_path: Path to the binary file to analyze
        run_auto_analysis: Whether to run IDA's automatic analysis (default: True)
        session_id: Optional custom session ID (default: auto-generated)
        
    Returns:
        Dictionary with session information
    """
    if not HAS_IDALIB:
        return {"error": "open_database is only supported in headless idalib mode"}
        
    try:
        manager = get_session_manager()
        session_id_result = manager.open_binary(
            Path(input_path),
            run_auto_analysis=run_auto_analysis,
            session_id=session_id
        )
        
        session = manager.get_session(session_id_result)
        if session is None:
            return {"error": f"Failed to retrieve session after opening: {session_id_result}"}
        
        return {
            "success": True,
            "session": session.to_dict(),
            "message": f"Binary opened successfully: {session.input_path.name}"
        }
    except FileNotFoundError as e:
        return {"error": str(e)}
    except RuntimeError as e:
        return {"error": f"Failed to open binary: {e}"}
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}


@tool
def close_database(
    session_id: Annotated[str, "Session ID to close"]
) -> dict:
    """Close an IDA session and its associated database (idalib mode only)"""
    if not HAS_IDALIB:
        return {"error": "close_database is only supported in headless idalib mode"}

    try:
        manager = get_session_manager()
        
        if manager.close_session(session_id):
            return {
                "success": True,
                "message": f"Session closed: {session_id}"
            }
        else:
            return {
                "success": False,
                "error": f"Session not found: {session_id}"
            }
    except Exception as e:
        return {"error": f"Failed to close session: {e}"}


@tool
def switch_database(
    session_id: Annotated[str, "Session ID to switch to"]
) -> dict:
    """Switch to a different IDA session (idalib mode only)"""
    if not HAS_IDALIB:
        return {"error": "switch_database is only supported in headless idalib mode"}

    try:
        manager = get_session_manager()
        
        if manager.switch_session(session_id):
            session = manager.get_current_session()
            if session is None:
                return {"error": "Failed to retrieve current session after switching"}
            
            return {
                "success": True,
                "session": session.to_dict(),
                "message": f"Switched to session: {session_id} ({session.input_path.name})"
            }
    except ValueError as e:
        return {"error": str(e)}
    except RuntimeError as e:
        return {"error": f"Failed to switch session: {e}"}
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}


@tool
def list_databases() -> dict:
    """List all open IDA sessions (idalib mode only)"""
    if not HAS_IDALIB:
        return {"error": "list_databases is only supported in headless idalib mode"}

    try:
        manager = get_session_manager()
        sessions = manager.list_sessions()
        current_session = manager.get_current_session()
        
        return {
            "sessions": sessions,
            "count": len(sessions),
            "current_session_id": current_session.session_id if current_session else None
        }
    except Exception as e:
        return {"error": f"Failed to list sessions: {e}"}


@tool
def current_database() -> dict:
    """Get information about the current active IDA session (idalib mode only)"""
    if not HAS_IDALIB:
        return {"error": "current_database is only supported in headless idalib mode"}

    try:
        manager = get_session_manager()
        session = manager.get_current_session()
        
        if session is None:
            return {
                "error": "No active session. Use open_database() to open a binary first."
            }
        
        return session.to_dict()
    except Exception as e:
        return {"error": f"Failed to get current session: {e}"}


@tool
def exit_ida(
    code: Annotated[int, "Exit code"] = 0
) -> dict:
    """Shutdown IDA and exit the process"""
    try:
        if HAS_IDALIB:
            manager = get_session_manager()
            manager.close_all_sessions()
        
        ida_pro.qexit(code)
        return {"success": True, "message": "Exiting IDA..."}
    except Exception as e:
        return {"error": f"Failed to exit IDA: {e}"}
