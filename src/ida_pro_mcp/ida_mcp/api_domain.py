"""Domain API Functions - High-level IDA 9.x Data Abstraction Layer"""

import logging
from typing import Annotated, Optional, Any

try:
    import ida_domain
    import ida_domain.database
    import ida_domain.instructions
    import ida_domain.names
    HAS_DOMAIN = True
except ImportError:
    HAS_DOMAIN = False

from .rpc import tool
from .sync import idasync

logger = logging.getLogger(__name__)

@tool
@idasync
def domain_get_info() -> dict:
    """Get high-level database information using the Domain API (IDA 9+)
    
    Returns metadata about the currently loaded database using the modern
    Data Abstraction Layer.
    """
    if not HAS_DOMAIN:
        return {"error": "Domain API (ida_domain) is not available. Requires IDA 9.0+"}
        
    try:
        db = ida_domain.database.get_current_database()
        return {
            "success": True,
            "filename": db.filename,
            "base_address": hex(db.base_address),
            "is_64bit": db.is_64bit,
            "processor": db.processor_name,
            "file_type": db.file_type_name,
        }
    except Exception as e:
        return {"error": f"Failed to get domain info: {e}"}

@tool
@idasync
def domain_query_symbol(
    name: Annotated[str, "Symbol name to look up"]
) -> dict:
    """Look up a symbol using the Domain API
    
    Args:
        name: Name of the symbol/name to find
    """
    if not HAS_DOMAIN:
        return {"error": "Domain API (ida_domain) is not available."}
        
    try:
        db = ida_domain.database.get_current_database()
        symbol = db.names.get(name)
        if not symbol:
            return {"success": False, "message": f"Symbol not found: {name}"}
            
        return {
            "success": True,
            "name": symbol.name,
            "address": hex(symbol.address),
            "is_public": symbol.is_public,
        }
    except Exception as e:
        return {"error": f"Failed to query symbol: {e}"}

@tool
@idasync
def domain_analyze_instruction(
    address: Annotated[str, "Address of the instruction (hex or int)"]
) -> dict:
    """Analyze an instruction using the Domain API
    
    Provides structured information about an instruction at a given address.
    """
    if not HAS_DOMAIN:
        return {"error": "Domain API (ida_domain) is not available."}
        
    try:
        from .utils import parse_address
        ea = parse_address(address)
        
        db = ida_domain.database.get_current_database()
        insn = db.instructions.get(ea)
        
        if not insn:
            return {"success": False, "message": f"No instruction at {hex(ea)}"}
            
        return {
            "success": True,
            "address": hex(insn.address),
            "mnemonic": insn.mnemonic,
            "text": insn.text,
            "size": insn.size,
            "operands": [
                {
                    "text": op.text,
                    "type": str(op.type),
                    "value": hex(op.value) if hasattr(op, 'value') else None
                }
                for op in insn.operands
            ]
        }
    except Exception as e:
        return {"error": f"Failed to analyze instruction: {e}"}
