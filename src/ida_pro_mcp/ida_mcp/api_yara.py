"""YARA Generation API - Intelligent rule creation using mkyara"""

import logging
from typing import Annotated, Optional

try:
    import mkyara
    from mkyara import YaraGenerator
    from capstone import (
        CS_ARCH_X86, CS_MODE_32, CS_MODE_64,
        CS_ARCH_ARM, CS_ARCH_ARM64, CS_MODE_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN, CS_MODE_BIG_ENDIAN,
        CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_MIPS64
    )
    HAS_MKYARA = True
except ImportError:
    HAS_MKYARA = False

import ida_ida
import ida_bytes
import ida_segment
import ida_ua
from .rpc import tool
from .sync import idasync
from .utils import parse_address

logger = logging.getLogger(__name__)

def _get_capstone_context(ea: int):
    """Maps IDA architecture state at a specific address to Capstone constants.
    
    mkyara requires Capstone constants to correctly disassemble and wildcard instructions.
    Even though we get bytes from IDA, mkyara needs to know 'what' those bytes are.
    """
    proc_name = ida_ida.inf_get_procname().lower()
    is_64 = ida_ida.inf_get_app_bitness() == 64
    is_be = ida_ida.inf_is_be()
    
    arch = None
    mode = 0

    # Endianness
    endian_mode = CS_MODE_BIG_ENDIAN if is_be else CS_MODE_LITTLE_ENDIAN

    if proc_name in ("metapc", "80386", "80486", "p3", "p4", "8086"):
        arch = CS_ARCH_X86
        mode = CS_MODE_64 if is_64 else CS_MODE_32
        # x86 usually ignores endian flag in Capstone (always little), but good to know context
    
    elif proc_name == "arm":
        if is_64:
            arch = CS_ARCH_ARM64
            mode = CS_MODE_ARM | endian_mode
        else:
            arch = CS_ARCH_ARM
            # Check T segment register for Thumb mode
            # 1 = Thumb, 0 = ARM
            is_thumb = ida_segment.get_sreg(ea, "T") == 1
            mode = (CS_MODE_THUMB if is_thumb else CS_MODE_ARM) | endian_mode

    elif proc_name == "mips":
        arch = CS_ARCH_MIPS
        mode = (CS_MODE_MIPS64 if is_64 else CS_MODE_MIPS32) | endian_mode

    else:
        # TODO: Add more architectures (PPC, etc) as needed
        raise ValueError(f"Architecture '{proc_name}' is not currently supported for YARA generation.")

    return arch, mode

@tool
@idasync
def generate_yara_rule(
    name: Annotated[str, "Name of the YARA rule"],
    start_addr: Annotated[str, "Start address of the memory range (hex or int)"],
    end_addr: Annotated[str, "End address of the memory range (hex or int)"],
    mode: Annotated[str, "Wildcard mode: 'loose' (all operands), 'normal' (displacements), 'strict' (jumps/calls)"] = "normal",
    include_data: Annotated[bool, "Whether to include data chunks in the rule"] = False
) -> dict:
    """Generate a YARA rule for a selected memory range using intelligent wildcarding. 
    
    Uses the 'mkyara' library to generate rules that are resilient to relocation and 
    offset changes.
    
    Modes:
    - loose: Wildcards all operands. Very generic.
    - normal: Wildcards only displacement operands (e.g., memory offsets). Balanced.
    - strict: Wildcards only jump/call targets. Specific.
    """
    if not HAS_MKYARA:
        return {
            "error": "Required libraries not found. Please install 'mkyara' and 'capstone'.\n"
                     "pip install mkyara capstone"
        }

    valid_modes = ["loose", "normal", "strict"]
    if mode not in valid_modes:
        return {"error": f"Invalid mode '{mode}'. Must be one of: {', '.join(valid_modes)}"}

    try:
        start = parse_address(start_addr)
        end = parse_address(end_addr)
        
        if start >= end:
            return {"error": "Start address must be less than end address."}

        # Initialize Generator with context from the start address
        # Note: If architecture changes mid-stream (e.g. ARM <-> Thumb), 
        # mkyara might struggle if we use a single generator instance.
        # For now, we assume the start address defines the context.
        try:
            arch, cs_mode = _get_capstone_context(start)
        except ValueError as e:
            return {"error": str(e)}

        gen = YaraGenerator(mode, arch, cs_mode)
        
        current = start
        while current < end:
            # Get item size (instruction size or data item size)
            item_size = ida_bytes.get_item_size(current)
            if item_size == 0:
                # Safety check to prevent infinite loops on undefined bytes
                item_size = 1

            # Ensure we don't go past end
            if current + item_size > end:
                # Partial item at the end, usually better to skip or just take bytes
                item_size = end - current

            flags = ida_bytes.get_flags(current)
            is_code = ida_bytes.is_code(flags)
            
            # If we hit code, check if we need to update mode (e.g. Thumb switch) 
            # Complex to handle with single YaraGenerator instance. 
            # Ideally we would check if arch changed, but Capstone context is fixed per gen.
            # We proceed with initial context.
            
            should_add = False
            is_data_chunk = False

            if is_code:
                should_add = True
                is_data_chunk = False
            elif include_data:
                should_add = True
                is_data_chunk = True
            
            if should_add:
                chunk_bytes = ida_bytes.get_bytes(current, item_size)
                if chunk_bytes:
                    # mkyara uses relative offsets from the start of the block
                    rel_offset = current - start
                    
                    gen.add_chunk(
                        chunk_bytes,
                        offset=rel_offset,
                        is_data=is_data_chunk
                    )

            current += item_size

        rule = gen.generate_rule()
        rule.rule_name = name # Ensure name is set
        
        return {
            "success": True,
            "rule": rule.get_rule_string(),
            "info": f"Generated rule '{name}' from {hex(start)} to {hex(end)} ({mode} mode)"
        }

    except Exception as e:
        return {"error": f"Yara generation failed: {e}"}
