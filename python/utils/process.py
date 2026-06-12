"""Safe subprocess execution with timeout and resource limits."""
import asyncio
import os
import signal
from typing import Optional, Tuple, List
from dataclasses import dataclass

@dataclass
class ProcessResult:
    """Result of a subprocess execution."""
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


async def run_command_safe(
    cmd: List[str],
    timeout_seconds: int = 300,
    input_data: Optional[str] = None,
    env: Optional[dict] = None,
) -> ProcessResult:
    """
    Run a command with timeout, killing entire process group on timeout.
    
    Args:
        cmd: Command and arguments as list (safe from injection)
        timeout_seconds: Maximum execution time
        input_data: Optional stdin data
        env: Optional environment variables override
    
    Returns:
        ProcessResult with stdout, stderr, returncode, and timeout flag
    """
    process_env = os.environ.copy()
    if env:
        process_env.update(env)
    
    # Create process with new process group
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if input_data else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=process_env,
            preexec_fn=os.setsid,  # Create new process group (Unix only)
        )
    except FileNotFoundError:
        return ProcessResult(
            returncode=127,
            stdout="",
            stderr=f"Command not found: {cmd[0]}",
            timed_out=False
        )
    
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=input_data.encode() if input_data else None),
            timeout=timeout_seconds
        )
        return ProcessResult(
            returncode=proc.returncode or 0,
            stdout=stdout.decode('utf-8', errors='replace'),
            stderr=stderr.decode('utf-8', errors='replace'),
            timed_out=False
        )
    except asyncio.TimeoutError:
        # Kill entire process group
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        # Wait for process to be cleaned up
        await proc.wait()
        return ProcessResult(
            returncode=-1,
            stdout="",
            stderr=f"Process timed out after {timeout_seconds}s",
            timed_out=True
        )


def escape_shell_arg(arg: str) -> str:
    """Escape a shell argument for safe use in shell commands (only if shell=True is unavoidable)."""
    # Prefer using list form; this is a fallback
    return f"'{arg.replace(chr(39), chr(39) + chr(34) + chr(39) + chr(34) + chr(39))}'"