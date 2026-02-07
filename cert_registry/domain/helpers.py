import subprocess
from pathlib import Path
from typing import Sequence, Optional, Union

def run_cmd(
    args: Sequence[Union[str, Path]],
    *,
    check: bool = True,
    shell: bool = False,
    timeout: Optional[int] = None
) -> str:
    args = [str(a) for a in args]
    
    process = subprocess.run(
        args, 
        shell=shell, 
        stdin=subprocess.DEVNULL, 
        stderr=subprocess.PIPE, 
        stdout=subprocess.PIPE, 
        check=check, 
        text=True, 
        #executable="/bin/bash",
        timeout=timeout
    )
    return process.stdout or process.stderr
