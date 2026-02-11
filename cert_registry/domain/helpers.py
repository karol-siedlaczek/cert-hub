import subprocess
from typing import Sequence, Optional

def run_cmd(
    args: Sequence[str],
    *,
    shell: bool = False,
    timeout: Optional[int] = None
) -> subprocess.CompletedProcess[str]:
    args = [str(a) for a in args]
    
    result = subprocess.run(
        args, 
        shell=shell, 
        stdin=subprocess.DEVNULL, 
        stderr=subprocess.PIPE, 
        stdout=subprocess.PIPE, 
        text=True, 
        #executable="/bin/bash",
        timeout=timeout
    )
    return result
