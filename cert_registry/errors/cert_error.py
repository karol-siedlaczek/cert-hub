from typing import Sequence
from cert_registry.domain.cert_status import CertStatus
from cert_registry.errors.api_error import ApiError

class CertError(ApiError):
    cert_id: str
    cmd: Sequence[str]
    return_code: int
    output: str
    
    def __init__(
        self,
        cert_id: str,
        *,
        cmd: Sequence[str],
        return_code: int,
        output: str
    ) -> None:
        self.cert_id = cert_id
        self.return_code = return_code
        self.cmd = cmd
        self.output = output
        detail = {
            "cmd": cmd,
            "return_code": return_code,
            "output": output
        }
        super().__init__(502, f"Failed running command for '{cert_id}' certificate", detail=detail, level="error")
    

class CertException(Exception):
    cert_id: str
    msg: str
    status: CertStatus
    
    def __init__(
        self, 
        cert_id: str, 
        msg: str, 
        *, 
        status: CertStatus
    ) -> None:
        self.cert_id = cert_id
        self.msg = msg
        self.status = status
        super().__init__(msg)
    