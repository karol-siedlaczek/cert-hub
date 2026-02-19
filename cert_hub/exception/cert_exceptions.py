from typing import Sequence
from cert_hub.domain.cert_status import CertStatus
from cert_hub.exception.api_exceptions import ApiError

class CertBotError(ApiError):
    cert_name: str
    cmd: Sequence[str]
    return_code: int
    output: str
    
    def __init__(
        self,
        cert_name: str,
        *,
        cmd: Sequence[str],
        return_code: int,
        output: str
    ) -> None:
        self.cert_name = cert_name
        self.return_code = return_code
        self.cmd = cmd
        self.output = output
        detail = {
            "cmd": cmd,
            "return_code": return_code,
            "output": output
        }
        super().__init__(502, msg=f"CertBot failed while processing certificate '{cert_name}'", detail=detail, level="error")
    

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
    