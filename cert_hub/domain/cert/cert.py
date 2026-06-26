import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import ClassVar
from cert_hub.domain.cert.cert_bot import CertBot
from cert_hub.domain.cert.cert_status import CertStatus
from cert_hub.domain.cert.cert_type import CertType

log = logging.getLogger(__name__)


class Cert(ABC):
    DATE_FMT: ClassVar[str] = '%Y-%m-%d %H:%M'

    # Provided by subclasses (annotations only — not dataclass fields here):
    id: str
    type: ClassVar[CertType]
    custom_attrs: dict
    domains: tuple[str, ...]


    # ── abstract interface ───────────────────────────────────────────────
    @abstractmethod
    def is_issued(self) -> bool: ...


    @abstractmethod
    def get_certificate(self) -> str: ...


    @abstractmethod
    def get_chain(self) -> str: ...


    @abstractmethod
    def get_private_key(self) -> str: ...


    @abstractmethod
    def get_expire_date(self) -> datetime: ...


    @abstractmethod
    def get_status(self) -> CertStatus: ...


    @abstractmethod
    def issue(self, force: bool = False) -> None: ...


    @abstractmethod
    def renew(self, force: bool = False) -> None: ...


    @abstractmethod
    def revoke(self) -> None: ...


    def get_full_chain(self) -> str:
        chain = self.get_chain()
        certificate = self.get_certificate()
        return f"{certificate}\n{chain}" if chain else certificate


    def get_next_renew_date_as_str(self) -> str:
        return datetime.strftime(self.get_next_renew_date(), self.DATE_FMT)


    def get_next_renew_date(self) -> datetime:
        certbot = CertBot.get_from_global_context()
        return self.get_expire_date() - timedelta(days=certbot.renew_before_days)


    def get_expire_date_as_str(self) -> str:
        return datetime.strftime(self.get_expire_date(), self.DATE_FMT)


    def get_days_to_expire(self) -> int:
        return self._get_time_left().days


    def is_expiring(self) -> bool:
        certbot = CertBot.get_from_global_context()
        return self.get_days_to_expire() <= certbot.renew_before_days


    def is_expired(self) -> bool:
        return self._get_time_left().total_seconds() <= 0


    def _expiry_status(self) -> CertStatus:
        if self.is_expired():
            return CertStatus.EXPIRED
        elif self.is_expiring():
            return CertStatus.EXPIRING
        else:
            return CertStatus.OK


    def _get_time_left(self) -> timedelta:
        return self.get_expire_date() - datetime.now(timezone.utc)


    def _read_text(self, file_path: Path) -> str:
        try:
            return file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return file_path.read_text(encoding="ascii", errors="ignore")


    def __str__(self) -> str:
        return self.id
