from enum import Enum

class DnsProvider(Enum):
    AWS = "aws"
    
    @classmethod
    def values(cls) -> list[str]:
        return [item.value for item in cls]
    
    def get_plugin(self) -> str:
        if self == DnsProvider.AWS:
            return 'dns-route53'
        
        
    def get_required_module(self) -> str:
        if self == DnsProvider.AWS:
            return "certbot-dns-route53"

        
    def get_required_envs(self) -> tuple[str]:
        if self == DnsProvider.AWS:
            return ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
        