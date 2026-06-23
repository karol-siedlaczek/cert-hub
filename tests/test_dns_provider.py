from cert_hub.domain.dns_provider import DnsProvider


def test_values_lists_all_providers():
    assert DnsProvider.values() == ["aws", "cloudflare"]


def test_aws_metadata():
    assert DnsProvider.AWS.get_plugin() == "dns-route53"
    assert DnsProvider.AWS.get_required_module() == "certbot-dns-route53"
    assert DnsProvider.AWS.get_required_envs() == ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")


def test_cloudflare_metadata():
    assert DnsProvider.CF.get_plugin() == "dns-cloudflare"
    assert DnsProvider.CF.get_required_module() == "certbot-dns-cloudflare"
    assert DnsProvider.CF.get_required_envs() == ("CLOUDFLARE_DNS_API_TOKEN",)
