from src.main import is_trusted_src_ip, parse_trusted_networks


def test_trusted_ip_suppresses_alert():
    trusted_networks = parse_trusted_networks({
        'trusted_networks': ['127.0.0.0/8'],
    })

    assert is_trusted_src_ip('127.0.0.1', trusted_networks) is True


def test_untrusted_ip_fires_alert():
    trusted_networks = parse_trusted_networks({
        'trusted_networks': ['192.168.1.0/24'],
    })

    assert is_trusted_src_ip('10.0.0.5', trusted_networks) is False
