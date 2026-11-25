from ssrf.guard import check_redirect, check_scheme, check_target, ssrf_batch

PUBLIC = "93.184.216.34"
PUBLIC_ALT = "8.8.8.8"

HOSTS = {
    "cdn.example.com": [PUBLIC],
    "192.168.1.1.nip.io": [PUBLIC],
    "img.example.org": [PUBLIC_ALT],
    "metadata.internal": ["10.0.0.5"],
}


def resolver(host):
    return list(HOSTS.get(host, ["10.0.0.5"]))


def make_policy(**overrides):
    policy = {
        "schemes": ["http", "https"],
        "ports": [80, 443],
        "max_redirects": 3,
        "block_private": True,
        "resolver": resolver,
    }
    policy.update(overrides)
    return policy


def test_public_address_is_allowed():
    assert check_target("https://cdn.example.com/logo.png", make_policy()) is True
    assert check_target("http://192.168.1.1.nip.io/banner.jpg", make_policy()) is True


def test_loopback_address_is_rejected():
    assert check_target("http://127.0.0.1/admin", make_policy()) is False


def test_only_whitelisted_schemes_are_allowed():
    assert check_scheme("ftp://cdn.example.com/logo.png", make_policy()) is False
    assert check_scheme("https://cdn.example.com/logo.png", make_policy()) is True


def test_redirect_hops_are_checked_again():
    chain = ["https://cdn.example.com/logo.png", "http://127.0.0.1/admin"]
    assert check_redirect(chain, make_policy()) is False


def test_batch_targets_are_independent():
    urls = ["https://cdn.example.com/a.png", "http://127.0.0.1/b.png"]
    results = ssrf_batch(urls, make_policy())
    assert results[urls[0]] is True
    assert results[urls[1]] is False