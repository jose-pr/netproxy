import netproxy


def test_version_comes_from_installed_metadata():
    assert netproxy.__version__ != "0+unknown"
