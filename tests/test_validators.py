import pytest

from nmap_gui.validators import ValidationError, validate_ports, validate_target


@pytest.mark.parametrize("value,expected", [
    ("192.168.56.101", "192.168.56.101"), ("192.168.56.42/24", "192.168.56.0/24"),
    ("2001:db8::1", "2001:db8::1"), ("2001:db8::5/64", "2001:db8::/64"),
    ("SCANME.nmap.org", "scanme.nmap.org"), ("localhost", "localhost"), ("lab.local.", "lab.local."),
])
def test_targets(value, expected):
    assert validate_target(value) == expected


@pytest.mark.parametrize("value", ["", "-sV", "999.1.1.1", "1.2.3", "::gg", "10.0.0.0/99",
    "a..org", "-host", "a-.org", "a" * 64 + ".org", "https://lab.org", "a b", "a\nb",
    "127.0.0.1;id", "a&&id", "a||id", "`id`", "$(id)", "a|id", "a>file", "a\x00"])
def test_invalid_targets(value):
    with pytest.raises(ValidationError):
        validate_target(value)


@pytest.mark.parametrize("value", ["22", "22,80,443", "1-1000", "22,80,443,8000-9000", "65535"])
def test_ports(value):
    assert validate_ports(value) == value


@pytest.mark.parametrize("value", ["", "0", "65536", "100-1", "1--2", "22,", ",22", "1-", "-1",
    "22 80", "22;id", "22&&id", "$(id)", "T:22", "1,2\n", "1" * 4097])
def test_invalid_ports(value):
    with pytest.raises(ValidationError):
        validate_ports(value)
