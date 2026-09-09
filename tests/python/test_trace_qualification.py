import pytest

from trace_qualification import relative_call_target


@pytest.mark.parametrize("address,code,target", [
    (0x1000, "e80b000000", 0x1010), (0x2000, "e8fbffffff", 0x2000),
    (0x7ff700001000, "e8fbefffff", 0x7ff700000000),
])
def test_blocked_fixture_call_target(address, code, target):
    assert relative_call_target(address, code) == target


@pytest.mark.parametrize("code", ["", "e8", "e900000000", "ff15000000", "e80000000090"])
def test_blocked_fixture_rejects_wrong_call_encoding(code):
    with pytest.raises(AssertionError, match="direct rel32"):
        relative_call_target(0x1000, code)
