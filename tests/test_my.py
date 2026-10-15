import pytest
from conftest import load

# Завантажуємо модуль задачі 5
M = load(5)


@pytest.mark.parametrize("status_text, expected", [
    (
        "Name:\tbash\nState:\tS (sleeping)\nNSpid:\t45201\t102\t1\n",
        [45201, 102, 1]
    ),
    (
        "NSpid: 999\n",
        [999]
    ),
    (
        "VmSize:\t1024 kB\nNSpid:\t5555   22\t1\nThreads:\t1\n",
        [5555, 22, 1]
    ),
])
def test_my_parse_nspid_valid(status_text, expected):
    assert M.parse_nspid(status_text) == expected


def test_my_parse_nspid_missing():
    invalid_status = "Name:\tpython3\nPid:\t12345\nPPid:\t1\n"
    with pytest.raises(ValueError, match="У status немає рядка NSpid"):
        M.parse_nspid(invalid_status)