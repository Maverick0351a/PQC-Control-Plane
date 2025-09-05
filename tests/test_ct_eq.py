from src.signet.utils.ct import ct_eq


def test_ct_eq_basic():
    assert ct_eq(b'abc', b'abc') is True
    assert ct_eq(b'abc', b'abd') is False
    assert ct_eq(b'abc', b'abcd') is False
