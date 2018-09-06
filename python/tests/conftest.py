import pytest

import deltachat


def pytest_addoption(parser):
    parser.addoption("--user", action="store", default=None,
        help="user and domain of test account: example user@example.org")
    parser.addoption("--password", action="store", default=None)


@pytest.fixture
def userpassword(pytestconfig):
    user = pytestconfig.getoption("--user")
    passwd = pytestconfig.getoption("--password")
    if user and passwd:
        return user, passwd
    pytest.skip("specify a test account with --user and --password options")


@pytest.fixture
def tmp_db_path(tmpdir):
    return tmpdir.join("test.db").strpath
