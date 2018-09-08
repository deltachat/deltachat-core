import pytest
import re
import threading
from deltachat import Account


def pytest_addoption(parser):
    parser.addoption(
        "--liveconfig", action="store", default=None,
        help="a file with >=2 lines where each line "
             "contains NAME=VALUE config settings for one account"
    )


@pytest.fixture
def acfactory(pytestconfig, tmpdir, request):
    fn = pytestconfig.getoption("--liveconfig")
    if not fn:
        pytest.skip("specify a --liveconfig file to run tests with real accounts")

    class AccountMaker:
        def __init__(self):
            self.configlist = []
            for line in open(fn):
                if line.strip():
                    d = {}
                    for part in line.split():
                        name, value = part.split("=")
                        d[name] = value
                    self.configlist.append(d)
            self.count = 0

        def get_live_account(self, started=True):
            configdict = self.configlist.pop(0)
            tmpdb = tmpdir.join("testdb%d" % self.count)
            ac = Account(tmpdb.strpath)
            ac._evlogger.set_timeout(10)
            ac.set_config(**configdict)
            if started:
                ac.start()
            request.addfinalizer(ac.shutdown)
            return ac

    return AccountMaker()


@pytest.fixture
def tmp_db_path(tmpdir):
    return tmpdir.join("test.db").strpath
