import pytest
import re
import threading
from deltachat import Account
from deltachat.types import cached_property


def pytest_addoption(parser):
    parser.addoption(
        "--liveconfig", action="store", default=None,
        help="a file with >=2 lines where each line "
             "contains NAME=VALUE config settings for one account"
    )


@pytest.fixture
def acfactory(pytestconfig, tmpdir, request):
    fn = pytestconfig.getoption("--liveconfig")

    class AccountMaker:
        def __init__(self):
            self.live_count = 0
            self.offline_count = 0

        @cached_property
        def configlist (self):
            configlist = []
            for line in open(fn):
                if line.strip():
                    d = {}
                    for part in line.split():
                        name, value = part.split("=")
                        d[name] = value
                    configlist.append(d)
            return configlist

        def get_offline_account(self):
            self.offline_count += 1
            tmpdb = tmpdir.join("offlinedb%d" % self.offline_count)
            ac = Account(tmpdb.strpath, logid="ac{}".format(self.offline_count))
            ac._evlogger.set_timeout(2)
            return ac

        def get_live_account(self, started=True):
            if not fn:
                pytest.skip("specify a --liveconfig file to run tests with real accounts")
            self.live_count += 1
            configdict = self.configlist.pop(0)
            tmpdb = tmpdir.join("livedb%d" % self.live_count)
            ac = Account(tmpdb.strpath, logid="ac{}".format(self.live_count))
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
