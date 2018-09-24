from __future__ import print_function
import pytest
import re
import threading
from deltachat import Account
from deltachat.types import cached_property
from deltachat.capi import lib


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

        def get_unconfigured_account(self):
            self.offline_count += 1
            tmpdb = tmpdir.join("offlinedb%d" % self.offline_count)
            ac = Account(tmpdb.strpath, logid="ac{}".format(self.offline_count))
            ac._evlogger.set_timeout(2)
            return ac

        def get_configured_offline_account(self):
            self.offline_count += 1
            tmpdb = tmpdir.join("offlinedb%d" % self.offline_count)
            ac = Account(tmpdb.strpath, logid="ac{}".format(self.offline_count))

            # do a pseudo-configured account
            addr = "addr{}@offline.org".format(self.offline_count)
            ac.set_config("addr", addr)
            lib.dc_set_config(ac._dc_context, b"configured_addr", addr.encode("ascii"))
            lib.dc_set_config_int(ac._dc_context, b"configured", 1);
            ac._evlogger.set_timeout(2)
            return ac

        def get_live_account(self, started=True):
            if not fn:
                pytest.skip("specify a --liveconfig file to run tests with real accounts")
            self.live_count += 1
            configdict = self.configlist.pop(0)
            tmpdb = tmpdir.join("livedb%d" % self.live_count)
            ac = Account(tmpdb.strpath, logid="ac{}".format(self.live_count))
            ac._evlogger.set_timeout(30)
            ac.configure(**configdict)
            if started:
                ac.start()
            request.addfinalizer(ac.shutdown)
            return ac

    return AccountMaker()


@pytest.fixture
def tmp_db_path(tmpdir):
    return tmpdir.join("test.db").strpath


@pytest.fixture
def lp():
    class Printer:
        def sec(self, msg):
            print()
            print("=" * 10, msg, "=" * 10)
        def step(self, msg):
            print("-" * 5, "step " + msg, "-" * 5)
    return Printer()
