import pytest

import deltachat
from deltachat import capi
import threading


@pytest.fixture
def register_dc_callback(monkeypatch):
    """Register a callback for a given context.

    This is a function-scoped fixture and the function will be
    unregisterd automatically on fixture teardown.
    """
    def register_dc_callback(ctx, func):
        monkeypatch.setitem(deltachat._DC_CALLBACK_MAP, ctx, func)
    return register_dc_callback


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



def imap_thread(context, quitflag):
    print ("starting imap thread")
    while not quitflag.is_set():
        capi.lib.dc_perform_imap_jobs(context)
        capi.lib.dc_perform_imap_fetch(context)
        capi.lib.dc_perform_imap_idle(context)


def smtp_thread(context, quitflag):
    print ("starting smtp thread")
    while not quitflag.is_set():
        capi.lib.dc_perform_smtp_jobs(context)
        capi.lib.dc_perform_smtp_idle(context)


@pytest.fixture
def dc_context():
    ctx = capi.lib.dc_context_new(capi.lib.py_dc_callback,
                                  capi.ffi.NULL, capi.ffi.NULL)
    yield ctx
    capi.lib.dc_close(ctx)


@pytest.fixture
def dc_threads(dc_context):
    quitflag = threading.Event()
    t1 = threading.Thread(target=imap_thread, name="imap", args=[dc_context, quitflag])
    t1.setDaemon(1)
    t1.start()
    t2 = threading.Thread(target=smtp_thread, name="smtp", args=[dc_context, quitflag])
    t2.setDaemon(1)
    t2.start()
    yield
    quitflag.set()

