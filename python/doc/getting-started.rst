

Getting started
================

::

    # instantiate and configure deltachat account
    import deltachat
    ac1 = deltachat.Account("/tmp/db")
    ac.set_config(addr="test2@hq5.merlinux.eu", mail_pw="********")

    # start configuration activity and smtp/imap threads
    ac.start()

    # create a contact and send a message
    contact = ac.create_contact("test3@hq5.merlinux.eu")

    ...
