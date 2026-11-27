"""Repository test helpers shared by behavior and contract suites."""

import os
import unittest

if "NAS_KEEPASS_SETUP_BIN" not in os.environ:
    # Setup code validates KeePass passwords through the Go helper.
    from tests.go_binaries import binary

    try:
        os.environ["NAS_KEEPASS_SETUP_BIN"] = str(binary("nas-keepass-setup"))
    except unittest.SkipTest:
        pass
