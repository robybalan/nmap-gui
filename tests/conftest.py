import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ["QT_QPA_PLATFORMTHEME"] = ""
os.environ["QT_STYLE_OVERRIDE"] = "Fusion"

import pytest
from PyQt6.QtWidgets import QApplication


@pytest.fixture(scope="session")
def qt_app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def wait_until(qt_app):
    def wait(predicate, timeout=10):
        deadline = time.monotonic() + timeout
        while not predicate():
            qt_app.processEvents()
            if time.monotonic() > deadline:
                pytest.fail("Timed out waiting for Qt worker")
            time.sleep(0.005)
        qt_app.processEvents()
    return wait
