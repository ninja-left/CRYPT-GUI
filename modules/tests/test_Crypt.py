from PySide6.QtWidgets import QApplication
import clipman
from Crypt import MainWindow
from modules import functions
import pytest


@pytest.fixture
def app(qtbot):
    window = MainWindow()
    qtbot.addWidget(window)
    return window


def test_buttons(app):
    # Test zoom-in & out buttons
    oldOutputFont = app.outputText.font().pointSize()
    oldInputFont = app.inputText.font().pointSize()

    app.btnZoomIn.click()
    assert app.outputText.font().pointSize() > oldOutputFont
    assert app.inputText.font().pointSize() > oldInputFont

    app.btnZoomOut.click()
    assert app.outputText.font().pointSize() == oldOutputFont
    assert app.inputText.font().pointSize() == oldInputFont

    # Test copy & paste buttons
    clipman.init()
    clipman.copy("testing")
    app.inputText.setPlainText("")
    app.btnPaste.click()
    assert app.inputText.toPlainText() != ""

    app.outputText.setPlainText("testing!!!!!")
    app.btnCopy.click()
    assert clipman.paste() != "testing"
