"""Consistent, readable light colors independent of the desktop's palette."""

from PyQt6.QtGui import QColor, QPalette
from PyQt6.QtWidgets import QApplication


STYLESHEET = """
    QMainWindow, QDialog { background: #f3f6f8; color: #172b3a; }
    QLabel, QCheckBox, QGroupBox, QStatusBar { color: #172b3a; }
    QLabel#title { color: #145e65; font-size: 25px; font-weight: 700; }
    QGroupBox {
        background: #ffffff; font-weight: 600;
        border: 1px solid #b5c4ce; border-radius: 7px;
        margin-top: 12px; padding: 12px 8px 8px;
    }
    QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; }
    QLineEdit, QSpinBox, QComboBox, QPlainTextEdit, QTableWidget {
        background: #ffffff; color: #172b3a;
        selection-background-color: #145e65; selection-color: #ffffff;
        border: 1px solid #98aab7; border-radius: 3px;
    }
    QLineEdit, QSpinBox, QComboBox { padding: 4px; }
    QLineEdit:focus, QSpinBox:focus, QComboBox:focus, QPlainTextEdit:focus {
        border: 1px solid #145e65;
    }
    QComboBox QAbstractItemView {
        background: #ffffff; color: #172b3a;
        selection-background-color: #145e65; selection-color: #ffffff;
        border: 1px solid #98aab7;
    }
    QPushButton {
        background: #ffffff; color: #172b3a; border: 1px solid #98aab7;
        border-radius: 5px; padding: 7px 10px;
    }
    QPushButton:hover { background: #edf3f6; color: #172b3a; border-color: #145e65; }
    QPushButton:pressed { background: #dce8ed; color: #172b3a; }
    QPushButton:focus { border: 2px solid #145e65; padding: 6px 9px; }
    QPushButton#run { background: #145e65; color: #ffffff; border-color: #145e65; }
    QPushButton#run:hover { background: #104d54; color: #ffffff; }
    QPushButton#run:pressed { background: #0d3e44; color: #ffffff; }
    QPushButton:disabled, QPushButton#run:disabled,
    QLineEdit:disabled, QSpinBox:disabled, QComboBox:disabled {
        background: #e2e8f0; color: #475569; border-color: #b5c4ce;
    }
    QLabel:disabled, QCheckBox:disabled, QGroupBox:disabled { color: #475569; }
    QTabWidget::pane { background: #ffffff; border: 1px solid #b5c4ce; }
    QTabBar::tab {
        background: #e2e8f0; color: #172b3a;
        border: 1px solid #b5c4ce; padding: 7px 10px;
    }
    QTabBar::tab:selected { background: #ffffff; color: #145e65; font-weight: 600; }
    QTabBar::tab:hover { background: #edf3f6; color: #172b3a; }
    QTableWidget { alternate-background-color: #f0f5f8; gridline-color: #c6d3db; }
    QTableWidget::item { padding: 4px; }
    QTableWidget::item:selected { background: #145e65; color: #ffffff; }
    QHeaderView::section {
        background: #e2e8f0; color: #172b3a;
        border: 1px solid #c6d3db; padding: 5px;
    }
    QPlainTextEdit#console {
        background: #18222d; color: #edf3f8; border: 0; padding: 8px;
        selection-background-color: #b8dce2; selection-color: #172b3a;
    }
    QToolTip { background: #ffffff; color: #172b3a; border: 1px solid #98aab7; padding: 5px; }
"""


def apply_light_theme(app: QApplication) -> None:
    """Set both palette roles and styled states, including inactive/disabled ones."""
    app.setStyle("Fusion")
    palette = QPalette()
    colors = {
        QPalette.ColorRole.Window: "#f3f6f8",
        QPalette.ColorRole.WindowText: "#172b3a",
        QPalette.ColorRole.Base: "#ffffff",
        QPalette.ColorRole.AlternateBase: "#f0f5f8",
        QPalette.ColorRole.Text: "#172b3a",
        QPalette.ColorRole.PlaceholderText: "#526376",
        QPalette.ColorRole.Button: "#ffffff",
        QPalette.ColorRole.ButtonText: "#172b3a",
        QPalette.ColorRole.Highlight: "#145e65",
        QPalette.ColorRole.HighlightedText: "#ffffff",
        QPalette.ColorRole.ToolTipBase: "#ffffff",
        QPalette.ColorRole.ToolTipText: "#172b3a",
        QPalette.ColorRole.Link: "#145e65",
        QPalette.ColorRole.LinkVisited: "#57418b",
        QPalette.ColorRole.Light: "#ffffff",
        QPalette.ColorRole.Midlight: "#edf3f6",
        QPalette.ColorRole.Mid: "#98aab7",
        QPalette.ColorRole.Dark: "#526376",
        QPalette.ColorRole.Shadow: "#172b3a",
        QPalette.ColorRole.BrightText: "#ffffff",
        QPalette.ColorRole.Accent: "#145e65",
    }
    for group in (QPalette.ColorGroup.Active, QPalette.ColorGroup.Inactive, QPalette.ColorGroup.Disabled):
        for role, color in colors.items():
            palette.setColor(group, role, QColor(color))
    for role in (QPalette.ColorRole.WindowText, QPalette.ColorRole.Text, QPalette.ColorRole.ButtonText):
        palette.setColor(QPalette.ColorGroup.Disabled, role, QColor("#475569"))
    for role in (QPalette.ColorRole.Base, QPalette.ColorRole.Button):
        palette.setColor(QPalette.ColorGroup.Disabled, role, QColor("#e2e8f0"))
    app.setPalette(palette)
    app.setStyleSheet(STYLESHEET)
    font = app.font()
    if 0 < font.pointSizeF() < 10:
        font.setPointSize(10)
        app.setFont(font)
