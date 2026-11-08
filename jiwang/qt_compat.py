import os

try:
    # 优先使用 PyQt5。不同版本的 wheel 目录名可能为 'Qt' 或 'Qt5'。
    import PyQt5
    from PyQt5.QtCore import Qt, QObject, pyqtSignal as Signal, QLibraryInfo, QTimer, QCoreApplication
    from PyQt5.QtWidgets import (
        QApplication,
        QMainWindow,
        QWidget,
        QVBoxLayout,
        QHBoxLayout,
        QSplitter,
        QTableWidget,
        QTableWidgetItem,
        QTextEdit,
        QTreeWidget,
        QTreeWidgetItem,
        QGroupBox,
        QLabel,
        QPushButton,
        QLineEdit,
        QComboBox,
        QSpinBox,
        QToolBar,
        QAction,
        QMessageBox,
        QHeaderView,
    )
    _root = os.path.dirname(PyQt5.__file__)
    _candidates = [os.path.join(_root, 'Qt'), os.path.join(_root, 'Qt5')]
    _qt_plugins = next((os.path.join(d, 'plugins', 'platforms') for d in _candidates if os.path.isdir(os.path.join(d, 'plugins', 'platforms'))), None)
    _qt_bin = next((os.path.join(d, 'bin') for d in _candidates if os.path.isdir(os.path.join(d, 'bin'))), None)
    # 不再强制检查两者都存在；app 会在运行时设置 PATH/插件路径。
except Exception:
    # 回退到 PySide6（wheel 自带完整 Qt 运行库）
    from PySide6.QtCore import Qt, QObject, Signal, QLibraryInfo, QTimer, QCoreApplication
    from PySide6.QtWidgets import (
        QApplication,
        QMainWindow,
        QWidget,
        QVBoxLayout,
        QHBoxLayout,
        QSplitter,
        QTableWidget,
        QTableWidgetItem,
        QTextEdit,
        QTreeWidget,
        QTreeWidgetItem,
        QGroupBox,
        QLabel,
        QPushButton,
        QLineEdit,
        QComboBox,
        QSpinBox,
        QToolBar,
        QMessageBox,
        QHeaderView,
    )
    from PySide6.QtGui import QAction
