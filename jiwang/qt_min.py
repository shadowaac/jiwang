
import os
import sys

from qt_compat import Qt, QLibraryInfo, QCoreApplication, QApplication, QLabel


def ensure_qt_plugins():
    # Force platform and plugins path for robustness on Windows
    if sys.platform == "win32":
        try:
            # Prefer explicit PyQt5 wheel layout (Qt or Qt5)
            try:
                import PyQt5
                pyqt_root = os.path.dirname(PyQt5.__file__)
                for base in (os.path.join(pyqt_root, "Qt"), os.path.join(pyqt_root, "Qt5")):
                    plugin_base = os.path.join(base, "plugins")
                    platforms_sub = os.path.join(plugin_base, "platforms")
                    bin_dir = os.path.join(base, "bin")
                    if os.path.isdir(platforms_sub):
                        os.environ.setdefault("QT_QPA_PLATFORM_PLUGIN_PATH", platforms_sub)
                    if os.path.isdir(plugin_base):
                        os.environ["QT_PLUGIN_PATH"] = plugin_base + os.pathsep + os.environ.get("QT_PLUGIN_PATH", "")
                        try:
                            QCoreApplication.addLibraryPath(plugin_base)
                            QCoreApplication.addLibraryPath(platforms_sub)
                        except Exception:
                            pass
                    if os.path.isdir(bin_dir):
                        os.environ["PATH"] = bin_dir + os.pathsep + os.environ.get("PATH", "")
                        try:
                            os.add_dll_directory(bin_dir)
                        except Exception:
                            pass
            except Exception:
                pass

            # Also add the generic Qt plugins path reported by Qt
            try:
                plugins_dir = QLibraryInfo.location(QLibraryInfo.PluginsPath)
                platforms_dir = os.path.join(plugins_dir, "platforms")
                if os.path.isdir(plugins_dir):
                    QCoreApplication.addLibraryPath(plugins_dir)
                if os.path.isdir(platforms_dir):
                    os.environ.setdefault("QT_QPA_PLATFORM_PLUGIN_PATH", platforms_dir)
                    QCoreApplication.addLibraryPath(platforms_dir)
            except Exception:
                pass

            os.environ.setdefault("QT_QPA_PLATFORM", "windows")
            os.environ.setdefault("QT_OPENGL", "software")
        except Exception:
            pass


def main():
    if "--qt-debug" in sys.argv:
        os.environ["QT_DEBUG_PLUGINS"] = "1"

    ensure_qt_plugins()

    try:
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
        try:
            QApplication.setAttribute(Qt.AA_UseSoftwareOpenGL, True)
        except Exception:
            pass
        app = QApplication([a for a in sys.argv if a != "--qt-debug"])
        try:
            print("[qt_min] Qt library paths:", "; ".join(QCoreApplication.libraryPaths()))
            print("[qt_min] QT_QPA_PLATFORM_PLUGIN_PATH:", os.environ.get("QT_QPA_PLATFORM_PLUGIN_PATH"))
            print("[qt_min] QT_PLUGIN_PATH:", os.environ.get("QT_PLUGIN_PATH"))
        except Exception:
            pass
    except Exception as e:
        print("[qt_min][error] QApplication init failed:", e)
        sys.exit(1)

    w = QLabel("Qt OK")
    w.setMinimumSize(320, 160)
    w.setAlignment(Qt.AlignCenter)
    w.show()
    try:
        w.raise_()
        w.activateWindow()
    except Exception:
        pass

    sys.exit(app.exec_() if hasattr(app, "exec_") else app.exec())


if __name__ == "__main__":
    main()
