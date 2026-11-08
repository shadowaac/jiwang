import sys
import os
import ctypes
import threading
import subprocess
from collections import defaultdict

########## Qt 兼容层 ##########
from qt_compat import (
    Qt,
    QObject,
    Signal,
    QLibraryInfo,
    QTimer,
    QCoreApplication,
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

from sniffer_backend import Sniffer, get_pcap_dll_path
from utils import format_hexdump, packet_layers_iter, guess_protocol, pkt_endpoints

########## 主窗口 ##########
class MainWindow(QMainWindow):
    interfaces_ready = Signal(list)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Qt + Npcap 网络抓包解包工具")
        self.resize(1280, 800)

        ########## 抓包引擎 ##########
        self.sniffer = Sniffer()
        self.sniffer.packet_captured.connect(self.on_packet_captured)
        self.sniffer.started.connect(lambda: self.statusBar().showMessage("正在抓包…"))
        self.sniffer.stopped.connect(lambda: self.statusBar().showMessage("抓包已停止"))
        self.sniffer.error.connect(self.on_sniffer_error)

        ########## 数据缓存 ##########
        self.packet_rows = []               # 按到达顺序保存 scapy 报文
        self.protocol_counts = defaultdict(int)
        self.total_packets = 0

        self._build_ui()

        self.interfaces_ready.connect(self._on_interfaces_ready)
        QTimer.singleShot(0, self._populate_interfaces)   # 事件循环启动后再执行

    # ------------------------------------------------------------------
    # 界面构造总入口
    # ------------------------------------------------------------------
    def _build_ui(self):
        self._build_toolbar()

        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QHBoxLayout(central)

        ########## 左侧：上下分割 ##########
        left_split = QSplitter(Qt.Vertical)

        ## 上：包列表表格
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["No.", "Port", "Source", "Destination", "Protocol", "Length", "Info"])
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.selectionModel().selectionChanged.connect(self.on_selection_changed)

        # 列宽自适应 + 横向滚动条
        try:
            self.table.setTextElideMode(Qt.ElideNone)
            th = self.table.horizontalHeader()
            th.setSectionResizeMode(QHeaderView.ResizeToContents)
            th.setStretchLastSection(False)
            self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
            self.table.setWordWrap(False)
        except Exception:
            pass

        ## 下：十六进制视图
        self.hex_view = QTextEdit()
        self.hex_view.setReadOnly(True)

        left_split.addWidget(self.table)
        left_split.addWidget(self.hex_view)
        left_split.setSizes([600, 400])

        ########## 右侧：统计 + 协议树 + Ping ##########
        right_container = QWidget()
        right_layout = QVBoxLayout(right_container)

        # ---- 实时统计 ----
        self.stats_group = QGroupBox("实时统计")
        stats_layout = QHBoxLayout(self.stats_group)
        self.lbl_total = QLabel("总数: 0")
        self.lbl_tcp  = QLabel("TCP: 0")
        self.lbl_udp  = QLabel("UDP: 0")
        self.lbl_icmp = QLabel("ICMP: 0")
        self.lbl_http = QLabel("HTTP: 0")
        for lbl in (self.lbl_total, self.lbl_tcp, self.lbl_udp,
                    self.lbl_icmp, self.lbl_http):
            stats_layout.addWidget(lbl)
        stats_layout.addStretch(1)

        # ---- 协议树 ----
        self.details_tree = QTreeWidget()
        self.details_tree.setHeaderLabels(["字段", "值"])
        try:
            self.details_tree.setTextElideMode(Qt.ElideNone)
            hdr = self.details_tree.header()
            hdr.setSectionResizeMode(QHeaderView.ResizeToContents)
            hdr.setStretchLastSection(False)
            self.details_tree.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        except Exception:
            pass

        # ---- Ping 输出 ----
        self.ping_group = QGroupBox("Ping 输出")
        ping_layout = QVBoxLayout(self.ping_group)
        self.ping_output = QTextEdit()
        self.ping_output.setReadOnly(True)
        ping_layout.addWidget(self.ping_output)

        right_layout.addWidget(self.stats_group)
        right_layout.addWidget(self.details_tree, 3)
        right_layout.addWidget(self.ping_group, 2)

        root_split = QSplitter(Qt.Horizontal)
        root_split.addWidget(left_split)
        root_split.addWidget(right_container)
        root_split.setSizes([800, 480])
        root_layout.addWidget(root_split)

        self.statusBar().showMessage("就绪")

    # ------------------------------------------------------------------
    # 工具条
    # ------------------------------------------------------------------
    def _build_toolbar(self):
        tb = QToolBar("Controls")
        self.addToolBar(tb)

        self.act_start = QAction("开始", self)
        self.act_start.triggered.connect(self.on_start)
        tb.addAction(self.act_start)

        self.act_stop = QAction("停止", self)
        self.act_stop.triggered.connect(self.on_stop)
        self.act_stop.setEnabled(False)
        tb.addAction(self.act_stop)
        tb.addSeparator()

        tb.addWidget(QLabel("网卡:"))
        self.combo_iface = QComboBox()
        self.combo_iface.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.combo_iface.setMinimumContentsLength(12)
        tb.addWidget(self.combo_iface)

        # 协议过滤
        tb.addSeparator()
        tb.addWidget(QLabel("协议:"))
        self.combo_proto = QComboBox()
        self.combo_proto.addItems(["Any", "TCP", "UDP", "ICMP", "HTTP"])
        tb.addWidget(self.combo_proto)

        tb.addWidget(QLabel("IP:"))
        self.input_ip = QLineEdit()
        self.input_ip.setPlaceholderText("例如 192.168.1.10")
        self.input_ip.setFixedWidth(150)
        tb.addWidget(self.input_ip)

        tb.addWidget(QLabel("端口:"))
        self.input_port = QSpinBox()
        self.input_port.setRange(0, 65535)
        self.input_port.setFixedWidth(90)
        tb.addWidget(self.input_port)

        # 高级 BPF
        tb.addWidget(QLabel("BPF:"))
        self.input_bpf = QLineEdit()
        self.input_bpf.setPlaceholderText("高级 BPF 过滤表达式")
        self.input_bpf.setFixedWidth(220)
        tb.addWidget(self.input_bpf)

        self.btn_apply_filter = QPushButton("应用过滤")
        self.btn_apply_filter.clicked.connect(self.on_apply_filter)
        tb.addWidget(self.btn_apply_filter)

        self.addToolBarBreak()
        tb_ping = QToolBar("Ping")
        self.addToolBar(tb_ping)
        tb_ping.addWidget(QLabel("Ping 目标:"))
        self.input_ping_host = QLineEdit()
        self.input_ping_host.setPlaceholderText("例如 www.baidu.com")
        self.input_ping_host.setFixedWidth(200)
        tb_ping.addWidget(self.input_ping_host)

        self.btn_ping = QPushButton("Ping")
        self.btn_ping.clicked.connect(self.on_ping)
        tb_ping.addWidget(self.btn_ping)

    # ------------------------------------------------------------------
    # 异步
    # ------------------------------------------------------------------
    def _populate_interfaces(self):
        self.statusBar().showMessage("正在加载网卡…")
        def worker():
            try:
                names = self.sniffer.list_interfaces()
            except Exception:
                names = []
            self.interfaces_ready.emit(names)
        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------------
    # 主线程更新网卡下拉框
    # ------------------------------------------------------------------
    def _on_interfaces_ready(self, names):
        if not names:
            QMessageBox.warning(self, "接口获取失败", "无法列出网卡接口，请检查 Npcap 与权限。")
        else:
            self.combo_iface.clear()
            for name in names:
                self.combo_iface.addItem(name)
            # 根据最长名字动态调整最小宽度
            fm = self.combo_iface.fontMetrics()
            maxw = max((fm.horizontalAdvance(n) for n in names), default=0)
            self.combo_iface.setMinimumWidth(max(150, maxw + 40))
            try:
                self.combo_iface.view().setMinimumWidth(max(200, maxw + 60))
            except Exception:
                pass
        self.statusBar().showMessage("就绪")

    # ------------------------------------------------------------------
    # 抓包控制
    # ------------------------------------------------------------------
    def on_start(self):
        iface = self.combo_iface.currentText() or None
        bpf = self.input_bpf.text().strip() or self._build_bpf()
        try:
            self.sniffer.start(iface=iface, bpf_filter=bpf)
        except Exception as e:
            QMessageBox.critical(self, "启动失败",
                                 f"启动抓包失败: {e}\n请确认已安装 Npcap 并以管理员权限运行。")
            return
        self.act_start.setEnabled(False)
        self.act_stop.setEnabled(True)
        self.statusBar().showMessage(f"抓包中… 接口: {iface or '默认'}  过滤: {bpf or '无'}")

    def on_stop(self):
        self.sniffer.stop()
        self.act_start.setEnabled(True)
        self.act_stop.setEnabled(False)

    def on_apply_filter(self):
        # 若正在抓包，先停再启，使新过滤条件生效
        if self.sniffer.is_running:
            self.on_stop()
            QApplication.processEvents()
            self.on_start()

    def on_sniffer_error(self, msg: str):
        QMessageBox.critical(self, "抓包错误", msg)

    # ------------------------------------------------------------------
    # Ping 工具
    # ------------------------------------------------------------------
    def on_ping(self):
        host = (self.input_ping_host.text() or "").strip()
        if not host:
            QMessageBox.information(self, "提示", "请输入 Ping 目标，例如 www.baidu.com")
            return
        self.ping_output.clear()
        self.ping_output.append(f"开始 Ping {host} (发送 4 个 ICMP)…\n")

        def run_ping():
            try:
                proc = subprocess.run(["ping", "-n", "4", host],
                                      capture_output=True, text=True, timeout=20)
                out = proc.stdout or proc.stderr
            except Exception as e:
                out = f"Ping 执行失败: {e}"
            self.ping_output.append(out)
        threading.Thread(target=run_ping, daemon=True).start()

    # ------------------------------------------------------------------
    # 每收到一个包都会进这里
    # ------------------------------------------------------------------
    def on_packet_captured(self, pkt):
        self.packet_rows.append(pkt)
        row = self.table.rowCount()
        self.table.insertRow(row)

        # 提取端口、端点、协议、长度、摘要
        port = ""
        try:
            from scapy.layers.inet import TCP, UDP
            if TCP in pkt:
                port = str(int(pkt[TCP].dport))
            elif UDP in pkt:
                port = str(int(pkt[UDP].dport))
        except Exception:
            port = ""
        src, dst = pkt_endpoints(pkt)
        proto = guess_protocol(pkt)
        length = len(pkt)
        info = pkt.summary()

        # 填表
        self.table.setItem(row, 0, QTableWidgetItem(str(row + 1)))
        self.table.setItem(row, 1, QTableWidgetItem(port))
        self.table.setItem(row, 2, QTableWidgetItem(src))
        self.table.setItem(row, 3, QTableWidgetItem(dst))
        self.table.setItem(row, 4, QTableWidgetItem(proto))
        self.table.setItem(row, 5, QTableWidgetItem(str(length)))
        self.table.setItem(row, 6, QTableWidgetItem(info))

        # 统计刷新
        self.total_packets += 1
        self.protocol_counts[proto] += 1
        self._refresh_stats()

    def _refresh_stats(self):
        self.lbl_total.setText(f"总数: {self.total_packets}")
        self.lbl_tcp.setText( f"TCP: {self.protocol_counts.get('TCP', 0)}")
        self.lbl_udp.setText( f"UDP: {self.protocol_counts.get('UDP', 0)}")
        self.lbl_icmp.setText(f"ICMP: {self.protocol_counts.get('ICMP', 0)}")
        self.lbl_http.setText(f"HTTP: {self.protocol_counts.get('HTTP', 0)}")

    # ------------------------------------------------------------------
    # 单击表格行 → 刷新十六进制 + 协议树
    # ------------------------------------------------------------------
    def on_selection_changed(self, *_):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        idx = rows[0].row()
        if idx < 0 or idx >= len(self.packet_rows):
            return
        pkt = self.packet_rows[idx]
        self.hex_view.setPlainText(format_hexdump(bytes(pkt)))
        self._fill_details(pkt)

    def _fill_details(self, pkt):
        self.details_tree.clear()
        for layer in packet_layers_iter(pkt):
            layer_item = QTreeWidgetItem([layer.__class__.__name__, ""])
            self.details_tree.addTopLevelItem(layer_item)
            try:
                for k, v in layer.fields.items():
                    key_text = str(k)
                    val_text = str(v)
                    child = QTreeWidgetItem([key_text, val_text])
                    child.setToolTip(0, key_text)
                    child.setToolTip(1, val_text)
                    layer_item.addChild(child)
            except Exception:
                pass
        self.details_tree.expandAll()

    # ------------------------------------------------------------------
    # 根据 UI 输入自动生成 BPF 过滤串
    # ------------------------------------------------------------------
    def _build_bpf(self) -> str:
        parts = []
        proto = self.combo_proto.currentText()
        if proto and proto != "Any":
            p = proto.upper()
            if p == "HTTP":
                parts.append("tcp port 80 or port 8080 or port 8000")
            else:
                parts.append(p.lower())
        ip = self.input_ip.text().strip()
        if ip:
            parts.append(f"host {ip}")
        port = int(self.input_port.value())
        if port > 0:
            parts.append(f"port {port}")
        return " and ".join(parts)


########## 程序入口 ##########
def main():
    # ------------------------------------------------------------------
    # Windows 管理员提权
    # ------------------------------------------------------------------
    if sys.platform == "win32" and "--no-elevate" not in sys.argv and "--elevated" not in sys.argv:
        try:
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            is_admin = False
        if not is_admin:
            try:
                script = os.path.abspath(__file__)
                args = [script] + [a for a in sys.argv[1:]] + ["--elevated"]
                params = " ".join([f'"{a}"' if " " in a else a for a in args])
                ret = ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, params, None, 1)
                if ret and ret > 32:
                    sys.exit(0)          # 提权成功，当前进程退出
                else:
                    print("[提示] 未能自动提升为管理员，建议右键以管理员运行。")
            except Exception as e:
                print("[提示] 自动提权失败:", e)

    # ------------------------------------------------------------------
    # Windows Qt 插件路径自动修复
    # ------------------------------------------------------------------
    if sys.platform == "win32":
        try:
            plugins_dir = QLibraryInfo.location(QLibraryInfo.PluginsPath)
            platforms_dir = os.path.join(plugins_dir, "platforms")
            if os.path.isdir(platforms_dir):
                os.environ.setdefault("QT_QPA_PLATFORM_PLUGIN_PATH", platforms_dir)

            # 针对 PyQt5 轮子内嵌路径再补一遍
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
                        os.environ["QT_PLUGIN_PATH"] = (
                            plugin_base + os.pathsep + os.environ.get("QT_PLUGIN_PATH", ""))
                        QCoreApplication.addLibraryPath(plugin_base)
                        QCoreApplication.addLibraryPath(platforms_sub)
                    if os.path.isdir(bin_dir):
                        os.environ["PATH"] = bin_dir + os.pathsep + os.environ.get("PATH", "")
                        try:
                            os.add_dll_directory(bin_dir)
                        except Exception:
                            pass
            except Exception:
                pass

            # 兜底再扫全局 plugins 目录
            if os.path.isdir(plugins_dir):
                QCoreApplication.addLibraryPath(plugins_dir)
            if os.path.isdir(platforms_dir):
                QCoreApplication.addLibraryPath(platforms_dir)

            # 强制 windows 平台插件 + 软件 OpenGL，防止黑屏
            os.environ.setdefault("QT_QPA_PLATFORM", "windows")
            os.environ.setdefault("QT_OPENGL", "software")
        except Exception:
            pass

    # 调试开关
    if "--qt-debug" in sys.argv:
        os.environ["QT_DEBUG_PLUGINS"] = "1"

    #  wpcap.dll 路径
    if sys.platform == "win32":
        try:
            print("[诊断] 已加载 wpcap.dll:", get_pcap_dll_path())
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 创建 QApplication
    # ------------------------------------------------------------------
    try:
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
        QApplication.setAttribute(Qt.AA_UseSoftwareOpenGL, True)
        app = QApplication(sys.argv)
        print("[诊断] Qt 库搜索路径:", "; ".join(QCoreApplication.libraryPaths()))
    except Exception as e:
        print("[错误] Qt 初始化失败:", e)
        print("请尝试: pip install --upgrade PyQt5, 并确认 Qt 插件路径可用。")
        sys.exit(1)

    # ------------------------------------------------------------------
    # 显示主窗口并进入事件循环
    # ------------------------------------------------------------------
    w = MainWindow()
    w.show()
    try:
        w.raise_()
        w.activateWindow()
        app.setActiveWindow(w)
    except Exception:
        pass
    # 延迟再提一次窗口，防止某些窗口管理器失效
    QTimer.singleShot(200, lambda: (w.raise_(), w.activateWindow()))

    rc = app.exec_() if hasattr(app, "exec_") else app.exec()
    sys.exit(rc)


########## 只有直接运行才启动 ##########
if __name__ == "__main__":
    main()