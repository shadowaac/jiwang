#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
抓包后端：负责加载 Npcap/WinPcap、枚举网卡、启动/停止异步抓包
作者：You
"""
from qt_compat import QObject, Signal
import os
import sys
import ctypes
import logging

########## 优先加载 Npcap（而非旧版 WinPcap）##########
PCAP_DLL_DIR = None

def _prefer_npcap_explicit_load():

    if sys.platform != "win32":
        return None
    candidates = [
        r"C:\Windows\System32\Npcap",
        r"C:\Windows\SysWOW64\Npcap",
        r"C:\Windows\System32",
        r"C:\Windows\SysWOW64",
    ]
    for d in candidates:
        if not d or not os.path.isdir(d):
            continue
        wpcap = os.path.join(d, "wpcap.dll")
        packet = os.path.join(d, "Packet.dll")
        if not (os.path.exists(wpcap) and os.path.exists(packet)):
            continue
        # 把目录加入 DLL 搜索顺序
        try:
            os.add_dll_directory(d)
        except Exception:
            pass
        os.environ["PATH"] = d + os.pathsep + os.environ.get("PATH", "")
        try:
            ctypes.WinDLL(packet)
            ctypes.WinDLL(wpcap)
            return d
        except Exception:
            continue
    return None

def get_pcap_dll_path():
    """
    返回当前进程已加载的 wpcap.dll 完整路径，用于诊断
    """
    if sys.platform != "win32":
        return None
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        GetModuleHandleW = kernel32.GetModuleHandleW
        GetModuleFileNameW = kernel32.GetModuleFileNameW
        GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
        GetModuleHandleW.restype = ctypes.c_void_p
        GetModuleFileNameW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_uint]
        GetModuleFileNameW.restype = ctypes.c_uint
        hmod = GetModuleHandleW("wpcap.dll")
        if not hmod:
            return None
        buf = ctypes.create_unicode_buffer(260)
        if GetModuleFileNameW(hmod, buf, 260):
            return buf.value
    except Exception:
        pass
    return None

########## 日志级别抑制 ##########
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
PCAP_DLL_DIR = _prefer_npcap_explicit_load()

_SCAPY_READY = False
_AsyncSniffer = None
_get_if_list = None

def _load_scapy():
    """
    延迟加载 scapy，确保 DLL 路径已优先设置好
    """
    global _SCAPY_READY, _AsyncSniffer, _get_if_list
    if _SCAPY_READY:
        return
    try:
        from scapy.config import conf
        conf.use_pcap = True
        from scapy.all import AsyncSniffer, get_if_list
        _AsyncSniffer = AsyncSniffer
        _get_if_list = get_if_list
        _SCAPY_READY = True
    except Exception as e:
        raise RuntimeError(f"加载 Scapy 失败: {e}")

########## ctypes 结构体：pcap_if_t ##########
class _pcap_if_t(ctypes.Structure):
    pass

_pcap_if_t._fields_ = [
    ("next", ctypes.POINTER(_pcap_if_t)),
    ("name", ctypes.c_char_p),
    ("description", ctypes.c_char_p),
    ("addresses", ctypes.c_void_p),
    ("flags", ctypes.c_uint),
]

def _pcap_findalldevs_ctypes():
    """
    用 ctypes 直接调用 wpcap.dll 的 pcap_findalldevs，
    不依赖 scapy/pylibpcap，最底层方案
    """
    try:
        dll = ctypes.WinDLL("wpcap.dll")
        pcap_findalldevs = dll.pcap_findalldevs
        pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(_pcap_if_t)), ctypes.c_char_p]
        pcap_findalldevs.restype = ctypes.c_int

        pcap_freealldevs = dll.pcap_freealldevs
        pcap_freealldevs.argtypes = [ctypes.POINTER(_pcap_if_t)]
        pcap_freealldevs.restype = None

        alldevs = ctypes.POINTER(_pcap_if_t)()
        errbuf = ctypes.create_string_buffer(256)
        rc = pcap_findalldevs(ctypes.byref(alldevs), errbuf)
        if rc != 0:
            msg = errbuf.value.decode(errors="ignore")
            raise RuntimeError(f"pcap_findalldevs 失败: {msg}")
        result = []
        try:
            cur = alldevs
            while cur:
                name = cur.contents.name.decode(errors="ignore") if cur.contents.name else ""
                desc = cur.contents.description.decode(errors="ignore") if cur.contents.description else ""
                result.append((name, desc))
                cur = cur.contents.next
        finally:
            if alldevs:
                pcap_freealldevs(alldevs)
        return result
    except Exception as e:
        logging.getLogger(__name__).warning("ctypes 枚举接口失败: %s", e)
        return []

########## 抓包核心类 ##########
class Sniffer(QObject):
    # 信号：面向 UI 线程发送事件
    started = Signal()
    stopped = Signal()
    packet_captured = Signal(object)   # 携带 scapy 报文
    error = Signal(str)

    def __init__(self):
        super().__init__()
        self._sniffer = None
        self.is_running = False
        self._iface = None
        self._filter = None
        # 显示名 → 真实设备名 映射，仅 Windows 需要
        self._iface_map = {}

    # ---------- 对外 API ----------
    def start(self, iface=None, bpf_filter=None):
        """
        启动异步抓包
        :param iface: 网卡显示名，None=默认
        :param bpf_filter: BPF 过滤串，None=不过滤
        """
        if self.is_running:
            return
        self._iface = iface
        self._filter = bpf_filter or None
        try:
            _load_scapy()
            # Windows 把友好名称转成 \\Device\\NPF_{GUID}
            real_iface = self._iface
            if sys.platform == "win32" and self._iface:
                real_iface = self._iface_map.get(self._iface, self._iface)

            self._sniffer = _AsyncSniffer(
                iface=real_iface,
                filter=self._filter,
                store=False,
                prn=self._on_packet,   # 收到包回调
            )
            self._sniffer.start()
            self.is_running = True
            self.started.emit()
        except Exception as e:
            self._sniffer = None
            self.is_running = False
            self.error.emit(f"无法启动抓包: {e}")
            raise

    def stop(self):
        """
        停止抓包
        """
        if not self.is_running:
            return
        try:
            if self._sniffer is not None:
                self._sniffer.stop()
        finally:
            self._sniffer = None
            self.is_running = False
            self.stopped.emit()

    def list_interfaces(self):
        """
        返回网卡列表（供 UI 下拉框使用）
        优先顺序：ctypes → scapy Windows 助手 → pylibpcap → scapy 通用列表
        """
        try:
            if sys.platform == "win32":
                # 1. 裸调 DLL，最准
                devs = _pcap_findalldevs_ctypes()
                if devs:
                    names = []
                    self._iface_map.clear()
                    for dev, desc in devs:
                        disp = f"{desc} ({dev})" if desc else dev
                        self._iface_map[disp] = dev
                        names.append(disp)
                    if names:
                        return names

                # 2. Scapy Windows 助手（不依赖 pcap 提供者）
                try:
                    from scapy.arch.windows import get_windows_if_list  # type: ignore
                    names = []
                    self._iface_map.clear()
                    for info in get_windows_if_list():
                        guid = (info.get("guid") or info.get("netid") or "").strip("{}")
                        friendly = info.get("name") or info.get("description") or guid or "Unknown"
                        disp = f"{friendly} [{guid}]" if guid else friendly
                        if guid:
                            dev = f"\\Device\\NPF_{{{guid}}}"
                            self._iface_map[disp] = dev
                        names.append(disp)
                    if names:
                        return names
                except Exception:
                    pass

                # 3. pylibpcap（如果装了）
                try:
                    from pylibpcap.base import findalldevs  # type: ignore
                    devs = findalldevs()
                    names = []
                    self._iface_map.clear()
                    for dev, desc in devs:
                        disp = f"{desc} ({dev})" if desc else dev
                        self._iface_map[disp] = dev
                        names.append(disp)
                    if names:
                        return names
                except Exception:
                    pass

                # 4. Scapy 通用列表（可能为空）
                try:
                    _load_scapy()
                    return list(_get_if_list())
                except Exception:
                    return []

            # 非 Windows 平台
            _load_scapy()
            return list(_get_if_list())
        except Exception as e:
            self.error.emit(f"列出网卡失败: {e}")
            return []

    # ---------- 内部 ----------
    def _on_packet(self, pkt):
        """
        后台线程每收到一个包就回调这里；
        立即 emit Qt 信号，Qt 会线程安全地投递到主线程
        """
        self.packet_captured.emit(pkt)