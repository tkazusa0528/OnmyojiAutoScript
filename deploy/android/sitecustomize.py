# 非 Windows 平台（Android proot 内的 Linux）下为 pywin32 提供占位实现。
#
# 由 rootfs 构建脚本安装成 venv 的 site-packages/sitecustomize.py，解释器启动时
# 经 site 机制自动导入，所以对 server.py 拉起的所有子进程（image / OCR 与
# 工具进程）都生效，无需在各个入口重复 import。
#
# 为什么需要：OAS 的设备层在**模块级**就 `from win32api import ...`、
# `from ctypes import wintypes`。Android 上装不了 pywin32，ctypes.wintypes 还会因
# VARIANT_BOOL 的 `_type_ = 'v'` 在导入时直接抛 ValueError，导致
# `import module.server.app` 失败、WebUI 起不来。而这些分支在 Android 上永远
# 不会被选中（设备后端固定 oasaos，桌面客户端与 window 截图走不到）。
#
# 占位只保证"可导入"：真的调用 Windows API 时直接抛 RuntimeError，不静默返回假值。
# 平台门控写在这里而不是 OAS_ANDROID，因为同一份 rootfs 在 Linux 上跑测试时
# 同样需要它；Windows 开发机完全不受影响。
#
# pywin32 stand-ins for the Linux runtime inside the Android proot. Installed as
# the venv's sitecustomize.py so every interpreter startup (server.py and the
# subprocesses it spawns) gets it. Imports succeed; real Windows API calls raise.

import ctypes
import sys
import types


class _Unavailable(types.ModuleType):
    """函数式 pywin32 模块：任意属性都是"调用即失败"的可调用对象。"""

    def __getattr__(self, name):
        if name.startswith('__'):
            raise AttributeError(name)

        def unavailable(*args, **kwargs):
            raise RuntimeError(f'{self.__name__}.{name} is only available on Windows')

        setattr(self, name, unavailable)
        return unavailable


class _Constants(types.ModuleType):
    """常量式 pywin32 模块（win32con）：任意属性都返回 0。"""

    def __getattr__(self, name):
        if name.startswith('__'):
            raise AttributeError(name)
        setattr(self, name, 0)
        return 0


class _WinTypes(types.ModuleType):
    """ctypes.wintypes 占位：任意属性都是 ctypes 类型，既能当类型也能实例化。"""

    def __getattr__(self, name):
        if name.startswith('__'):
            raise AttributeError(name)
        setattr(self, name, ctypes.c_void_p)
        return ctypes.c_void_p


def install() -> None:
    """注册 pywin32 与 ctypes.wintypes 的占位模块。"""
    for name in ('win32api', 'win32gui', 'win32process', 'win32ui', 'win32print',
                 'pywintypes', 'pythoncom'):
        sys.modules.setdefault(name, _Unavailable(name))
    sys.modules.setdefault('win32con', _Constants('win32con'))
    # 必须在任何 `from ctypes import wintypes` 之前占位：真模块在非 Windows 上导入即报错。
    wintypes = _WinTypes('ctypes.wintypes')
    sys.modules.setdefault('ctypes.wintypes', wintypes)
    ctypes.wintypes = wintypes


if sys.platform != 'win32':
    install()
