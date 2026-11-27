#!/usr/bin/env python3
"""OAS-Android 热更新安全门禁（本地与 GitHub Actions 共用）。

校验四条容器红线：
1. 依赖冻结边界：requirements.txt（Linux 归一后）与 deploy/android/requirements-linux.lock 对齐。
2. Linux / PRoot 平台隔离：禁止在共享 module/ 与 tasks/ 中新增未受 IS_WINDOWS / win32 保护的 pywin32 导入。
3. 资源与多语言同步：tasks/**/assets.py 引用的 PNG 均存在，JSON 规则项均已生成进 assets.py，i18n JSON 合法。
4. 容器运行态烟雾检查（--mode full）：注入 sitecustomize + OAS_ANDROID=1，验证 server、ConfigModel 全任务参数与全部任务入口可正常导入。
"""

from __future__ import annotations

import argparse
import ast
import importlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOCK_FILE = ROOT / 'deploy/android/requirements-linux.lock'

WIN32_MODULES = frozenset({
    'win32api', 'win32con', 'win32gui', 'win32print',
    'win32process', 'win32ui', 'pywintypes', 'pythoncom',
})

# 上游历史遗留未清理的无用死规则引用（不阻塞基线，禁止新增缺失图片）
LEGACY_MISSING_PNGS = frozenset({
    'tasks/DailyTrifles/summonRecall/sm_sm_confirm_2.png',
    'tasks/KekkaiActivation/a/a_a_cards_realm.png',
    'tasks/MetaDemon/md/md_share_demon.png',
    'tasks/MetaDemon/md/md_fight_share_demon.png',
    'tasks/MysteryShop/ms/ms_ms_taiko_6.png',
    'tasks/MysteryShop/ms/ms_ms_exp.png',
    'tasks/MysteryShop/ms/ms_ms_check_taiko_6.png',
    'tasks/MysteryShop/ms/ms_ms_check_exp.png',
    'tasks/WantedQuests/invite/invite_wq_friend_1.png',
    'tasks/WantedQuests/invite/invite_wq_friend_2.png',
    'tasks/WantedQuests/invite/invite_wq_friend_3.png',
    'tasks/WantedQuests/invite/invite_wq_friend_4.png',
    'tasks/WantedQuests/invite/invite_wq_friend_5.png',
})

# 仅桌面/Windows 截图控制分支才会进入的隔离模块（oasaos 永远不走这些分支）
WIN32_ALLOWLIST = frozenset({
    'module/device/handle.py',
    'module/device/method/desktop_impl.py',
    'module/device/method/windows_impl.py',
    'module/device/platform2/platform_windows.py',
    'module/gui/utils.py',
})

REQ_NAME_RE = re.compile(r'^([A-Za-z0-9_.-]+)\s*(==[^\s#;]+)?')
RULE_FILE_RE = re.compile(r'file="([^"]+\.png)"')
RULE_ATTR_RE = re.compile(r'^\s+([IOCSL]_[A-Z0-9_]+)\s*=', re.MULTILINE)

JSON_PREFIX_MAP = {
    'image.json': 'I_',
    'ocr.json': 'O_',
    'click.json': 'C_',
    'swipe.json': 'S_',
    'long_click.json': 'L_',
    'list.json': 'L_',
}


def _parse_req_pins(path: Path, linux_normalize: bool = False) -> dict[str, str]:
    pins: dict[str, str] = {}
    for raw in path.read_text(encoding='utf-8').splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        if linux_normalize:
            if line.lower().startswith('pywin32'):
                continue
            if line.startswith('opencv-python=='):
                line = line.replace('opencv-python==', 'opencv-contrib-python-headless==', 1)
        m = REQ_NAME_RE.match(line)
        if not m:
            continue
        pkg = m.group(1).lower().replace('_', '-')
        ver = m.group(2) or ''
        pins[pkg] = ver
    return pins


def check_deps_freeze() -> list[str]:
    errors: list[str] = []
    if not LOCK_FILE.is_file():
        return [f'缺少容器依赖基线文件: {LOCK_FILE.relative_to(ROOT)}']

    locked = _parse_req_pins(LOCK_FILE, linux_normalize=False)
    current = _parse_req_pins(ROOT / 'requirements.txt', linux_normalize=True)

    for pkg, ver in sorted(current.items()):
        if pkg not in locked:
            errors.append(
                f'依赖越界: requirements.txt 新增了容器未预装的包 {pkg}{ver} '
                f'（需先更新 OAS-Android rootfs/seeds/requirements-linux.txt 重编 APK，再同步 {LOCK_FILE.relative_to(ROOT)}）'
            )
        elif ver and locked[pkg] and ver != locked[pkg]:
            errors.append(
                f'依赖版本变更: {pkg} 当前 {ver} != 容器基线 {locked[pkg]} '
                f'（确认双架构 wheel 可用并重编 rootfs 后再同步 {LOCK_FILE.relative_to(ROOT)}）'
            )

    req_in = _parse_req_pins(ROOT / 'requirements-in.txt', linux_normalize=True)
    for pkg in sorted(req_in):
        if pkg == 'opencv-python':
            pkg = 'opencv-contrib-python-headless'
        if pkg not in locked:
            errors.append(f'依赖越界: requirements-in.txt 包含容器基线外的包 {pkg}')
    return errors


def _is_platform_guard(test: ast.AST) -> bool:
    src = ast.unparse(test)
    return 'win32' in src or 'IS_WINDOWS' in src


def _collect_unguarded_win32_imports(tree: ast.AST) -> list[tuple[int, str]]:
    hits: list[tuple[int, str]] = []

    def visit(node: ast.AST, guarded: bool) -> None:
        if isinstance(node, ast.If) and _is_platform_guard(node.test):
            # 粗粒度识别 if sys.platform == 'win32' / if not IS_WINDOWS 分支
            src = ast.unparse(node.test)
            body_guarded = ('!=' not in src and 'not ' not in src) or guarded
            else_guarded = ('!=' in src or 'not ' in src) or guarded
            for child in node.body:
                visit(child, body_guarded)
            for child in node.orelse:
                visit(child, else_guarded)
            return

        if not guarded:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split('.')[0]
                    if top in WIN32_MODULES or alias.name == 'ctypes.wintypes':
                        hits.append((node.lineno, alias.name))
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ''
                top = mod.split('.')[0]
                if top in WIN32_MODULES or mod == 'ctypes.wintypes':
                    hits.append((node.lineno, mod))
                elif mod == 'ctypes' and any(a.name == 'wintypes' for a in node.names):
                    hits.append((node.lineno, 'ctypes.wintypes'))

        for child in ast.iter_child_nodes(node):
            visit(child, guarded)

    visit(tree, False)
    return hits


def check_win32_boundaries() -> list[str]:
    errors: list[str] = []
    for base in ('module', 'tasks'):
        for py_file in sorted((ROOT / base).rglob('*.py')):
            rel = py_file.relative_to(ROOT).as_posix()
            if rel in WIN32_ALLOWLIST or '/__pycache__/' in rel:
                continue
            try:
                tree = ast.parse(py_file.read_text(encoding='utf-8'), filename=rel)
            except SyntaxError as exc:
                errors.append(f'语法错误: {rel}:{exc.lineno}: {exc.msg}')
                continue
            for lineno, mod in _collect_unguarded_win32_imports(tree):
                errors.append(
                    f'未受保护的 Windows 专属导入: {rel}:{lineno} 导入了 {mod} '
                    f'（Android PRoot 调用会抛 RuntimeError，请加 IS_WINDOWS / sys.platform == "win32" 守卫）'
                )
    return errors


def check_assets_and_i18n() -> list[str]:
    errors: list[str] = []

    for lang_file in ('assets/i18n/zh-CN.json', 'assets/i18n/en-US.json'):
        p = ROOT / lang_file
        if not p.is_file():
            errors.append(f'缺少多语言词表: {lang_file}')
            continue
        try:
            data = json.loads(p.read_text(encoding='utf-8'))
            if not isinstance(data, dict) or not data:
                errors.append(f'多语言词表为空或非 JSON 对象: {lang_file}')
        except json.JSONDecodeError as exc:
            errors.append(f'多语言 JSON 解析失败: {lang_file}:{exc.lineno}: {exc.msg}')

    for assets_py in sorted((ROOT / 'tasks').glob('*/assets.py')):
        rel_assets = assets_py.relative_to(ROOT).as_posix()
        text = assets_py.read_text(encoding='utf-8')
        for img_rel in RULE_FILE_RE.findall(text):
            cleaned = img_rel.removeprefix('./')
            if cleaned in LEGACY_MISSING_PNGS:
                continue
            if not (ROOT / cleaned).is_file():
                errors.append(f'资源图片缺失: {rel_assets} 引用了不存在的 {img_rel}')

        declared_attrs = set(RULE_ATTR_RE.findall(text))
        task_dir = assets_py.parent
        for json_file in sorted(task_dir.rglob('*.json')):
            prefix = JSON_PREFIX_MAP.get(json_file.name)
            if prefix is None:
                continue
            rel_json = json_file.relative_to(ROOT).as_posix()
            try:
                items = json.loads(json_file.read_text(encoding='utf-8'))
            except json.JSONDecodeError as exc:
                errors.append(f'资源 JSON 损坏: {rel_json}:{exc.lineno}: {exc.msg}')
                continue
            if not isinstance(items, list):
                continue
            for entry in items:
                if not isinstance(entry, dict):
                    continue
                item_name = entry.get('itemName')
                expected_attr = f'{prefix}{str(item_name).upper()}' if item_name else ''
                if expected_attr and expected_attr not in declared_attrs:
                    errors.append(
                        f'资源未同步: {rel_json} 中的 itemName="{item_name}" ({expected_attr}) 未出现在 {rel_assets} '
                        f'（请运行 dev_tools/assets_extract.py 同步）'
                    )
                if json_file.name == 'image.json' and entry.get('imageName'):
                    img_name = str(entry['imageName'])
                    candidate = (json_file.parent / img_name).relative_to(ROOT).as_posix()
                    if candidate not in LEGACY_MISSING_PNGS and not (json_file.parent / img_name).is_file():
                        errors.append(f'模板图片缺失: {rel_json} 引用的 {img_name} 不在同目录中')

    return errors


def check_runtime_imports() -> list[str]:
    errors: list[str] = []
    os.environ['OAS_ANDROID'] = '1'
    os.environ['OAS_ANDROID_HOST'] = '1'

    shim_file = ROOT / 'deploy/android/sitecustomize.py'
    if shim_file.is_file() and sys.platform != 'win32':
        spec = importlib.util.spec_from_file_location('_oas_android_sitecustomize', shim_file)
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if hasattr(mod, 'install'):
                mod.install()
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))

    os.chdir(ROOT)
    try:
        importlib.import_module('module.server.app')
    except Exception as exc:
        errors.append(f'导入 module.server.app 失败: {type(exc).__name__}: {exc}')
        return errors

    try:
        from module.config.config_model import ConfigModel
        model = ConfigModel('template')
        for field_name in ConfigModel.model_fields:
            if field_name == 'config_name':
                continue
            task_cmd = ConfigModel.type(field_name)
            args = model.script_task(task_cmd)
            if not isinstance(args, dict):
                errors.append(f'ConfigModel.script_task({task_cmd!r}) 返回类型异常: {type(args)}')
    except Exception as exc:
        errors.append(f'ConfigModel("template") 参数生成校验失败: {type(exc).__name__}: {exc}')

    for kind in ('config.py', 'script_task.py'):
        for py_file in sorted((ROOT / 'tasks').glob(f'*/{kind}')):
            mod_name = '.'.join(py_file.relative_to(ROOT).with_suffix('').parts)
            try:
                importlib.import_module(mod_name)
            except Exception as exc:
                errors.append(f'任务模块导入失败 ({mod_name}): {type(exc).__name__}: {exc}')

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--mode',
        choices=('static', 'full'),
        default='static',
        help='static: 依赖/win32边界/资源/i18n 静态检查；full: 额外执行容器运行态导入与模板生成烟雾校验',
    )
    args = parser.parse_args()

    checks = [
        ('1/3 依赖冻结边界检查', check_deps_freeze),
        ('2/3 Windows/PRoot 隔离检查', check_win32_boundaries),
        ('3/3 资源与 i18n 一致性检查', check_assets_and_i18n),
    ]
    if args.mode == 'full':
        checks = [
            ('1/4 依赖冻结边界检查', check_deps_freeze),
            ('2/4 Windows/PRoot 隔离检查', check_win32_boundaries),
            ('3/4 资源与 i18n 一致性检查', check_assets_and_i18n),
            ('4/4 容器运行态导入与 ConfigModel 烟雾校验', check_runtime_imports),
        ]

    all_errors: list[str] = []
    for title, fn in checks:
        errs = fn()
        status = 'PASS' if not errs else f'FAIL ({len(errs)})'
        print(f'[{status}] {title}')
        for e in errs:
            print(f'  - {e}')
            if os.environ.get('GITHUB_ACTIONS') == 'true':
                safe_msg = str(e).replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
                print(f'::error title={title}::{safe_msg}')
        all_errors.extend(errs)

    if all_errors:
        print(f'\n热更安全门禁未通过，共 {len(all_errors)} 项问题。', file=sys.stderr)
        return 1

    print('\n热更安全门禁全部通过！')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as _exc:
        import traceback
        traceback.print_exc()
        if os.environ.get('GITHUB_ACTIONS') == 'true':
            print(f'::error title=Unhandled::{type(_exc).__name__}: {_exc}')
        sys.exit(1)
