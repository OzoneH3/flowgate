#!/usr/bin/env python3
"""Desktop accessibility adapter for the same inventory plan on Linux."""
import ctypes
import json
import os
from pathlib import Path
import re
import sys
import subprocess
import tempfile
import time
from collections import Counter

import gi

gi.require_version("Atspi", "2.0")
from gi.repository import Atspi, Gio, GLib


def role(node):
    return node.get_role_name().replace(" ", "-")


def walk(node, ancestors=()):
    yield node, ancestors
    for i in range(node.get_child_count()):
        child = node.get_child_at_index(i)
        if child:
            yield from walk(child, (*ancestors, node))


def visible(node):
    states = node.get_state_set()
    return states.contains(Atspi.StateType.SHOWING) and not states.contains(Atspi.StateType.DEFUNCT)


def locate(locator):
    names = locator.get("names", [])
    roles = locator.get("roles", [])
    under = locator.get("under")
    pid = locator.get("pid")
    children = set(locator.get("childNames", []))
    heading = locator.get("heading")
    descendants = set(locator.get("descendantNames", []))
    candidates = []
    for node, ancestors in walk(Atspi.get_desktop(0)):
        if not visible(node) or (roles and role(node) not in roles):
            continue
        if names and not any(re.fullmatch(pattern, node.get_name() or "") for pattern in names):
            continue
        if under and not any(re.fullmatch(under, parent.get_name() or "") for parent in ancestors):
            continue
        if pid and node.get_process_id() != pid:
            continue
        if children:
            names_found = {child.get_name() for i in range(node.get_child_count())
                           if (child := node.get_child_at_index(i))}
            if not children <= names_found:
                continue
        if heading and not any(role(child) == "heading" and child.get_name() == heading and visible(child)
                               for child, _parents in walk(node)):
            continue
        if descendants:
            found = {child.get_name() for child, _parents in walk(node) if visible(child)}
            if not descendants <= found:
                continue
        candidates.append(node)
    if len(candidates) != 1:
        reported = {key: value for key, value in locator.items() if key != "pid"}
        raise RuntimeError(f"Expected one accessible target for {reported}, found {len(candidates)}")
    return candidates[0]


def emit(root):
    controls, issues = [], []
    ids = {}
    counts = Counter()
    for node, ancestors in walk(root):
        if not visible(node):
            continue
        parent = next((ids[id(parent)] for parent in reversed(ancestors) if id(parent) in ids), None)
        name, kind = node.get_name() or "", role(node)
        attrs = node.get_attributes() or {}
        semantic = attrs.get("id") or attrs.get("accessible-id") or kind
        key = f"{parent}/{semantic}" if parent else semantic
        counts[key] += 1
        identity = key if counts[key] == 1 else f"{key}#{counts[key]}"
        ids[id(node)] = identity
        states = node.get_state_set()
        has = states.contains
        # Menus and dialog controls expose their labels through the accessible
        # name. Text-bearing accessibles expose the rendered string via Text.
        get_text = node.get_text_iface()
        try:
            text = " ".join(get_text.get_text(0, -1).split()) if get_text else name
        except Exception as error:
            text = None
            issues.append({"kind": "unreadable", "id": identity, "message": str(error)})
        control = dict(id=identity, parentId=parent, role=kind, text=text)
        if name and name != text:
            control["accessibleName"] = name
        if has(Atspi.StateType.SENSITIVE) or kind in {"push-button", "check-box", "radio-button", "menu-item",
                                                    "check-menu-item", "radio-menu-item", "toggle-button", "entry"}:
            control["enabled"] = bool(has(Atspi.StateType.SENSITIVE) and has(Atspi.StateType.ENABLED))
        if has(Atspi.StateType.CHECKABLE) or kind in {"check-box", "radio-button", "check-menu-item", "radio-menu-item"}:
            control["checked"] = "mixed" if has(Atspi.StateType.INDETERMINATE) else bool(has(Atspi.StateType.CHECKED))
        if has(Atspi.StateType.EXPANDABLE):
            control["expanded"] = bool(has(Atspi.StateType.EXPANDED))
        if has(Atspi.StateType.SELECTABLE):
            control["selected"] = bool(has(Atspi.StateType.SELECTED))
        value = node.get_value_iface()
        if value:
            try:
                control["value"] = value.get_current_value()
            except Exception as error:
                control["value"] = None
                issues.append({"kind": "unreadable", "id": identity, "message": str(error)})
        if kind in {"password-text", "password-entry"}:
            control["text"] = None
            control.pop("value", None)
        controls.append(control)
    return controls, issues


def keyboard(keys):
    xkb = ctypes.CDLL("libxkbcommon.so.0")
    xkb.xkb_keysym_from_name.argtypes = [ctypes.c_char_p, ctypes.c_int]
    xkb.xkb_keysym_from_name.restype = ctypes.c_uint
    for key in keys:
        symbol = xkb.xkb_keysym_from_name(key.encode(), 0)
        if not symbol or not Atspi.generate_keyboard_event(symbol, None, Atspi.KeySynthType.SYM):
            raise RuntimeError(f"Desktop accessibility could not send {key}")
        time.sleep(0.1)



def observe_kwin(pid, scratch):
    """Read the compositor's clients without changing focus, visibility or geometry."""
    session = Gio.bus_get_sync(Gio.BusType.SESSION)
    if not session.call_sync('org.freedesktop.DBus', '/org/freedesktop/DBus',
                             'org.freedesktop.DBus', 'NameHasOwner', GLib.Variant('(s)', ('org.kde.KWin',)),
                             None, Gio.DBusCallFlags.NONE, 1000, None).unpack()[0]:
        return {"available": False}
    interface = 'org.flowgate.Inventory'
    object_path = '/org/flowgate/Inventory'
    signature = '<node><interface name="org.flowgate.Inventory"><method name="Report"><arg type="s" direction="in"/></method></interface></node>'
    result = []
    loop = GLib.MainLoop()

    def report(_conn, _sender, _path, _interface, _method, params, invocation):
        result.extend(json.loads(params.unpack()[0]))
        invocation.return_value(None)
        loop.quit()

    handle = session.register_object(object_path, Gio.DBusNodeInfo.new_for_xml(signature).interfaces[0], report)
    name = 'flowgate-inventory-' + str(os.getpid())
    source = """
const matches = workspace.windowList().filter(w => w.pid === PID || String(w.caption).includes('FlowGate')).map(w => ({
  pid: w.pid, caption: w.caption, resourceName: String(w.resourceName),
  resourceClass: String(w.resourceClass), desktopFileName: w.desktopFileName,
  internalId: String(w.internalId), normalWindow: w.normalWindow, active: w.active,
  hidden: w.hidden, minimized: w.minimized, onCurrentDesktop: w.onCurrentDesktop,
  shown: typeof w.isShown === 'function' ? w.isShown() : null
}));
callDBus(BUS, '/org/flowgate/Inventory', 'org.flowgate.Inventory', 'Report', JSON.stringify(matches));
""".replace('PID', str(pid)).replace('BUS', json.dumps(session.get_unique_name()))

    def call(path, method, *args):
        return subprocess.check_output(['gdbus', 'call', '--session', '--dest', 'org.kde.KWin',
                                        '--object-path', path, '--method', method, *args],
                                       text=True, stderr=subprocess.STDOUT, timeout=3).strip()

    script = None
    try:
        with tempfile.TemporaryDirectory(prefix='kwin-', dir=scratch) as directory:
            file = Path(directory) / 'read.js'
            file.write_text(source)
            reply = call('/Scripting', 'org.kde.kwin.Scripting.loadScript', str(file), name)
            match = re.fullmatch(r'\((?:int32 )?(\d+),\)', reply)
            if not match:
                return {"available": True, "error": "KWin could not load read-only observer: " + reply}
            script = match.group(1)
            call('/Scripting/Script' + script, 'org.kde.kwin.Script.run')
            deadline = GLib.timeout_add(1500, lambda: (loop.quit(), False)[1])
            loop.run()
            if result:
                GLib.source_remove(deadline)
            return {"available": True, "windows": result}
    finally:
        if script:
            try:
                call('/Scripting', 'org.kde.kwin.Scripting.unloadScript', name)
            except (subprocess.SubprocessError, OSError):
                pass
        session.unregister_object(handle)


def diagnose(request):
    pid = request["pid"]
    keys = ("XDG_SESSION_ID", "XDG_SESSION_TYPE", "XDG_CURRENT_DESKTOP", "DISPLAY",
            "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS", "AT_SPI_BUS_ADDRESS")
    env = {key: os.environ[key] for key in keys if key in os.environ}
    application = Path(f'/proc/{pid}')
    process = {"pid": pid, "uid": application.stat().st_uid, "executable": os.readlink(application / 'exe')}
    status = subprocess.run(['gdbus', 'call', '--session', '--dest', 'org.a11y.Bus',
                             '--object-path', '/org/a11y/bus', '--method', 'org.freedesktop.DBus.Properties.GetAll',
                             'org.a11y.Status'], text=True, capture_output=True, timeout=3)
    bus = subprocess.run(['gdbus', 'call', '--session', '--dest', 'org.a11y.Bus',
                          '--object-path', '/org/a11y/bus', '--method', 'org.a11y.Bus.GetAddress'],
                         text=True, capture_output=True, timeout=3)
    apps = []
    desktop = Atspi.get_desktop(0)
    for i in range(desktop.get_child_count()):
        app = desktop.get_child_at_index(i)
        if not app:
            continue
        entry = {"pid": app.get_process_id(), "role": role(app), "name": app.get_name(),
                 "showing": visible(app)}
        if entry["pid"] == pid:
            entry["children"] = [
                {"pid": child.get_process_id(), "role": role(child), "name": child.get_name(),
                 "showing": visible(child)}
                for i in range(app.get_child_count()) if (child := app.get_child_at_index(i))
            ]
        apps.append(entry)
    try:
        kwin = observe_kwin(pid, request['scratch'])
    except (GLib.Error, subprocess.SubprocessError, OSError) as error:
        kwin = {"available": True, "error": str(error)}
    return {"session": env, "process": process, "kwin": kwin,
            "atspi": {"status": status.stdout.strip(), "bus": bus.stdout.strip(),
                      "error": (status.stderr + bus.stderr).strip(), "applications": apps}}

def main():
    request = json.load(sys.stdin)
    Atspi.init()
    Atspi.set_timeout(1500, 2000)
    op = request["op"]
    if op == "diagnose":
        return diagnose(request)
    if op == "key":
        keyboard(request["keys"])
        return {"ok": True}
    node = locate(request["locator"])
    if op == "showing":
        return {"name": node.get_name(), "role": role(node), "showing": True}
    if op == "focus":
        component = node.get_component_iface()
        if not component or not component.grab_focus():
            raise RuntimeError("Accessible does not accept keyboard focus")
        node.clear_cache()
        if not node.get_state_set().contains(Atspi.StateType.FOCUSED):
            raise RuntimeError("Desktop did not confirm keyboard focus")
        return {"ok": True}
    if op != "capture":
        raise RuntimeError(f"Unknown desktop accessibility operation {op}")
    controls, issues = emit(node)
    return {"controls": controls, "issues": issues}


if __name__ == "__main__":
    try:
        print(json.dumps(main(), ensure_ascii=False, allow_nan=False))
    except Exception as error:
        print(json.dumps({"error": str(error)}))
        sys.exit(1)
