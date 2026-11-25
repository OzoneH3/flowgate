#!/usr/bin/env python3
"""Desktop accessibility adapter for the same inventory plan on Linux."""
import ctypes
import json
import re
import sys
import time
from collections import Counter

import gi

gi.require_version("Atspi", "2.0")
from gi.repository import Atspi


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
        candidates.append(node)
    if len(candidates) != 1:
        raise RuntimeError(f"Expected one accessible target for {locator}, found {len(candidates)}")
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


def main():
    request = json.load(sys.stdin)
    Atspi.init()
    Atspi.set_timeout(1500, 2000)
    op = request["op"]
    if op == "key":
        keyboard(request["keys"])
        return {"ok": True}
    node = locate(request["locator"])
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
