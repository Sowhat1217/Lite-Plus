#!/usr/bin/env python3
"""Plus 主控 / Web 跟版用的版本号、baseline 和冲突分类。"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys

BASELINE_KEYS = ("lite", "lite_agent", "lite_theme", "lite_web", "plus")


def parse_three(version: str) -> tuple[int, int, int]:
    parts = version.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise SystemExit(f"not a three-part version: {version}")
    return int(parts[0]), int(parts[1]), int(parts[2])


def bump_plus(plus: str, old_lite: str, new_lite: str) -> str:
    plus_v = parse_three(plus)
    old_v = parse_three(old_lite)
    new_v = parse_three(new_lite)
    if new_v <= old_v:
        raise SystemExit(f"Lite {new_lite} is not newer than baseline {old_lite}")
    if new_v[0] != old_v[0] or new_v[1] != old_v[1]:
        return f"{plus_v[0]}.{plus_v[1] + 1}.0"
    return f"{plus_v[0]}.{plus_v[1]}.{plus_v[2] + 1}"


def theme_git_ref(raw: str) -> str:
    value = (raw or "").strip()
    if not value:
        return "v1.2.9"
    if value in {"main", "master", "Snapshot"}:
        return value
    if value.startswith("v") or value.startswith("Snapshot-"):
        return value
    return "v" + value


def load_list(path: pathlib.Path) -> set[str]:
    names: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        item = line.strip().replace("\\", "/")
        if item and not item.startswith("#"):
            names.add(item)
    return names


def unmerged_files(repo: pathlib.Path) -> list[str]:
    out = subprocess.check_output(
        ["git", "diff", "--name-only", "--diff-filter=U"],
        cwd=repo,
        text=True,
    )
    return [line.strip().replace("\\", "/") for line in out.splitlines() if line.strip()]


def apply_ours(repo: pathlib.Path, ours_file: pathlib.Path, c_file: pathlib.Path) -> str:
    ours = load_list(ours_file)
    c_files = load_list(c_file)
    remaining = unmerged_files(repo)
    for name in remaining:
        if name in ours:
            subprocess.check_call(["git", "checkout", "--ours", "--", name], cwd=repo)
            subprocess.check_call(["git", "add", "--", name], cwd=repo)
    remaining = unmerged_files(repo)
    if not remaining:
        return "ok"
    if any(name in c_files for name in remaining):
        print("C-class conflicts: " + " ".join(remaining), file=sys.stderr)
        return "c-conflict"
    print("unresolved conflicts: " + " ".join(remaining), file=sys.stderr)
    return "other-conflict"


def validate_baseline(path: pathlib.Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    keys = tuple(sorted(data))
    if keys != BASELINE_KEYS:
        raise SystemExit(f"{path} keys must be {', '.join(BASELINE_KEYS)}, got: {', '.join(keys)}")
    for key in BASELINE_KEYS:
        if not str(data[key]).strip():
            raise SystemExit(f"{path} missing {key}")
    return data


def write_baseline(path: pathlib.Path, payload: dict) -> None:
    ordered = {key: payload[key] for key in ("plus", "lite", "lite_web", "lite_agent", "lite_theme")}
    path.write_text(json.dumps(ordered, indent=2) + "\n", encoding="utf-8")


def replace_once(path: pathlib.Path, pattern: str, repl: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    updated, count = re.subn(pattern, repl, text, count=1)
    if count != 1:
        raise SystemExit(f"{path}: expected 1 replacement for {label}, got {count}")
    path.write_text(updated, encoding="utf-8")


def rewrite_server(root: pathlib.Path, plus: str, lite: str, lite_web: str, lite_agent: str, lite_theme: str) -> None:
    replace_once(
        root / "utils" / "version.go",
        r'CurrentVersion = "[^"]*"',
        f'CurrentVersion = "{plus}"',
        "CurrentVersion",
    )
    write_baseline(
        root / "plus-baseline.json",
        {
            "plus": plus,
            "lite": lite,
            "lite_web": lite_web,
            "lite_agent": lite_agent,
            "lite_theme": lite_theme,
        },
    )


def rewrite_web(root: pathlib.Path, plus: str, lite: str, lite_web: str, lite_agent: str, lite_theme: str) -> None:
    pkg = root / "package.json"
    data = json.loads(pkg.read_text(encoding="utf-8"))
    data["name"] = "lite-plus-web"
    data["version"] = plus
    pkg.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    lock = root / "package-lock.json"
    if lock.exists():
        lock_data = json.loads(lock.read_text(encoding="utf-8"))
        lock_data["name"] = "lite-plus-web"
        lock_data["version"] = plus
        packages = lock_data.get("packages")
        if isinstance(packages, dict) and "" in packages:
            packages[""]["name"] = "lite-plus-web"
            packages[""]["version"] = plus
        lock.write_text(json.dumps(lock_data, indent=2) + "\n", encoding="utf-8")
    write_baseline(
        root / "plus-baseline.json",
        {
            "plus": plus,
            "lite": lite,
            "lite_web": lite_web,
            "lite_agent": lite_agent,
            "lite_theme": lite_theme,
        },
    )


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit(
            "usage: plus_follow.py bump|theme-ref|validate-baseline|rewrite-server|rewrite-web|apply-ours ..."
        )
    cmd = sys.argv[1]
    if cmd == "bump":
        if len(sys.argv) != 5:
            raise SystemExit("usage: plus_follow.py bump <plus> <old-lite> <new-lite>")
        sys.stdout.write(bump_plus(sys.argv[2], sys.argv[3], sys.argv[4]))
        return
    if cmd == "theme-ref":
        raw = sys.argv[2] if len(sys.argv) > 2 else ""
        sys.stdout.write(theme_git_ref(raw))
        return
    if cmd == "validate-baseline":
        if len(sys.argv) != 3:
            raise SystemExit("usage: plus_follow.py validate-baseline <plus-baseline.json>")
        data = validate_baseline(pathlib.Path(sys.argv[2]))
        json.dump(data, sys.stdout)
        return
    if cmd == "rewrite-server":
        if len(sys.argv) != 8:
            raise SystemExit("usage: plus_follow.py rewrite-server <root> <plus> <lite> <lite_web> <lite_agent> <lite_theme>")
        rewrite_server(pathlib.Path(sys.argv[2]), *sys.argv[3:8])
        return
    if cmd == "rewrite-web":
        if len(sys.argv) != 8:
            raise SystemExit("usage: plus_follow.py rewrite-web <root> <plus> <lite> <lite_web> <lite_agent> <lite_theme>")
        rewrite_web(pathlib.Path(sys.argv[2]), *sys.argv[3:8])
        return
    if cmd == "apply-ours":
        if len(sys.argv) != 5:
            raise SystemExit("usage: plus_follow.py apply-ours <repo> <ours.txt> <c.txt>")
        result = apply_ours(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]), pathlib.Path(sys.argv[4]))
        sys.stdout.write(result)
        if result != "ok":
            raise SystemExit(1)
        return
    raise SystemExit(f"unknown command: {cmd}")


if __name__ == "__main__":
    main()
