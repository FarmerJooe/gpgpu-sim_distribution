#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan all .config files and write their paths to a Markdown file."
    )
    parser.add_argument(
        "-r",
        "--root",
        default=".",
        help="Root directory to scan (default: current directory).",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="config_files_summary.md",
        help="Output Markdown path (default: config_files_summary.md).",
    )
    return parser.parse_args()


def collect_config_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.config") if p.is_file())


def write_markdown(output_path: Path, root: Path, files: list[Path]) -> None:
    lines = [
        "# .config 文件路径汇总",
        "",
        f"- 扫描根目录: `{root.resolve()}`",
        f"- 文件总数: `{len(files)}`",
        "",
        "## 文件列表",
        "",
    ]

    if files:
        for file_path in files:
            rel = file_path.resolve().relative_to(root.resolve())
            lines.append(f"- `{rel.as_posix()}`")
    else:
        lines.append("未找到 `.config` 文件。")

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    args = parse_args()
    root = Path(args.root).resolve()
    output = Path(args.output).resolve()

    if not root.exists() or not root.is_dir():
        raise SystemExit(f"Invalid root directory: {root}")

    files = collect_config_files(root)
    write_markdown(output, root, files)
    print(f"Done. Found {len(files)} .config files.")
    print(f"Markdown written to: {output}")


if __name__ == "__main__":
    main()
