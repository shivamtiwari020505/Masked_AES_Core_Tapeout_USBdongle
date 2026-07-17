#!/usr/bin/env python3
"""
Run a rough Yosys synthesis feasibility check for the masked AES core.

Default use:
    python3 check_synth.py

For a real SKY130 timing estimate, pass a Liberty file from your PDK:
    python3 check_synth.py --liberty $PDK_ROOT/sky130B/libs.ref/sky130_fd_sc_hd/lib/sky130_fd_sc_hd__tt_025C_1v80.lib

The generic no-Liberty mode is useful for fast construct and cell-count checks,
but critical-path delay is only meaningful after mapping to a real
standard-cell library. Cell count per Tiny Tapeout tile is an approximation;
the target shuttle's hardening workflow is authoritative for fit.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


TT_CELLS_PER_TILE_DEFAULT = 1000
TT_DEFAULT_TARGET_TILES = 2
TT_TILE_SHAPES = [
    (1, "1x1"),
    (2, "1x2"),
    (4, "2x2"),
    (6, "3x2"),
    (8, "4x2"),
    (12, "6x2"),
    (16, "8x2"),
]


def parse_tile_count(tile_value: str) -> int | None:
    cleaned = tile_value.strip().strip("\"'")
    if "x" in cleaned:
        left, right = cleaned.lower().split("x", 1)
        if left.isdigit() and right.isdigit():
            return int(left) * int(right)
        return None
    if cleaned.isdigit():
        return int(cleaned)
    return None


def read_target_tiles_from_info_yaml(path: str) -> int | None:
    info_path = Path(path)
    if not info_path.exists():
        return None

    for line in info_path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"\s*tiles\s*:\s*(.+?)\s*(?:#.*)?$", line)
        if match:
            return parse_tile_count(match.group(1))
    return None


def tile_shape_for_count(tile_count: int) -> str:
    for max_tiles, shape in TT_TILE_SHAPES:
        if tile_count <= max_tiles:
            return shape
    return "larger than the listed Tiny Tapeout shapes"


def find_default_liberty() -> str | None:
    pdk_root = os.environ.get("PDK_ROOT")
    if not pdk_root:
        return None

    candidates = [
        Path(pdk_root) / "sky130B/libs.ref/sky130_fd_sc_hd/lib/sky130_fd_sc_hd__tt_025C_1v80.lib",
        Path(pdk_root) / "sky130A/libs.ref/sky130_fd_sc_hd/lib/sky130_fd_sc_hd__tt_025C_1v80.lib",
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return None


def quote_yosys_path(path: str) -> str:
    return path.replace("\\", "/")


def build_yosys_script(args: argparse.Namespace) -> str:
    rtl_files = " ".join(quote_yosys_path(str(Path(f))) for f in args.rtl)

    if args.liberty:
        liberty = quote_yosys_path(str(Path(args.liberty)))
        return f"""
read_liberty -lib {liberty}
read_verilog -sv -DYOSYS {rtl_files}
hierarchy -check -top {args.top}
synth -top {args.top}
dfflibmap -liberty {liberty}
abc -liberty {liberty}
opt_clean
check
stat -top {args.top} -liberty {liberty}
"""

    return f"""
read_verilog -sv -DYOSYS {rtl_files}
hierarchy -check -top {args.top}
proc
opt
fsm
opt
memory
opt
techmap
opt
abc -fast
opt_clean
check
stat -top {args.top}
"""


def run_yosys(args: argparse.Namespace, script: str) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile("w", suffix=".ys", delete=False) as yosys_script:
        yosys_script.write(script)
        script_name = yosys_script.name

    try:
        try:
            proc = subprocess.run(
                [args.yosys, "-s", script_name],
                cwd=args.workdir,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
            return proc.returncode, proc.stdout
        except FileNotFoundError:
            return 127, f"ERROR: Yosys executable not found: {args.yosys}\n"
    finally:
        try:
            os.unlink(script_name)
        except OSError:
            pass


def parse_cell_count(yosys_log: str) -> int | None:
    matches = re.findall(r"Number of cells:\s+([0-9]+)", yosys_log)
    if not matches:
        return None
    return int(matches[-1])


def parse_cell_types(yosys_log: str) -> dict[str, int]:
    cells: dict[str, int] = {}
    for line in yosys_log.splitlines():
        match = re.match(r"\s+([A-Za-z_$][A-Za-z0-9_$\\.]+)\s+([0-9]+)\s*$", line)
        if match:
            name, count = match.groups()
            if name.startswith("$_") or name.startswith("$") or not name.startswith("\\"):
                cells[name] = cells.get(name, 0) + int(count)
    return cells


def parse_delay(yosys_log: str) -> str | None:
    patterns = [
        (r"Delay\s*=\s*([0-9.]+)\s*ps", "ps"),
        (r"Delay\s*=\s*([0-9.]+)\s*ns", "ns"),
        (r"critical path[^0-9]*([0-9.]+)\s*ps", "ps"),
        (r"critical path[^0-9]*([0-9.]+)\s*ns", "ns"),
        (r"Longest topological path[^0-9]*([0-9.]+)", "library units"),
    ]
    for pattern, units in patterns:
        match = re.search(pattern, yosys_log, flags=re.IGNORECASE | re.DOTALL)
        if match:
            return f"{float(match.group(1)):.3f} {units}"
    return None


def parse_issues(yosys_log: str, liberty_mode: bool) -> tuple[list[str], list[str]]:
    unsupported = []
    unmapped = []

    for line in yosys_log.splitlines():
        lowered = line.lower()
        if "unsupported" in lowered or "failed to" in lowered or "syntax error" in lowered:
            unsupported.append(line.strip())
        if "warning:" in lowered and "unsupported" in lowered:
            unsupported.append(line.strip())

    cells = parse_cell_types(yosys_log)
    if liberty_mode:
        for name, count in sorted(cells.items()):
            if name.startswith("$"):
                unmapped.append(f"{name}: {count}")

    return unsupported, unmapped


def recommended_tiles(total_cells: int | None, cells_per_tile: int) -> tuple[str, str]:
    if total_cells is None:
        return "unknown", "cell count was not parsed"

    tiles = max(1, math.ceil(total_cells / cells_per_tile))
    for max_tiles, shape in TT_TILE_SHAPES:
        if tiles <= max_tiles:
            return str(tiles), shape
    return str(tiles), "larger than the listed Tiny Tapeout shapes; reduce or partition"


def main() -> int:
    parser = argparse.ArgumentParser(description="Yosys feasibility check for masked AES.")
    parser.add_argument("--yosys", default="yosys", help="Yosys executable")
    parser.add_argument("--top", default="masked_aes_core", help="Top module")
    parser.add_argument(
        "--rtl",
        nargs="+",
        default=["masked_sbox.sv", "masked_aes_core.sv"],
        help="RTL files to synthesize",
    )
    parser.add_argument(
        "--liberty",
        help="Optional SKY130 Liberty file for mapped timing; if omitted, PDK_ROOT is checked",
    )
    parser.add_argument("--workdir", default=".", help="Run directory")
    parser.add_argument(
        "--cells-per-tile",
        type=int,
        default=TT_CELLS_PER_TILE_DEFAULT,
        help="Approximate Tiny Tapeout cells per tile",
    )
    parser.add_argument(
        "--target-tiles",
        type=int,
        help="Configured Tiny Tapeout tile target; default is read from info.yaml",
    )
    parser.add_argument(
        "--info-yaml",
        default="info.yaml",
        help="info.yaml path used to infer --target-tiles when not specified",
    )
    parser.add_argument("--report-dir", default="reports", help="Report output directory")
    args = parser.parse_args()
    if not args.liberty:
        args.liberty = find_default_liberty()
    if args.target_tiles is None:
        args.target_tiles = read_target_tiles_from_info_yaml(args.info_yaml)
    if args.target_tiles is None:
        args.target_tiles = TT_DEFAULT_TARGET_TILES

    script = build_yosys_script(args)
    returncode, yosys_log = run_yosys(args, script)

    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "synth_feasibility_yosys.log").write_text(yosys_log, encoding="utf-8")

    total_cells = parse_cell_count(yosys_log)
    critical_path = parse_delay(yosys_log) if args.liberty else None
    unsupported, unmapped = parse_issues(yosys_log, liberty_mode=bool(args.liberty))
    tile_count, tile_shape = recommended_tiles(total_cells, args.cells_per_tile)

    target_cells = args.target_tiles * args.cells_per_tile
    target_shape = tile_shape_for_count(args.target_tiles)
    if total_cells is None:
        recommendation = "run Yosys successfully to get a tile recommendation"
    elif total_cells > target_cells:
        if args.top == "masked_aes_core":
            recommendation = (
                f"full masked_aes_core exceeds the configured {args.target_tiles}-tile "
                "target; use the serialized Tiny Tapeout wrapper with external round keys"
            )
        else:
            recommendation = (
                f"{args.top} exceeds the configured {args.target_tiles}-tile target; "
                "reduce serialization further or request more TT tiles"
            )
    else:
        recommendation = f"{args.top} is within the configured {args.target_tiles}-tile target"

    summary = {
        "top": args.top,
        "yosys_returncode": returncode,
        "total_cells": total_cells,
        "target_tiles": args.target_tiles,
        "target_tt_shape": target_shape,
        "target_cells": target_cells,
        "fits_target_tiles": (total_cells is not None and total_cells <= target_cells),
        "critical_path_delay": critical_path or "N/A; pass --liberty for mapped SKY130 timing",
        "unsupported_constructs": unsupported,
        "unmapped_cells": unmapped,
        "recommended_tile_count": tile_count,
        "recommended_tt_shape": tile_shape,
        "recommendation": recommendation,
    }

    text_lines = [
        "Masked AES synthesis feasibility",
        f"Top: {summary['top']}",
        f"Yosys return code: {returncode}",
        f"Total cell count: {total_cells if total_cells is not None else 'unparsed'}",
        f"Configured tile target: {args.target_tiles} tiles ({target_shape})",
        f"Configured cell target: {target_cells} cells",
        f"Fits configured TT target: {summary['fits_target_tiles']}",
        f"Critical path delay: {summary['critical_path_delay']}",
        f"Recommended tile count: {tile_count}",
        f"Approximate TT shape: {tile_shape}",
        "Tile-fit note: this estimate is not a substitute for the target hardening flow.",
        f"Recommendation: {recommendation}",
        "",
        "Unsupported constructs / parser issues:",
    ]
    text_lines.extend(f"  - {item}" for item in unsupported[:20])
    if not unsupported:
        text_lines.append("  - none detected")

    text_lines.append("")
    text_lines.append("Unmapped cells:")
    text_lines.extend(f"  - {item}" for item in unmapped[:40])
    if not unmapped:
        if args.liberty:
            text_lines.append("  - none detected")
        else:
            text_lines.append("  - not checked in generic no-Liberty mode")

    report_text = "\n".join(text_lines) + "\n"
    (report_dir / "synth_feasibility.txt").write_text(report_text, encoding="utf-8")
    (report_dir / "synth_feasibility.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )

    print(report_text)
    if returncode != 0:
        print("Yosys failed. See reports/synth_feasibility_yosys.log.", file=sys.stderr)
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
