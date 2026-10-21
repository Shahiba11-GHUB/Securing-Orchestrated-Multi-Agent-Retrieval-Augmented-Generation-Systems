"""CLI for generating reproducible midterm reporting artifacts."""

from __future__ import annotations

import argparse

from src.attack_harness import generate_midterm_artifacts


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate midterm reporting artifacts.")
    parser.add_argument(
        "--dataset-root",
        default="BIPIA_EmailQA_20_Pairs",
        help="Path to BIPIA fixture root.",
    )
    parser.add_argument(
        "--output-dir",
        default="results/midterm",
        help="Output folder for generated protocol/results artifacts.",
    )
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    artifacts = generate_midterm_artifacts(
        dataset_root=args.dataset_root,
        output_dir=args.output_dir,
    )
    for name, path in artifacts.items():
        print(f"{name}: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
