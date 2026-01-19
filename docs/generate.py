#!/usr/bin/env python3
"""Generate markdown content for docs and README.

Usage: uv run python docs/generate.py
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
README_PATH = REPO_ROOT / "README.md"


def readme_section(section_name: str, *, strip_heading: bool = True) -> str:
    """Extract a marked section from README.md.

    Sections are marked with:
    <!-- SECTION:name:START --> ... <!-- SECTION:name:END -->
    """
    content = README_PATH.read_text()
    start = f"<!-- SECTION:{section_name}:START -->"
    end = f"<!-- SECTION:{section_name}:END -->"

    start_idx = content.find(start)
    if start_idx == -1:
        raise ValueError(f"Section '{section_name}' not found")

    end_idx = content.find(end, start_idx)
    if end_idx == -1:
        raise ValueError(f"End marker for '{section_name}' not found")

    section = content[start_idx + len(start) : end_idx].strip()

    if strip_heading:
        section = re.sub(r"^#{1,3}\s+[^\n]+\n+", "", section, count=1)

    return section


def main() -> int:
    """Run markdown-code-runner on all markdown files."""
    docs_dir = REPO_ROOT / "docs"
    files = list(docs_dir.glob("*.md")) + [README_PATH]

    env = os.environ.copy()
    env["PYTHONPATH"] = f"{docs_dir}:{env.get('PYTHONPATH', '')}"

    print(f"Generating content for {len(files)} files...")
    for f in files:
        print(f"  {f.relative_to(REPO_ROOT)}")
        result = subprocess.run(
            ["markdown-code-runner", str(f)],
            env=env,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f"    ERROR: {result.stderr}")
            return 1

    print("Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
