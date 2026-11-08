"""Independent protected check for the executable A2 demo fixture."""

from __future__ import annotations

import runpy
import sys


def main() -> int:
    namespace = runpy.run_path(sys.argv[1])
    slugify = namespace["slugify"]
    expected = {
        "  Hello World  ": "hello-world",
        "Already-Slugged": "already-slugged",
        "two words": "two-words",
    }
    for value, wanted in expected.items():
        observed = slugify(value)
        if observed != wanted:
            print(f"expected {wanted!r}, got {observed!r}", file=sys.stderr)
            return 1
    print("a2_fixture_check=ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
