"""Command line entry point for rpkit.

The CLI is how most people meet a protocol library, so it is part of the public surface and
gets the same typing and testing discipline as the rest of the package.
"""

from __future__ import annotations

import argparse
import sys

USAGE = """\
Examples:
  rpkit validate 1.2.3.0/24 64512 -- state and every reason behind it"""


def build_parser():
    return argparse.ArgumentParser(
        prog="rpkit",
        description="RPKI relying party: RRDP and repository fetch, CMS signed objects, manifests, validation paths, ROA extraction and SLURM filtering",
        epilog=USAGE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )


def main(argv=None):
    """Parse arguments, then refuse to pretend the protocol works.

    Exiting non-zero is the correct behaviour for a shell. A CLI that printed a friendly
    banner and exited 0 would be indistinguishable from one that actually did something.
    """
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_usage(sys.stderr)
    print("rpkit: no protocol behaviour is implemented yet; see ROADMAP.md", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
