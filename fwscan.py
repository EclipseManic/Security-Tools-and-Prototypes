#!/usr/bin/env python3
"""fwscan - firewall deny-log port-scan analyzer.

Entry point. Run 'python fwscan.py --help' for usage.
"""

import sys

from fwlog.cli import main

if __name__ == "__main__":
    sys.exit(main())
