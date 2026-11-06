"""Lets `python3 -m hushhook` work the same as the hushhook command."""

import sys

from .cli import main

sys.exit(main())
