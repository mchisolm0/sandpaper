#!/usr/bin/env python3
"""Hook entry point. Hooks run on every tool call, and importing friction instead of running it as a script lets
Python reuse its cached bytecode."""

import friction

friction.run()
