"""Test configuration — ensures imports work from any directory."""

import os
import sys

# Add project root to path so 'core' and 'collectors' packages are importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
