import sys
from pathlib import Path

# Make the repository root importable so tests can `import dh_key_exchange`.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
