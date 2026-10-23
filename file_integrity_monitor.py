import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main():
    args = list(sys.argv[1:])
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    cmd = [sys.executable, "-m", "file_integrity.gui", *args]
    raise SystemExit(subprocess.call(cmd, cwd=str(HERE), env=env))


if __name__ == "__main__":
    main()
