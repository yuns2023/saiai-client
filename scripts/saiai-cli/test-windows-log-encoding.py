#!/usr/bin/env python3
"""Read UTF-8 service errors through the actual Windows CLI, with no network."""
import argparse
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import threading


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    binary = parser.parse_args().binary.resolve(strict=True)
    if os.name != 'nt':
        parser.error('this check requires Windows')
    # Character escapes also let Windows PowerShell 5.1 runners use this source
    # without depending on the checkout's BOM or console code page.
    expected = '\u8fde\u63a5\u88ab\u5bf9\u7aef\u5173\u95ed (os error 10054)'
    with tempfile.TemporaryDirectory(prefix='saiai-log-encoding-') as directory:
        home = Path(directory)
        (home / 'saiai.log').write_text(expected + '\n', encoding='utf-8')
        process = subprocess.Popen(
            [str(binary), 'logs'], env={**os.environ, 'SAIAI_HOME': str(home)},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW,
        )
        lines: queue.Queue[bytes] = queue.Queue()

        def read() -> None:
            assert process.stdout is not None
            lines.put(process.stdout.readline())

        reader = threading.Thread(target=read, daemon=True)
        reader.start()
        try:
            actual = lines.get(timeout=20).decode('utf-8', errors='strict').rstrip('\r\n')
            if actual != expected:
                raise AssertionError('saiai logs did not preserve the UTF-8 error text')
        finally:
            # Kill only the synthetic CLI and its PowerShell log follower.
            subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=10, check=False)
            process.wait(timeout=10)
            reader.join(timeout=2)
            if process.stdout is not None:
                process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()
    print('Windows CLI UTF-8 log reading passed; zero provider/model requests')


if __name__ == '__main__':
    main()
