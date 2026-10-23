#!/usr/bin/env python3
"""Run a build stage with elapsed-time progress and a retained diagnostic log."""
import argparse
import collections
import pathlib
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--step', type=int, required=True)
    parser.add_argument('--total', type=int, required=True)
    parser.add_argument('--label', required=True)
    parser.add_argument('--log', type=pathlib.Path, required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command or not 1 <= args.step <= args.total:
        parser.error('a command and a valid stage number are required')
    args.log.parent.mkdir(parents=True, exist_ok=True)
    tty = sys.stderr.isatty()
    started = time.monotonic()

    def show(done=False, failed=False):
        completed = args.step if done else args.step - 1
        bar = '#' * completed + '-' * (args.total - completed)
        state = 'FAILED' if failed else 'done' if done else 'running'
        line = f'[{bar}] {args.step}/{args.total} {args.label} — {state}, {int(time.monotonic()-started)}s'
        print(('\r\033[2K' if tty else '') + line, end='\n' if done or failed or not tty else '', file=sys.stderr, flush=True)

    with args.log.open('w') as log:
        show()
        try:
            child = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        except OSError as error:
            show(failed=True)
            print(error, file=sys.stderr)
            return 1
        try:
            while True:
                try:
                    code = child.wait(timeout=1 if tty else 15)
                    break
                except subprocess.TimeoutExpired:
                    show()
        except KeyboardInterrupt:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
            show(failed=True)
            return 130
    show(done=code == 0, failed=code != 0)
    if code:
        print(f'Build log: {args.log}', file=sys.stderr)
        with args.log.open(errors='replace') as log:
            print(''.join(collections.deque(log, maxlen=40)), file=sys.stderr, end='')
    return code if code >= 0 else 128 - code


if __name__ == '__main__':
    sys.exit(main())
