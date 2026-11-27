#!/usr/bin/env python3
"""Build the next numbered FlowGate release candidate from the current commit."""

import argparse
from pathlib import Path
import os
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
PREFIX = "flowgate-v"


def git(*args):
    return subprocess.check_output(
        ["git", *args], cwd=ROOT, text=True,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    ).splitlines()


def remote_tags(remote):
    """Return tag names and peeled targets without changing local refs."""
    url, = git("remote", "get-url", remote)
    github_ssh = re.fullmatch(r"(?:git@github\.com:|ssh://git@github\.com/)([\w.-]+/[\w.-]+)", url)
    pattern = f"refs/tags/{PREFIX}*"
    repository = "https://github.com/" + github_ssh[1] if github_ssh else remote
    try:
        lines = git("ls-remote", "--tags", repository, pattern)
    except subprocess.CalledProcessError:
        if not github_ssh:
            raise
        lines = git("ls-remote", "--tags", remote, pattern)
    tags = {}
    for line in lines:
        sha, ref = line.split("\t")
        name = ref.removeprefix("refs/tags/")
        if name.endswith("^{}"):
            tags[name[:-3]] = sha
        else:
            tags.setdefault(name, sha)
    return tags


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="0.1.0", help="release series (default 0.1.0)")
    parser.add_argument("--dry-run", action="store_true", help="print the tag without creating or building it")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", args.base):
        parser.error("--base must be X.Y.Z")
    pattern = re.compile(re.escape(f"{PREFIX}{args.base}-rc.") + r"([0-9]+)")
    try:
        if git("status", "--porcelain", "--untracked-files=no"):
            parser.exit(1, "Commit or restore tracked changes before preparing an RC.\n")
        source, = git("rev-parse", "HEAD")
        on_source = git("tag", "--list", f"{PREFIX}*", "--points-at", source)
        if len(on_source) > 1 or (on_source and not pattern.fullmatch(on_source[0])):
            parser.exit(1, "HEAD already has a different release tag: " + ", ".join(on_source) + "\n")

        candidates = set(git("tag", "--list", f"{PREFIX}*"))
        for remote in git("remote"):
            try:
                tags = remote_tags(remote)
            except subprocess.CalledProcessError:
                parser.exit(1, f"Could not check release tags on {remote}. Restore access and retry.\n")
            if on_source and on_source[0] in tags and tags[on_source[0]] != source:
                parser.exit(1, f"{on_source[0]} points to another commit on {remote}.\n")
            for name, target in tags.items():
                if target == source and name not in on_source:
                    parser.exit(1, f"HEAD already has tag {name} on {remote}. Fetch the tag and retry.\n")
            candidates.update(tags)

        if on_source:
            tag = on_source[0]
        else:
            used = (int(match[1]) for name in candidates if (match := pattern.fullmatch(name)))
            tag = f"{PREFIX}{args.base}-rc.{max(used, default=0) + 1}"
        print(f"{'Reuse' if on_source else 'Create'} {tag} at {source}", flush=True)
        if args.dry_run:
            return
        if git("rev-parse", "HEAD") != [source]:
            parser.exit(1, "HEAD changed while checking tags. Retry from the intended commit.\n")
        if not on_source:
            git("tag", "-a", tag, source, "-m", f"FlowGate {tag.removeprefix(PREFIX)}")
        subprocess.run(["make", "package"], cwd=ROOT, check=True)
        if git("rev-parse", "HEAD") != [source]:
            parser.exit(1, "HEAD changed while packaging. Inspect the build before using it.\n")
        archive = Path(subprocess.check_output(["make", "-s", "archive-path"], cwd=ROOT, text=True).strip())
        receipts = [archive.with_suffix(archive.suffix + ".sha256").name, "flowgate-release.py.sha256"]
        subprocess.run(["sha256sum", "-c", "--", *receipts], cwd=archive.parent, check=True)
        print(f"Archive, offline installer and receipts: {archive.parent}")
    except (OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Could not prepare the RC: {error}\n")


if __name__ == "__main__":
    main()
