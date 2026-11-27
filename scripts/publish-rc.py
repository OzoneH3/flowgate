#!/usr/bin/env python3
"""Stage or publish the exact FlowGate RC files approved in testing."""

import argparse
import filecmp
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[1]
REPO = "OzoneH3/flowgate"
REMOTE = f"https://github.com/{REPO}.git"
GH_ENV = {**os.environ, "GH_PROMPT_DISABLED": "1", "GIT_TERMINAL_PROMPT": "0"}
GIT = ["git", "-c", "credential.helper=", "-c", "credential.helper=!gh auth git-credential"]


def run(*args, stdout=None):
    return subprocess.run(args, cwd=ROOT, env=GH_ENV, check=True, stdout=stdout).stdout


def output(*args):
    return run(*args, stdout=subprocess.PIPE).decode().strip()


def api(*args):
    return json.loads(output("gh", "api", "--hostname", "github.com", *args))


def rows(endpoint):
    return [row for page in api("--paginate", "--slurp", endpoint) for row in page]


def verify_pair(directory, digests):
    for name, expected in digests.items():
        with (directory / name).open("rb") as file:
            digest = hashlib.sha256()
            for block in iter(lambda: file.read(1024 * 1024), b""):
                digest.update(block)
        if digest.hexdigest() != expected:
            raise ValueError(f"{name} does not match the tested SHA-256")
        if (directory / (name + ".sha256")).read_bytes() != f"{expected}  {name}\n".encode():
            raise ValueError(f"{name}.sha256 does not match the tested SHA-256 and filename")


def package_identity(archive):
    with tarfile.open(archive, "r:gz") as bundle:
        member = bundle.getmember("release.json")
        if not member.isfile() or member.size > 1024 * 1024:
            raise ValueError("Invalid archive manifest")
        with bundle.extractfile(member) as data:
            manifest = json.load(data)
    version, source = manifest["version"], manifest["source"]
    if not (isinstance(version, str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+", version)
            and isinstance(source, str) and re.fullmatch(r"[0-9a-f]{40}", source)):
        raise ValueError("Expected a numbered RC archive with a full source SHA")
    release = f"{version}-{source[:12]}"
    if manifest["release"] != release or archive.name != f"flowgate-{release}-linux-x86_64.tar.gz":
        raise ValueError("Archive filename and manifest release ID disagree")
    return version, source


def remote_target(tag):
    ref = f"refs/tags/{tag}"
    refs = {}
    for line in output(*GIT, "ls-remote", "--tags", REMOTE, ref, ref + "^{}").splitlines():
        sha, name = line.split("\t")
        refs[name] = sha
    return refs.get(ref + "^{}", refs.get(ref))


def release_for(tag):
    matches = [item for item in rows(f"repos/{REPO}/releases?per_page=100") if item["tag_name"] == tag]
    if len(matches) > 1:
        raise ValueError(f"Multiple GitHub releases match {tag}. Inspect them before continuing.")
    return matches[0] if matches else None


def assets_for(release, filenames):
    endpoint = f"repos/{REPO}/releases/{release['id']}/assets?per_page=100"
    assets = {}
    for item in rows(endpoint):
        name = item["name"]
        if name not in filenames or name in assets or item["state"] != "uploaded":
            raise ValueError(f"Conflicting release asset {name}. Inspect the release before continuing.")
        assets[name] = item["id"]
    return assets


def compare_assets(originals, downloaded, assets):
    for name, asset_id in assets.items():
        destination = downloaded / name
        with destination.open("xb") as file:
            run("gh", "api", "--hostname", "github.com", "-H", "Accept: application/octet-stream",
                f"repos/{REPO}/releases/assets/{asset_id}", stdout=file)
        if not filecmp.cmp(originals / name, destination, shallow=False):
            raise ValueError(f"GitHub asset {name} differs from the retained original")
        print(f"Byte-for-byte match {name}", flush=True)


def stage(archive, digests, publish):
    verify_pair(archive.parent, digests)
    version, source = package_identity(archive)
    tag = f"flowgate-v{version}"
    ref = f"refs/tags/{tag}"
    if output("git", "rev-parse", "--verify", ref + "^{commit}") != source:
        raise ValueError(f"Local tag {tag} does not point to the tested source {source}")
    tag_object = output("git", "rev-parse", "--verify", ref)
    if api(f"repos/{REPO}/commits/{source}")["sha"] != source:
        raise ValueError(f"GitHub did not resolve the exact source {source}")
    remote = remote_target(tag)
    if remote is not None and remote != source:
        raise ValueError(f"Remote tag {tag} points to {remote}, expected {source}")

    filenames = [file for name in digests for file in (name, name + ".sha256")]
    metadata = [f"Source: `{source}`", *(f"SHA-256 {name}: `{sha}`" for name, sha in digests.items())]
    release = release_for(tag)
    scratch = ROOT / ".workspace"
    scratch.mkdir(exist_ok=True)
    ignore = scratch / ".gitignore"
    if not ignore.exists():
        ignore.write_text("*\n")
    with tempfile.TemporaryDirectory(prefix="github-rc-", dir=scratch) as directory:
        work = Path(directory)
        if release:
            body = release["body"] or ""
            if not release["prerelease"] or any(value not in body for value in [source, *digests.values()]):
                raise ValueError(f"GitHub release metadata conflicts with the tested RC. Inspect {release['html_url']}")
            assets = assets_for(release, filenames)
            if not release["draft"] and set(assets) != set(filenames):
                raise ValueError(f"Published release has an incomplete asset set. Inspect {release['html_url']}")
            existing = work / "existing"
            existing.mkdir()
            compare_assets(archive.parent, existing, assets)
        else:
            assets = {}

        if remote is None:
            run(*GIT, "push", REMOTE, f"{tag_object}:{ref}")
        if remote_target(tag) != source:
            raise ValueError("GitHub tag changed while staging the release")
        if release is None:
            notes = work / "notes.md"
            notes.write_text("\n\n".join(metadata) + "\n", encoding="utf-8")
            run("gh", "release", "create", tag, "--repo", f"github.com/{REPO}", "--draft", "--prerelease",
                "--verify-tag", "--latest=false", "--title", f"FlowGate {version}", "--notes-file", str(notes))
            release = release_for(tag)
            if not release or not release["draft"]:
                raise ValueError("Could not resolve the newly created GitHub draft")
        missing = [str(archive.parent / name) for name in filenames if name not in assets]
        if missing:
            run("gh", "release", "upload", tag, "--repo", f"github.com/{REPO}", *missing)

        assets = assets_for(release, filenames)
        if set(assets) != set(filenames):
            raise ValueError("Draft does not contain all four expected assets")
        downloaded = work / "verified"
        downloaded.mkdir()
        compare_assets(archive.parent, downloaded, assets)
        verify_pair(downloaded, digests)
        print("Both downloaded SHA-256 receipts verified.", flush=True)

        if publish and release["draft"]:
            current = release_for(tag)
            if not current or any(current[k] != release[k] for k in ("id", "draft", "prerelease", "body")):
                raise ValueError("Release changed during verification. Rerun before publishing.")
            if assets_for(release, filenames) != assets or remote_target(tag) != source:
                raise ValueError("Assets or tag changed during verification. Rerun before publishing.")
            release = api("--method", "PATCH", f"repos/{REPO}/releases/{release['id']}",
                          "-F", "draft=false", "-F", "prerelease=true", "-f", "make_latest=false")
            if release["draft"] or not release["prerelease"] or release["tag_name"] != tag:
                raise ValueError("GitHub did not confirm the requested prerelease state")
        print(f"{'Draft' if release['draft'] else 'Published prerelease'}: {release['html_url']}")
        print(f"{tag} -> {source}")


def sha256(value):
    if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise argparse.ArgumentTypeError("expected a 64-digit SHA-256")
    return value.lower()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="path to the retained tested RC archive")
    parser.add_argument("--archive-sha256", required=True, type=sha256, help="archive digest from the test receipt")
    parser.add_argument("--installer-sha256", required=True, type=sha256, help="installer digest from the test receipt")
    parser.add_argument("--publish", action="store_true", help="publish after verifying all four GitHub assets")
    args = parser.parse_args()
    try:
        archive = args.archive.resolve()
        stage(archive, {archive.name: args.archive_sha256, "flowgate-release.py": args.installer_sha256}, args.publish)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, tarfile.TarError) as error:
        parser.exit(1, f"Release staging stopped: {error}\n")


if __name__ == "__main__":
    main()
