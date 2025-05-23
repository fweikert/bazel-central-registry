import argparse
import ast
import json
import os
import platform
import re
import requests
import shutil
import subprocess
import sys
import tempfile
import yaml

from registry import download
from registry import download_file


SCANNER_VERSION = "v2.0.2"
SCANNER_URL_TEMPLATE = "https://github.com/google/osv-scanner/releases/download/{version}/osv-scanner_{os}_{arch}"


def download_scanner(version, dest_dir):
    arch = platform.machine()
    os_name = platform.system().lower()
    url = SCANNER_URL_TEMPLATE.format(version=version, os=os_name, arch=arch)

    path = os.path.join(dest_dir, 'osv-scanner')   
    download_file(url, path)
    return path


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--registry",
        type=str,
        default=".",
        help="Specify the root path of the registry (default: the current working directory).",
    )
    parser.add_argument(
        "--check",
        type=str,
        action="append",
        help="Specify a Bazel module version you want to perform the BCR check on."
        + " (e.g. bazel_skylib@1.3.0)."
        + " This flag can be repeated to accept multiple module versions.",
    )
    parser.add_argument(
        "--check_all",
        action="store_true",
        help="Check the latest version of all Bazel modules in the registry,"
        + " ignore other --check flags.",
    )
    # TODO: remove?
    parser.add_argument(
        "--token",
        type=str,
        help="GitHub API token for GitHug API requests.",
    )

    args = parser.parse_args(argv)
    if not args.check_all and not args.check:
        parser.print_help()
        return -1

    tmpdir = tempfile.mkdtemp()
    try:
        tags = TagResolver()

        

        scanner_path = download_scanner(SCANNER_VERSION, tmpdir)
    finally:
        shutil.rmtree(tmpdir)

    return 0


class TagResolver:

    def __init__(self):
        self._cache = {}
    
    def resolve(self, org, repo, tag):
        key = (org, repo, tag)
        if key not in self._cache:
            self._cache[key] = self._get_tag_commit(org, repo, tag)

        return self._cache[key]

    def _get_tag_commit(self, org, repo, tag):
        url = f"https://api.github.com/repos/{org}/{repo}/git/ref/tags/{tag}"

        print(f"HTTP {url}")

        data = json.loads(download(url))
        return data["object"]["sha"]


if __name__ == "__main__":
    # Under 'bazel run' we want to run within the source folder instead of the execroot.
    if os.getenv("BUILD_WORKSPACE_DIRECTORY"):
        os.chdir(os.getenv("BUILD_WORKSPACE_DIRECTORY"))
    sys.exit(main())
