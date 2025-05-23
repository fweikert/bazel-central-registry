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

from registry import RegistryClient
from registry import download
from registry import download_file


SCANNER_VERSION = "v2.0.2"
SCANNER_URL_TEMPLATE = "https://github.com/google/osv-scanner/releases/download/{version}/osv-scanner_{os}_{arch}"
GITHUB_RELEASE_URL_PATTERN = re.compile(r"https://github.com/(?P<org>[^/]+)/(?P<repo>[^/]+)/(archive/refs/tags|/releases/download)/(((?P<tag>[^/]+))/)?(?P<file>[^/]+)(\.zip|\.tar\.gz)")


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

    registry = RegistryClient(args.registry)

    tmpdir = tempfile.mkdtemp()
    try:
        module_set = set(get_base_modules(args.check_all, args.check, registry))
        deps_set = set()
        seen_modules = {}

        while module_set:
            pair = module_set.pop()
            if pair in seen_modules:
                continue

            module_name, version = pair
            # TODO: figure out sets etc. process and add deps
            for BAR in get_FOO(module_name, version, registry):
                pass # TODO

            seen_modules.append(pair)

        scanner_path = download_scanner(SCANNER_VERSION, tmpdir)
    finally:
        shutil.rmtree(tmpdir)

    return 0


def get_base_modules(check_all, modules_to_check, registry):
    return [(m, get_latest_version(m, registry)) for m in registry.get_all_modules()] if check_all else [parse_module_version(m) for m in modules_to_check]


def parse_module_version(value):
    module_name, _, version = value.partition("@")
    if not version:
        pass  # TODO: raise

    return (module_name, version)


def get_latest_version(module_name, registry):
    metadata = registry.get_metadata(module_name)
    return metadata["versions"][-1]


def get_FOO(module_name, version, registry):
    org, repo, tag, commit = get_release_info(module_name, version, registry)
    module_deps, extension_deps = get_deps(module_name, version, registry)

    # TODO: return synthetic object for this module
    # TODO: build deps objects (lockfile vs synthetic)
    return None, module_deps, extension_deps


def get_release_info(module_name, version, registry):
    source = registry.get_source(module_name, version)
    m = GITHUB_RELEASE_URL_PATTERN.search(source["url"])
    if not m:
        pass  # TODO

    org, repo, tag = m.group("org"), m.group("repo"), m.group("tag") or m.group("file")
    return org, repo, tag, resolve_tag(org, repo, tag)


def resolve_tag(org, repo, tag):
    url = f"https://api.github.com/repos/{org}/{repo}/git/ref/tags/{tag}"
    data = json.loads(download(url))
    return data["object"]["sha"]


def get_deps(module_name, version, registry):
    mdb_path = registry.get_module_dot_bazel_path(module_name, version)
    # TODO: parse and extract deps!
    return [], []


if __name__ == "__main__":
    # Under 'bazel run' we want to run within the source folder instead of the execroot.
    if os.getenv("BUILD_WORKSPACE_DIRECTORY"):
        os.chdir(os.getenv("BUILD_WORKSPACE_DIRECTORY"))
    sys.exit(main())
