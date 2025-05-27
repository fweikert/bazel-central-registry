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
GITHUB_RELEASE_URL_PATTERN = re.compile(r"https://github.com/(?P<org>[^/]+)/(?P<repo>[^/]+)/(archive(/refs/tags)?|releases/download)/(((?P<tag>[^/]+))/)?(?P<file>[^/]+)(\.zip|\.tar\.gz)")
DEV_DEPENDENCY = "dev_dependency"


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
        module_cache = {}
        lockfile_cache = set()

        module_set = set(get_base_modules(args.check_all, args.check, registry))
        roots = [recurse_TODO(m, v, registry, module_cache, lockfile_cache) for m, v in module_set]

        # TODO: run scanner on module_cache + lockfile_cache

        # TODO: report based on root and scanner results
        # for root in roots:
        #   root.print("\t", 0)

        # TODO: remove
        print(len(module_cache))
        print(len(set(k[0] for k in module_cache.keys())))

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


class ModuleNode:

    def __init__(self, name, version, org, repo, tag, commit):
        self.name = name
        self.version = version
        self.org = org
        self.repo = repo
        self.tag = tag
        self.commit = commit
        self.deps = []
        self.extensions = []

    def print(self, indent, level):
        print(f"{indent*level}{self.name}@{self.version}")
        for d in self.deps:
            d.print(indent, level+1)
        
        for org, repo, target in self.extensions:
            print(f"{(indent+1)*level}- {org}/{repo}:{target}")


def recurse_TODO(module_name, version, registry, module_cache, lockfile_cache):
    key = (module_name, version)
    existing = module_cache.get(key)
    if existing:
        return existing

    org, repo, tag, commit = get_release_info(module_name, version, registry)
    node = ModuleNode(module_name, version, org, repo, tag, commit)

    module_deps, extension_deps = get_deps(module_name, version, registry)

    for child_name, child_version in module_deps:
        node.deps.append(recurse_TODO(child_name, child_version, registry, module_cache, lockfile_cache))

    for e in extension_deps:
        lockfile_cache.add(e)
        node.extensions.append(e)

    module_cache[key] = node
    return node


def get_release_info(module_name, version, registry):
    source = registry.get_source(module_name, version)
    m = GITHUB_RELEASE_URL_PATTERN.search(source["url"])
    if not m:
        raise Exception("TODO: {}".format(source["url"]))  # TODO

    org, repo, tag = m.group("org"), m.group("repo"), m.group("tag") or m.group("file")
    return org, repo, tag, resolve_tag(org, repo, tag)


def resolve_tag(org, repo, tag):
    return f"commit_for_{tag}" # TODO: work around GitHub rate limit
    url = f"https://api.github.com/repos/{org}/{repo}/git/ref/tags/{tag}"
    data = json.loads(download(url))
    return data["object"]["sha"]


def get_deps(module_name, version, registry, include_dev_dependencies=True):
    mdb_path = registry.get_module_dot_bazel_path(module_name, version)

    # TODO
    if "aspect_rules_aws" not in str(mdb_path):
        return [], []

    # Great, now we're parsing Starlark code :(
    with open(mdb_path, "rb") as f:
        tree = ast.parse(f.read())

    def parse_value(c):
        if isinstance(c, ast.Name):
            return f"${c.id}"
        elif isinstance(c, ast.Constant):
            return c.value
        elif isinstance(c, ast.List):
            return [parse_value(e) for e in c.elts]

    def analyze_call(c):
        if not isinstance(c, ast.Call):
            return None, None, [], {}

        owner, func = (c.func.value.id, c.func.attr) if isinstance(c.func, ast.Attribute) else (None, c.func.id)
        return owner, func, [parse_value(a) for a in c.args], {k.arg : parse_value(k.value) for k in c.keywords}

    module_deps = []
    extensions = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            _, func, args, kwargs = analyze_call(node.value)
            if func != "use_extension" or (kwargs.get(DEV_DEPENDENCY) and not include_dev_dependencies):
                continue

            extensions.add(node.targets[0].id)
        elif isinstance(node, ast.Expr):
            owner, func, args, kwargs = analyze_call(node.value)
            if func == "bazel_dep" and (include_dev_dependencies or not kwargs.get(DEV_DEPENDENCY)):
                module_deps.append((kwargs["name"], kwargs["version"]))
            elif owner in extensions:
                # Extension method
                print(f"EXT TODO: {owner}.{func}({args}, **{kwargs})")

    return module_deps, []
    # TODO: [("name", "version")], [("org", "repo", "target")]


if __name__ == "__main__":
    # Under 'bazel run' we want to run within the source folder instead of the execroot.
    if os.getenv("BUILD_WORKSPACE_DIRECTORY"):
        os.chdir(os.getenv("BUILD_WORKSPACE_DIRECTORY"))
    sys.exit(main())
