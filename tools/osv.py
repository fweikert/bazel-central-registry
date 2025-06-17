import argparse
import ast
import dataclasses
import json
import os
import platform
import re
import requests
import shutil
import subprocess
import sys
import tempfile
import urllib
import yaml

from registry import RegistryClient
from registry import download
from registry import download_file


SCANNER_VERSION = "v2.0.2"
SCANNER_URL_TEMPLATE = "https://github.com/google/osv-scanner/releases/download/{version}/osv-scanner_{os}_{arch}"
GITHUB_RELEASE_URL_PATTERN = re.compile(r"https://github.com/(?P<org>[^/]+)/(?P<repo>[^/]+)/(archive(/refs/tags)?|releases/download)/(((?P<tag>[^/]+))/)?(?P<file>[^/]+)(\.zip|\.tar\.gz)")
DEV_DEPENDENCY = "dev_dependency"


def handle_oci_extension(org, repo, tag, args, kwargs, tmpdir):
    _ = org, repo, tag, args, tmpdir
    # TODO: handle non-happy path
    image = kwargs.get("image")
    if ":" not in image:
        image = f"{image}:{kwargs.get('tag', 'latest')}"

    return f"scan image {image}"


def handle_pip_extension(org, repo, tag, args, kwargs, tmpdir):
    _ = args
    # TODO: handle non-happy path
    target = kwargs.get("requirements_lock")

    # Guess source URL based on target (very hacky).
    path_suffix = target.replace("//", "").replace(":", "/")
    url = f"https://raw.githubusercontent.com/{org}/{repo}/refs/tags/{tag}/{path_suffix}"

    path = os.path.join(tmpdir, os.path.basename(path_suffix))
    try:
        download_file(url, path)
    except urllib.error.HTTPError as ex:
        # TODO
        raise Exception(url) from ex

    return f"scan source --lockfile {path}"


KNOWN_EXTENSIONS = {
    ("@rules_oci//oci:extensions.bzl", "oci", "pull"): handle_oci_extension,
    ("@rules_python//python/extensions:pip.bzl", "pip", "parse"): handle_pip_extension,
}


def download_scanner(version, dest_dir):
    arch = platform.machine().replace("x86_64", "amd64").replace("aarch64", "arm64")
    os_name = platform.system().lower()
    url = SCANNER_URL_TEMPLATE.format(version=version, os=os_name, arch=arch)

    path = os.path.join(dest_dir, "osv-scanner")
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
        TODO_all_ext = []

        module_cache = {}
        module_set = set(get_base_modules(args.check_all, args.check, registry))
        for m, v in module_set:
            recurse_TODO(m, v, registry, module_cache)

        for module in module_cache.values():
            github_module, extensions = module.resolve(registry, tmpdir)
            print(github_module)
            print(extensions)

            for k in extensions.keys():
                TODO_all_ext.append(f"{k} ({module.name}@{module.version})")

            print()

        # TODO: run scanner on module_cache + extension_cache

        # TODO: report based on root and scanner results

        # TODO: remove
        print(len(module_cache))
        print("\n".join(sorted(TODO_all_ext)))

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


class Module:

    def __init__(self, name, version):
        self.name = name
        self.version = version
        self.extensions = []

    def resolve(self, registry, tmpdir):
        org, repo, tag = self._get_release_info(registry)
        commit = self._resolve_tag(org, repo, tag)

        ghm = GitHubModule(name=self.name, version=self.version, org=org, repo=repo, tag=tag, commit=commit)
        return ghm, {
            f"{ext.file}: {ext.name}.{ext.func}()": self._resolve_extension(ext, org, repo, tag, tmpdir)
            for ext in self.extensions
        }

    def _get_release_info(self, registry):
        source = registry.get_source(self.name, self.version)
        m = GITHUB_RELEASE_URL_PATTERN.search(source["url"])
        if not m:
            raise Exception("TODO: {}".format(source["url"]))  # TODO

        org, repo, tag = m.group("org"), m.group("repo"), m.group("tag") or m.group("file")
        return org, repo, tag

    def _resolve_tag(self, org, repo, tag):
        return f"commit_for_{tag}"  # TODO: work around GitHub rate limit
        url = f"https://api.github.com/repos/{org}/{repo}/git/ref/tags/{tag}"
        data = json.loads(download(url))
        return data["object"]["sha"]

    def _resolve_extension(self, ext, org, repo, tag, tmpdir):
        ext_resolver = KNOWN_EXTENSIONS.get((ext.file, ext.name, ext.func))
        if not ext_resolver:
            return None  # TODO: report as unknown

        return ext_resolver(org, repo, tag, ext.args, ext.kwargs, tmpdir)

    def __str__(self):
        return f"{self.name}@{self.version}"


@dataclasses.dataclass(frozen=True)
class Extension:
    file: str
    name: str
    func: str
    args: list
    kwargs: dict


@dataclasses.dataclass(frozen=True)
class GitHubModule:
    name: str
    version: str
    org: str
    repo: str
    tag: str
    commit: str


def recurse_TODO(module_name, version, registry, module_cache):
    key = (module_name, version)
    if key in module_cache:
        return

    node = Module(module_name, version)
    module_cache[key] = node

    module_deps, extensions = get_deps(module_name, version, registry)
    node.extensions += extensions

    for child_name, child_version in module_deps:
        recurse_TODO(child_name, child_version, registry, module_cache)


def get_deps(module_name, version, registry, include_dev_dependencies=True):
    mdb_path = registry.get_module_dot_bazel_path(module_name, version)
    with open(mdb_path, "rb") as f:
        tree = ast.parse(f.read())  # Great, now we're parsing Starlark code :(

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
    extensions = []
    extension_registry = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            _, func, args, kwargs = analyze_call(node.value)
            if func != "use_extension" or (kwargs.get(DEV_DEPENDENCY) and not include_dev_dependencies):
                continue

            # extensions[symbol] = [extension_bzl_file, extension_name]
            extension_registry[node.targets[0].id] = args
        elif isinstance(node, ast.Expr):
            owner, func, args, kwargs = analyze_call(node.value)
            if not owner and func == "bazel_dep" and (include_dev_dependencies or not kwargs.get(DEV_DEPENDENCY)):
                module_deps.append((kwargs["name"], kwargs["version"]))
            elif not owner and func == "archive_override":
                print(f"LOL CALL: {owner}.{func}([{args}, **{kwargs}])")
            elif owner in extension_registry:
                extension_bzl_file, extension_name = extension_registry[owner]
                extensions.append(
                    Extension(file=extension_bzl_file, name=extension_name, func=func, args=args, kwargs=kwargs)
                )

    return module_deps, extensions


if __name__ == "__main__":
    # Under 'bazel run' we want to run within the source folder instead of the execroot.
    if os.getenv("BUILD_WORKSPACE_DIRECTORY"):
        os.chdir(os.getenv("BUILD_WORKSPACE_DIRECTORY"))
    sys.exit(main())
