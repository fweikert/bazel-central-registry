import attestations
import hashlib
import os
import platform
import re

from registry import download
from registry import integrity_for_comparison


class Verifier:

    _URL_TEMPLATE = (
        "https://github.com/slsa-framework/slsa-verifier/releases/download/{version}/slsa-verifier-{os}-{arch}{ext}"
    )
    _SHA256SUM_URL = "https://raw.githubusercontent.com/slsa-framework/slsa-verifier/refs/heads/main/SHA256SUM.md"
    _PROTOCOL_RE = re.compile(r"^http(s)?://")

    def __init__(self, version, download_dir):
        self._version = version
        self._path = os.path.join(download_dir, f"slsa-verifier{self._get_binary_extension()}")

    def _get_binary_extension(self):
        return ".exe" if platform.system().lower() == "windows" else ""

    def run(self, provenance, source_uri, source_tag, tmp_dir):
        self._download_if_necessary()

        provenance_basename = os.path.basename(provenance.url)
        raw_provenance = download(provenance.url)
        actual_integrity = integrity_for_comparison(raw_provenance, provenance.integrity)
        if actual_integrity != provenance.integrity:
            raise AttestationsError(
                f"{provenance_basename} has expected integrity `{provenance.integrity}`, "
                f"but the actual value is `{actual_integrity}`."
            )

        provenance_path = os.path.join(tmp_dir, provenance_basename)
        with open(provenance_path, "wb") as f:
            f.write(raw_provenance)

        artifact_path = self._download_artifact_if_required(provenance.artifact_url_or_path, tmp_dir)

        result = subprocess.run(
            [
                slsa_verifier_path,
                "verify-artifact",
                "--provenance-path",
                provenance_path,
                "--source-uri",
                source_uri,
                "--source-tag",
                source_tag,
                artifact_path,
            ],
            capture_output=True,
            encoding="utf-8",
        )

        if result.returncode:
            raise AttestationsError(
                "\n".join(
                    "SLSA verifier failed:",
                    f"\tArtifact: {artifact_path}",
                    f"\tProvenance: {provenance.url}",
                    "Output:",
                    result.stderr,
                )
            )
        # TODO: --builder-id, check blessed GHA action
        # TODO: VSA

    def _download_if_necessary(self):
        if self._path.exists():
            return

        url = self._get_url()
        raw_content = download(url)
        self._check_sha256sum(raw_content, os.path.basename(url))

        with open(self._path, "wb") as f:
            f.write(raw_content)

        os.chmod(self._path, 0o755)

    def _get_url(self):
        osname = platform.system().lower()
        m = platform.machine()
        arch = m if m == "arm64" else "amd64"
        return self._URL_TEMPLATE.format(version=self._version, os=osname, arch=arch, ext=self._get_binary_extension())

    def _check_sha256sum(self, raw_content, binary_name):
        actual_hash = hashlib.sha256(raw_content).hexdigest()
        pattern = re.compile(rf"^{actual_hash}\s+{binary_name}$", re.MULTILINE)

        sha256sums = download(self._SHA256SUM_URL).decode("utf-8")

        # Unfortunately the file contains Markdown.
        needle = f"[{self._version}]"
        for version_block in sha256sums.split("###"):
            if needle in version_block:
                if pattern.search(version_block):
                    return
                break

        raise attestations.Error(
            f"{binary_name}@{self._version}: " f"could not find actual checksum {actual_hash} in {self._SHA256SUM_URL}."
        )

    def _download_artifact_if_required(self, url_or_path, tmp_dir):
        if not self._PROTOCOL_RE.match(url_or_path):
            return url_or_path

        dest = os.path.join(tmp_dir, os.path.dirname(url_or_path))
        download_file(url_or_path, dest)
        return dest
