import attestations
import base64
import hashlib
import json
import os
import platform
import re
import textwrap

from pathlib import Path

from registry import download
from registry import integrity_for_comparison


# TODO: Read these settings from a config file
_VSA_VERIFIER_ID = ("https://bcid.corp.google.com/verifier/bcid_package_enforcer/v0.1",)
_VSA_VERIFIED_LEVEL = "SLSA_BUILD_LEVEL_2"
_VSA_KEY_ID = "keystore://76574:prod:vsa_signing_public_key"

# https://cloud.google.com/kubernetes-engine/docs/how-to/verify-control-plane-vm-integrity
_VSA_PUBLIC_KEY = textwrap.dedent(
    """\
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeGa6ZCZn0q6WpaUwJrSk+PPYEsca
    3Xkk3UrxvbQtoZzTmq0zIYq+4QQl0YBedSyy+XcwAMaUWTouTrB05WhYtg==
    -----END PUBLIC KEY-----"""
)

class Verifier:

    _URL_TEMPLATE = (
        "https://github.com/slsa-framework/slsa-verifier/releases/download/{version}/slsa-verifier-{os}-{arch}{ext}"
    )
    _SHA256SUM_URL = "https://raw.githubusercontent.com/slsa-framework/slsa-verifier/refs/heads/main/SHA256SUM.md"
    _PROTOCOL_RE = re.compile(r"^http(s)?://")

    def __init__(self, version, download_dir):
        self._version = version

        root = Path(download_dir)
        self._executable = root / f"slsa-verifier{self._get_binary_extension()}"
        self._vsa_key_path = root / "key.pem"

    def _get_binary_extension(self):
        return ".exe" if platform.system().lower() == "windows" else ""

    def run(self, provenance, source_uri, source_tag, valid_types, tmp_dir):
        self._download_if_necessary()

        provenance_basename = os.path.basename(provenance.url)
        raw_provenance = download(provenance.url)
        actual_integrity = integrity_for_comparison(raw_provenance, provenance.integrity)
        if actual_integrity != provenance.integrity:
            raise attestations.Error(
                f"{provenance_basename} has expected integrity `{provenance.integrity}`, "
                f"but the actual value is `{actual_integrity}`."
            )

        provenance_path = os.path.join(tmp_dir, provenance_basename)
        with open(provenance_path, "wb") as f:
            f.write(raw_provenance)

        actual_types = self._get_attestation_types(provenance_basename, raw_provenance)
        if not actual_types:
            raise attestations.Error(f"{provenance_basename} does not contain valid attestations.")

        if len(actual_types) > 1:
            # TODO: figure out what to do here
            raise attestations.Error(
                f"{provenance_basename} must contain attestations of the same type, but contains {', '.join(actual_types)}."
            )

        attestation_type = actual_types[0]
        if attestation_type not in valid_types:
            raise attestations.Error(
                f"{provenance_basename} contains a {attestation_type} attestation, "
                f"but BCR only allows {', '.join(valid_types)}."
            )

        # TODO: check if attestation_type matches a globally defined allowlist?

        cmd, args = self._get_args(
            attestation_type, provenance_path, source_uri, source_tag, artifact_url_or_path, tmp_dir
        )
        result = subprocess.run(
            [slsa_verifier_path, cmd] + args,
            capture_output=True,
            encoding="utf-8",
        )

        if result.returncode:
            raise attestations.Error(
                "\n".join(
                    "SLSA verifier failed:",
                    "Command:",
                    self._pretty_print(cmd, args),
                    "Output:",
                    f"\t{result.stderr}",
                )
            )
        # TODO: --builder-id, check blessed GHA action?

    def _download_if_necessary(self):
        if self._executable.exists():
            return

        url = self._get_url()
        raw_content = download(url)
        self._check_sha256sum(raw_content, os.path.basename(url))

        with open(self._executable, "wb") as f:
            f.write(raw_content)

        os.chmod(self._executable, 0o755)

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

    def _get_attestation_types(self, provenance_basename, raw_provenance):

        def parse(pos, line):
            try:
                data = json.loads(line)
                raw_payload = (data.get("dsseEnvelope") or data).get("payload")
                payload = json.loads(base64.b64decode(raw_payload))
                return payload.get("predicateType")
            except Exception as ex:
                raise Error(f"Error in {provenance_basename}:{pos}: {ex}.") from ex

        return [parse(p, l) for p, l in enumerate(raw_content.split(b"\n"))]

    def _get_args(self, attestation_type, provenance_path, source_uri, source_tag, artifact_url_or_path, tmp_dir):
        # TODO: validate attestation type?
        fname = "_get_vsa_args" if "verification_summary" in attestation_type else "_get_provenance_args"
        return getattr(self, fname)(provenance_path, source_uri, source_tag, artifact_url_or_path, tmp_dir)

    def _get_provenance_args(self, provenance_path, source_uri, source_tag, artifact_url_or_path, tmp_dir):
        artifact_path = self._download_artifact_if_required(artifact_url_or_path, tmp_dir)
        args = [
            "--provenance-path",
            provenance_path,
            "--source-uri",
            source_uri,
            "--source-tag",
            source_tag,
            artifact_path,
        ]
        return "verify-artifact", args

    def _download_artifact_if_required(self, url_or_path, tmp_dir):
        if not self._PROTOCOL_RE.match(url_or_path):
            return url_or_path

        dest = os.path.join(tmp_dir, os.path.dirname(url_or_path))
        download_file(url_or_path, dest)
        return dest

    def _get_vsa_args(self, provenance_path, source_uri, source_tag, artifact_url_or_path, tmp_dir):
        self._ensure_vsa_key_exists()
        artifact_digest = hashlib.sha256(self._read_url_or_file(artifact_url_or_path)).hexdigest()
        args = [
            "--subject-digest",
            artifact_digest,
            "--attestation-path",
            provenance_path,
            "--verifier-id",
            _VSA_VERIFIER_ID,
            "--resource-uri",
            source_uri,
            "--verified-level",
            _VSA_VERIFIED_LEVEL,
            "--public-key-path",
            self._vsa_key_path,
            "--public-key-id",
            _VSA_KEY_ID,
        ]
        return "verify-vsa", args

    def _ensure_vsa_key_exists(self):
        if self._vsa_key_path.exists():
            return

        with open(self._vsa_key_path, "wt") as f:
            f.write(_VSA_PUBLIC_KEY)

    def _read_url_or_file(self, url_or_path):
        if self._PROTOCOL_RE.match(url_or_path):
            return download(url_or_path)

        with open(url_or_path, "rb") as f:
            return f.read()

    def _pretty_print(self, cmd, args):
        parts = [f"\tslsa-verifier {cmd}"]

        i = 0
        while i < len(args):
            value = args[i]
            if value.startswith("--"):
                parts.append(f"\t{value} {args[i+1]}")
                i += 1
            else:
                parts.append(f"\t{value}")

            i += 1

        return " \\\n\t".join(parts)
