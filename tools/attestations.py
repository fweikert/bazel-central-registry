import dataclasses


class Error(Exception):
    """
    Raised whenever we encounter a problem related to attestations.
    """


_VALID_MEDIA_TYPES = frozenset(["application/vnd.build.bazel.registry.attestation+json;version=1.0.0"])


@dataclasses.dataclass(frozen=True)
class Provenance:
    url: str
    integrity: str
    artifact_url_or_path: str


def get_provenance(module_name, version, attestations_json, registry):
    _assert_is_dict_with_keys(attestations_json, ["mediaType", "attestations"])

    mediaType = attestations_json.get("mediaType")
    if mediaType not in _VALID_MEDIA_TYPES:
        raise Error(f"Invalid media type '{mediaType}'")

    source_url = registry.get_source()["url"]
    url_prefix, _, archive_basename = source_url.rpartition("/")

    full_locations = {
        "source.json": registry.get_source_json_path(module_name, version),
        "MODULE.bazel": registry.get_module_dot_bazel_path(module_name, version),
        archive_basename: source_url,
    }

    attestations = attestations_json.get("attestations")
    _assert_is_dict_with_keys(attestations, list(full_locations.keys()))

    provenances = []
    for basename, metadata in attestations.items():
        _assert_is_dict_with_keys(metadata, ["url", "integrity"])

        expected_url = f"{url_prefix}/{basename}.intoto.jsonl"
        url = metadata["url"]
        if url != expected_url:
            raise Error(f"Expected url {expected_url}, but got {url} in {basename} attestation.")

        integrity = metadata["integrity"]
        if not integrity:
            raise Error(f"Missing `integrity` field for {basename} attestation.")

        provenances.append(
            Provenance(
                url=url,
                integrity=integrity,
                artifact_url_or_path=full_locations[basename],
            )
        )

    return provenances


def _assert_is_dict_with_keys(self, candidate, keys):
    if not isinstance(candidate, dict):
        raise Error("Expected a dictionary.")
    if set(keys).symmetric_difference(candidate.keys()):
        raise Error(f"Expected keys {keys}, but got {candidate.keys()}.")
