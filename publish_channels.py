"""Public release-channel verifier. No application source or private signing key.

Published plain-version releases (including previews) may advance each platform
independently. All candidate bytes are checked before a single Git commit; the
branch update refuses concurrent changes. Never execute downloaded artifacts.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

REPOSITORY = "Treasur34/TitanViewer"
PUBLIC_KEY = "3J56TbZFzEJxTj9oGn8mOWCFoayrvlob1D2RQB03gsM="
PLATFORMS = ("windows-x64", "linux-x64", "linux-arm64")
MAX_ASSET = 768 * 1024 * 1024
MAX_METADATA = 32768


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def unique_json(raw):
    def pairs(items):
        result = {}
        for name, value in items:
            if name in result:
                raise ValueError("Duplicate JSON field")
            result[name] = value
        return result

    return json.loads(raw, object_pairs_hook=pairs)


def version(text):
    if not isinstance(text, str) or not re.fullmatch(r"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}", text):
        raise ValueError("Invalid version")
    return tuple(map(int, text.split(".")))


def signature(key, signature_text, content):
    raw = base64.b64decode(signature_text, validate=True)
    if len(raw) != 64 or base64.b64encode(raw).decode() != signature_text:
        raise ValueError("Invalid signature encoding")
    Ed25519PublicKey.from_public_bytes(key).verify(raw, content)


def digest_fields(size, digest):
    if type(size) is not int or not 1 <= size <= MAX_ASSET:
        raise ValueError("Invalid payload size")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("Invalid payload hash")


def verify(document, platform, *, public=PUBLIC_KEY, now=None, allow_expired=False):
    now = int(time.time()) if now is None else now
    key = base64.b64decode(public, validate=True)
    if platform.startswith("linux-"):
        if set(document) != {"release", "signature"}:
            raise ValueError("Invalid Linux envelope")
        value = document["release"]
        if set(value) != {
            "schema",
            "product",
            "platform",
            "arch",
            "version",
            "size",
            "sha256",
            "issued",
            "expires",
        }:
            raise ValueError("Invalid Linux manifest")
        if (
            type(value["schema"]) is not int
            or value["schema"] != 1
            or value["product"] != "Titan Viewer"
            or value["platform"] != "linux"
            or "linux-" + value["arch"] != platform
        ):
            raise ValueError("Linux target mismatch")
        if (
            type(value["issued"]) is not int
            or type(value["expires"]) is not int
            or not 0 <= value["issued"] <= now + 300
            or not value["issued"] < value["expires"] <= value["issued"] + 90 * 86400
        ):
            raise ValueError("Invalid Linux validity")
        signature(key, document["signature"], b"Titan Viewer Linux release v1\0" + canonical(value))
        size, digest = value["size"], value["sha256"]
        extension = ".tar.gz"
    elif platform == "windows-x64":
        if set(document) != {"schema", "envelope", "bundle_size", "bundle_sha256"} or document["schema"] != 1:
            raise ValueError("Invalid Windows channel")
        envelope = document["envelope"]
        value = envelope["manifest"]
        if "publisher_policy" in envelope:
            # Future authority delegation is deliberately fail-closed until its
            # complete revocation/successor protocol is supported by this worker.
            raise ValueError("Delegated Windows authority needs verifier upgrade")
        if set(envelope) != {"manifest", "signature"}:
            raise ValueError("Invalid Windows envelope")
        if set(value) != {"expires", "platform", "product", "sha256", "size", "version"}:
            raise ValueError("Invalid Windows manifest")
        if value["product"] != "RemoteDesk" or value["platform"] != platform:
            raise ValueError("Windows target mismatch")
        signature(key, envelope["signature"], canonical(value))
        digest_fields(value["size"], value["sha256"])
        size, digest = document["bundle_size"], document["bundle_sha256"]
        extension = ".rdupdate"
    else:
        raise ValueError("Unsupported platform")
    if type(value["expires"]) is not int or (not allow_expired and value["expires"] <= now):
        raise ValueError("Expired release")
    version(value["version"])
    digest_fields(size, digest)
    return {
        "version": value["version"],
        "size": size,
        "sha256": digest,
        "name": f"TitanViewer-{value['version']}-{platform}{extension}",
    }


def verify_file(path, expected, document, platform):
    if path.stat().st_size != expected["size"]:
        raise ValueError("Payload size differs from channel")
    with path.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != expected["sha256"]:
            raise ValueError("Payload digest differs from channel")
    if platform == "windows-x64":
        # The outer bundle digest is not signed; bind the executable and embedded
        # envelope to the verified signature as well. Never extract or execute it.
        with zipfile.ZipFile(path) as bundle:
            if sorted(bundle.namelist()) != ["RemoteDesk.exe", "manifest.json"]:
                raise ValueError("Unexpected bundle members")
            if bundle.getinfo("manifest.json").file_size > MAX_METADATA:
                raise ValueError("Oversized bundle manifest")
            if unique_json(bundle.read("manifest.json")) != document["envelope"]:
                raise ValueError("Bundle signature differs from channel")
            manifest = document["envelope"]["manifest"]
            if bundle.getinfo("RemoteDesk.exe").file_size != manifest["size"]:
                raise ValueError("Executable size mismatch")
            with bundle.open("RemoteDesk.exe") as stream:
                if hashlib.file_digest(stream, "sha256").hexdigest() != manifest["sha256"]:
                    raise ValueError("Executable hash mismatch")


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        url = urllib.parse.urlsplit(newurl)
        if (
            url.scheme != "https"
            or url.hostname != "release-assets.githubusercontent.com"
            or url.port not in (None, 443)
            or url.username
            or url.password
            or url.fragment
            or not url.path.startswith("/github-production-release-asset/")
        ):
            raise ValueError("Unexpected release redirect")
        # No API authentication is forwarded to the asset CDN.
        return urllib.request.Request(newurl, headers={"Accept-Encoding": "identity"})


def download(asset, tag, directory, *, limit):
    name = asset["name"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        raise ValueError("Unsafe asset name")
    expected_url = f"https://github.com/{REPOSITORY}/releases/download/{tag}/{name}"
    if asset.get("browser_download_url") != expected_url or asset.get("state") != "uploaded":
        raise ValueError("Unpublished or foreign asset")
    if type(asset.get("size")) is not int or not 1 <= asset["size"] <= limit:
        raise ValueError("Asset too large")
    destination = directory / name
    request = urllib.request.Request(expected_url, headers={"Accept-Encoding": "identity"})
    with urllib.request.build_opener(SafeRedirect).open(request, timeout=45) as response:
        if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
            raise ValueError("Invalid asset response")
        count = 0
        with destination.open("xb") as output:
            while block := response.read(262144):
                count += len(block)
                if count > asset["size"]:
                    raise ValueError("Asset exceeded advertised size")
                output.write(block)
        if count != asset["size"]:
            raise ValueError("Incomplete asset")
    return destination


def assets_by_name(release):
    result = {}
    for asset in release.get("assets", []):
        if asset["name"] in result:
            raise ValueError("Duplicate release asset")
        result[asset["name"]] = asset
    return result


def candidates(releases):
    eligible = []
    for release in releases:
        if release.get("draft") or not release.get("published_at"):
            continue
        tag = release.get("tag_name", "")
        if re.fullmatch(r"v[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}", tag):
            eligible.append(release)
    eligible.sort(key=lambda r: version(r["tag_name"][1:]), reverse=True)
    selected = {}
    for release in eligible:
        assets = assets_by_name(release)
        for platform in PLATFORMS:
            suffix = ".rdupdate" if platform == "windows-x64" else ".tar.gz"
            package = f"TitanViewer-{release['tag_name'][1:]}-{platform}{suffix}"
            metadata = platform + ".json"
            if platform not in selected and (metadata in assets or package in assets):
                if metadata not in assets or package not in assets:
                    raise ValueError("Incomplete release channel: " + release["tag_name"] + "/" + platform)
                selected[platform] = (release, assets)
    return selected


def plan(releases, current, directory, *, loader=download, public=PUBLIC_KEY, now=None):
    changes = {}
    for platform, (release, assets) in candidates(releases).items():
        meta = loader(assets[platform + ".json"], release["tag_name"], directory, limit=MAX_METADATA)
        document = unique_json(meta.read_bytes())
        expected = verify(document, platform, public=public, now=now)
        if expected["version"] != release["tag_name"][1:]:
            raise ValueError("Release tag differs from signed version")
        old = current.get(platform)
        if old:
            previous = verify(old, platform, public=public, now=now, allow_expired=True)
            if version(expected["version"]) < version(previous["version"]):
                raise ValueError("Refusing channel rollback")
            if expected["version"] == previous["version"]:
                if document != old:
                    raise ValueError("Published release is immutable")
                continue
        payload = loader(assets[expected["name"]], release["tag_name"], directory, limit=MAX_ASSET)
        verify_file(payload, expected, document, platform)
        changes[platform] = document
    return changes


def api(path, *, data=None, method=None):
    if not re.fullmatch(r"/[A-Za-z0-9_/-]+(?:\?[A-Za-z0-9_=&]+)?", path):
        raise ValueError("Invalid API path")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(
        "https://api.github.com/repos/" + REPOSITORY + path,
        data=canonical(data) if data is not None else None,
        headers=headers,
        method=method,
    )

    # Repository API redirects are never accepted with an authorization header.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args):
            raise ValueError("API redirect rejected")

    with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
        raw = response.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            raise ValueError("API response too large")
        return unique_json(raw)


def publish(changes, head, tree):
    entries = []
    for platform, document in sorted(changes.items()):
        entries.append(
            {
                "path": "channels/stable/" + platform + ".json",
                "mode": "100644",
                "type": "blob",
                "content": canonical(document).decode() + "\n",
            }
        )
    new_tree = api("/git/trees", data={"base_tree": tree, "tree": entries})
    commit = api(
        "/git/commits",
        data={
            "message": "Publish verified signed update channels",
            "tree": new_tree["sha"],
            "parents": [head],
        },
    )
    # Non-fast-forward updates fail; never overwrite another publisher's commit.
    return api("/git/refs/heads/main", data={"sha": commit["sha"], "force": False}, method="PATCH")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publish", action="store_true")
    args = parser.parse_args()
    head = api("/git/ref/heads/main")["object"]["sha"]
    tree = api("/git/commits/" + head)["tree"]["sha"]
    items = api("/git/trees/" + tree + "?recursive=1")
    if items.get("truncated"):
        raise ValueError("Repository tree incomplete")
    current = {}
    for item in items["tree"]:
        for platform in PLATFORMS:
            if item["path"] == "channels/stable/" + platform + ".json":
                blob = api("/git/blobs/" + item["sha"])
                if blob["size"] > MAX_METADATA or blob["encoding"] != "base64":
                    raise ValueError("Invalid current channel")
                current[platform] = unique_json(base64.b64decode(blob["content"]))
    releases = []
    for page in range(1, 11):
        values = api(f"/releases?per_page=100&page={page}")
        releases.extend(values)
        if len(values) < 100:
            break
    else:
        raise ValueError("Release inventory exceeds bounded pagination")
    with tempfile.TemporaryDirectory(prefix="titan-channel-") as folder:
        changes = plan(releases, current, Path(folder))
    print(json.dumps({"verified_channels": sorted(changes), "publication_requested": args.publish}))
    if changes and args.publish:
        if not os.environ.get("GITHUB_TOKEN"):
            raise ValueError("Publishing requires repository token")
        publish(changes, head, tree)


if __name__ == "__main__":
    main()
