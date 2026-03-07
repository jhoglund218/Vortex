#!/usr/bin/env python3
"""Generate and sync Flatpak source manifests for yarn, pnpm, and NuGet inputs."""

import argparse
import hashlib
import json
import re
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Iterable, List, Optional

from _flatpak_env import ensure_venv, repo_root, run_command
from _flatpak_nuget_hash import (
    collect_nuget_input_files,
    compute_nuget_sources_hash,
    read_stored_hash as read_nuget_stored_hash,
    write_stored_hash as write_nuget_stored_hash,
)
from _flatpak_pnpm_hash import (
    compute_pnpm_sources_hash,
    read_stored_hash as read_pnpm_stored_hash,
    write_stored_hash as write_pnpm_stored_hash,
)
from _flatpak_yarn_hash import (
    collect_lockfiles,
    compute_sources_hash,
    read_stored_hash as read_sources_stored_hash,
    write_stored_hash as write_sources_stored_hash,
)


DEFAULT_LOCKFILE = "yarn.lock"
DEFAULT_YARN_OUTPUT = "flatpak/generated-sources.json"
DEFAULT_YARN_HASH_FILE = "flatpak/generated-sources.hash"
DEFAULT_PNPM_LOCKFILE = "pnpm-lock.yaml"
DEFAULT_PNPM_OUTPUT = "flatpak/generated-pnpm-sources.json"
DEFAULT_PNPM_HASH_FILE = "flatpak/generated-pnpm-sources.hash"
DEFAULT_NUGET_SEARCH_ROOT = "extensions"
DEFAULT_NUGET_OUTPUT = "flatpak/generated-nuget-sources.json"
DEFAULT_NUGET_HASH_FILE = "flatpak/generated-nuget-sources.hash"
DEFAULT_DOTNET = "9"
DEFAULT_FREEDESKTOP = "25.08"
DEFAULT_DESTDIR = "flatpak-nuget-sources"
DEFAULT_RUNTIME = "linux-x64"

_PNPM_TARBALL_DEST = "flatpak-node/pnpm-tarballs"
_PNPM_SETUP_SCRIPT_NAME = "setup-pnpm-store.py"
_PNPM_TARBALL_URL_MAP_NAME = "pnpm-tarball-url-map.json"
_SCOPED_NPM_URL_RE = re.compile(
    r"^https://registry\.npmjs\.org/@(?P<scope>[^/]+)/(?P<name>[^/]+)/-/(?P<filename>[^/]+\.tgz)$"
)
_LOCKFILE_TARBALL_URL_RE = re.compile(
    r"resolution:\s*\{[^}]*\btarball:\s*(https?://[^,}\s]+)"
)

_PNPM_SETUP_SCRIPT = """\
TARBALLS_DIR = 'flatpak-node/pnpm-tarballs'
STORE_DIR = 'flatpak-node/pnpm-store'
TARBALL_URL_MAP_FILE = 'flatpak-node/pnpm-tarball-url-map.json'
VIRTUAL_STORE_DIR_MAX_LENGTH = 120

import base64
import hashlib
import json
import os
import re
import stat
import tarfile
import time

STORE_FILES_DIR = os.path.join(STORE_DIR, 'v10', 'files')
STORE_INDEX_DIR = os.path.join(STORE_DIR, 'v10', 'index')


def cafs_path(hex_hash: str, suffix: str = '') -> str:
    return os.path.join(STORE_FILES_DIR, hex_hash[:2], hex_hash[2:] + suffix)


def index_path(hex_hash: str, package_name: str, package_version: str) -> str:
    short_hash = hex_hash[:64]
    package_id = package_name.replace('/', '+')
    return os.path.join(
        STORE_INDEX_DIR,
        short_hash[:2],
        f'{short_hash[2:]}-{package_id}@{package_version}.json',
    )


def dep_path_to_filename_unescaped(dep_path: str) -> str:
    if not dep_path.startswith('file:'):
        if dep_path.startswith('/'):
            dep_path = dep_path[1:]
        index = dep_path.find('@', 1)
        if index == -1:
            return dep_path
        return f"{dep_path[:index]}@{dep_path[index + 1:]}"
    return dep_path.replace(':', '+', 1)


def dep_path_to_filename(dep_path: str, max_length_without_hash: int = VIRTUAL_STORE_DIR_MAX_LENGTH) -> str:
    filename = re.sub(r'[\\\\/:*?"<>|#]', '+', dep_path_to_filename_unescaped(dep_path))
    if '(' in filename:
        if filename.endswith(')'):
            filename = filename[:-1]
        filename = filename.replace(')(', '_').replace('(', '_').replace(')', '_')
    if len(filename) > max_length_without_hash or (
        filename != filename.lower() and not filename.startswith('file+')
    ):
        short_hash = hashlib.sha256(filename.encode('utf-8')).hexdigest()[:32]
        return f"{filename[:max_length_without_hash - 33]}_{short_hash}"
    return filename


def sha512_hex(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()


def sha512_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha512(data).digest()).decode()


os.makedirs(STORE_FILES_DIR, exist_ok=True)
os.makedirs(STORE_INDEX_DIR, exist_ok=True)

try:
    with open(TARBALL_URL_MAP_FILE, 'r') as fh:
        tarball_url_map = json.load(fh)
except Exception:
    tarball_url_map = {}

for tarball_name in sorted(os.listdir(TARBALLS_DIR)):
    tarball_path = os.path.join(TARBALLS_DIR, tarball_name)
    try:
        tf = tarfile.open(tarball_path, 'r:gz')
    except tarfile.ReadError:
        continue
    with open(tarball_path, 'rb') as fh:
        tarball_data = fh.read()
    tarball_hash = sha512_hex(tarball_data)
    checked_at = int(time.time() * 1000)

    files_index = {}
    package_manifest = None
    with tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            # Strip leading directory component (typically 'package/')
            parts = member.name.split('/', 1)
            rel_path = parts[1] if len(parts) > 1 else parts[0]
            file_obj = tf.extractfile(member)
            if file_obj is None:
                continue
            file_data = file_obj.read()
            file_hash = sha512_hex(file_data)
            is_exec = bool(member.mode & stat.S_IXUSR)
            suffix = '-exec' if is_exec else ''
            dest = cafs_path(file_hash, suffix)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            if not os.path.exists(dest):
                with open(dest, 'wb') as fh:
                    fh.write(file_data)
            files_index[rel_path] = {
                'checkedAt': checked_at,
                'integrity': 'sha512-' + sha512_b64(file_data),
                'mode': member.mode,
                'size': member.size,
            }
            if rel_path == 'package.json':
                try:
                    manifest = json.loads(file_data.decode('utf-8'))
                    if isinstance(manifest, dict):
                        package_manifest = manifest
                except Exception:
                    package_manifest = None

    package_name = package_manifest.get('name') if package_manifest else None
    package_version = package_manifest.get('version') if package_manifest else None
    if isinstance(package_name, str) and isinstance(package_version, str):
        package_index = {
            'name': package_name,
            'version': package_version,
            'requiresBuild': False,
            'files': files_index,
        }
        index_dest = index_path(tarball_hash, package_name, package_version)
        os.makedirs(os.path.dirname(index_dest), exist_ok=True)
        with open(index_dest, 'w') as fh:
            json.dump(package_index, fh)

        url = tarball_url_map.get(tarball_name)
        if isinstance(url, str):
            url_store_dir = os.path.join(STORE_DIR, 'v10', dep_path_to_filename(url))
            os.makedirs(url_store_dir, exist_ok=True)
            for index_name in ('integrity.json', 'integrity-not-built.json'):
                with open(os.path.join(url_store_dir, index_name), 'w') as fh:
                    json.dump(package_index, fh)

    print(f'Processed {tarball_name}')

print('pnpm store setup complete.')
"""


def _scoped_dest_filename(url: str, filename: str) -> str:
    match = _SCOPED_NPM_URL_RE.match(url)
    if match is None:
        return filename
    scope = match.group("scope")
    return f"{scope}__{filename}"


def _extract_lockfile_tarball_urls(lockfile: Path) -> List[str]:
    contents = lockfile.read_text(encoding="utf-8")
    return sorted(set(_LOCKFILE_TARBALL_URL_RE.findall(contents)))


def _dest_filename_for_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    filename = Path(parsed.path).name or "source"
    if parsed.netloc == "registry.npmjs.org":
        return _scoped_dest_filename(url, filename)

    url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]
    if "." not in filename:
        filename = f"{filename}.tgz"
    return f"url_{url_hash}_{filename}"


def _sha512_hex_from_url(url: str) -> str:
    digest = hashlib.sha512()
    with urllib.request.urlopen(url) as response:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _append_missing_tarball_sources(lockfile: Path, data: List[dict]) -> bool:
    source_entries = [
        source
        for source in data
        if source.get("type") == "file" and source.get("dest") == _PNPM_TARBALL_DEST
    ]
    existing_urls = {
        source["url"] for source in source_entries if isinstance(source.get("url"), str)
    }
    existing_filenames = {
        source["dest-filename"]
        for source in source_entries
        if isinstance(source.get("dest-filename"), str)
    }

    changed = False
    tarball_urls = _extract_lockfile_tarball_urls(lockfile)
    missing_urls = [url for url in tarball_urls if url not in existing_urls]

    if missing_urls:
        print(
            "Adding lockfile tarball sources missing from pnpm manifest "
            f"({len(missing_urls)} URL(s))."
        )

    for url in missing_urls:
        filename = _dest_filename_for_url(url)
        if filename in existing_filenames:
            filename = f"{hashlib.sha256(url.encode('utf-8')).hexdigest()[:12]}-{filename}"
        sha512_hex = _sha512_hex_from_url(url)
        data.append(
            {
                "type": "file",
                "url": url,
                "sha512": sha512_hex,
                "dest-filename": filename,
                "dest": _PNPM_TARBALL_DEST,
            }
        )
        existing_filenames.add(filename)
        changed = True

    return changed


def _pnpm_tarball_url_map_contents(data: List[dict]) -> str:
    tarball_url_map = {}
    for source in data:
        if source.get("type") != "file" or source.get("dest") != _PNPM_TARBALL_DEST:
            continue
        url = source.get("url")
        filename = source.get("dest-filename")
        if not isinstance(url, str) or not isinstance(filename, str):
            continue
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme in ("http", "https") and parsed.netloc != "registry.npmjs.org":
            tarball_url_map[filename] = url

    return f"{json.dumps(tarball_url_map, indent=2, sort_keys=True)}\n"


def _normalize_pnpm_manifest(lockfile: Path, output: Path) -> None:
    data = json.loads(output.read_text(encoding="utf-8"))
    changed = False

    for source in data:
        if source.get("type") == "file" and source.get("dest") == _PNPM_TARBALL_DEST:
            url = source.get("url")
            filename = source.get("dest-filename")
            if isinstance(url, str) and isinstance(filename, str):
                new_filename = _scoped_dest_filename(url, filename)
                if new_filename != filename:
                    source["dest-filename"] = new_filename
                    changed = True
        elif (
            source.get("type") == "inline"
            and source.get("dest-filename") == _PNPM_SETUP_SCRIPT_NAME
        ):
            if source.get("contents") != _PNPM_SETUP_SCRIPT:
                source["contents"] = _PNPM_SETUP_SCRIPT
                changed = True

    if _append_missing_tarball_sources(lockfile=lockfile, data=data):
        changed = True

    tarball_url_map_contents = _pnpm_tarball_url_map_contents(data)
    found_tarball_url_map = False
    for source in data:
        if (
            source.get("type") == "inline"
            and source.get("dest-filename") == _PNPM_TARBALL_URL_MAP_NAME
        ):
            found_tarball_url_map = True
            if source.get("contents") != tarball_url_map_contents:
                source["contents"] = tarball_url_map_contents
                changed = True
            if source.get("dest") != "flatpak-node":
                source["dest"] = "flatpak-node"
                changed = True
            break

    if not found_tarball_url_map:
        data.append(
            {
                "type": "inline",
                "contents": tarball_url_map_contents,
                "dest-filename": _PNPM_TARBALL_URL_MAP_NAME,
                "dest": "flatpak-node",
            }
        )
        changed = True

    if changed:
        output.write_text(f"{json.dumps(data, indent=4)}\n", encoding="utf-8")


def generate_sources(
    lockfile: Path,
    output: Path,
    recursive: bool,
    lockfiles: Optional[List[Path]] = None,
) -> None:
    info = ensure_venv(install_packages=True)

    root = repo_root()

    cmd = [
        str(info.flatpak_node_generator),
        "yarn",
        str(lockfile),
        "-o",
        str(output),
    ]
    if recursive:
        if lockfiles is None:
            lockfiles = collect_lockfiles(lockfile=lockfile, recursive=True)
        cmd.append("-r")
        for lockfile_path in lockfiles:
            cmd.extend(["-R", str(lockfile_path)])

    run_command(cmd, cwd=root)


def sync_generated_sources(
    lockfile: Path,
    output: Path,
    hash_file: Path,
    recursive: bool = True,
    force: bool = False,
) -> bool:
    root = repo_root()
    if not lockfile.is_absolute():
        lockfile = root / lockfile
    if not output.is_absolute():
        output = root / output
    if not hash_file.is_absolute():
        hash_file = root / hash_file

    source_hash, lockfiles = compute_sources_hash(
        lockfile=lockfile, recursive=recursive
    )
    stored_hash = read_sources_stored_hash(hash_file)

    if not force and output.exists() and stored_hash == source_hash:
        print("Flatpak generated sources are up to date (hash match).")
        return False

    if force:
        print("Regenerating flatpak sources (forced by --force).")
    elif not output.exists():
        print(f"Regenerating flatpak sources (missing output: {output}).")
    elif stored_hash is None:
        print(f"Regenerating flatpak sources (missing hash file: {hash_file}).")
    else:
        print("Regenerating flatpak sources (lockfile hash changed).")

    generate_sources(
        lockfile=lockfile,
        output=output,
        recursive=recursive,
        lockfiles=lockfiles,
    )
    write_sources_stored_hash(hash_file=hash_file, value=source_hash)
    print(f"Updated Flatpak sources hash: {hash_file}")
    return True


def generate_pnpm_sources(lockfile: Path, output: Path) -> None:
    info = ensure_venv(install_packages=True)
    root = repo_root()
    cmd = [
        str(info.flatpak_node_generator),
        "pnpm",
        str(lockfile),
        "-o",
        str(output),
    ]
    run_command(cmd, cwd=root)
    _normalize_pnpm_manifest(lockfile=lockfile, output=output)


def sync_generated_pnpm_sources(
    lockfile: Path,
    output: Path,
    hash_file: Path,
    force: bool = False,
) -> bool:
    root = repo_root()
    if not lockfile.is_absolute():
        lockfile = root / lockfile
    if not output.is_absolute():
        output = root / output
    if not hash_file.is_absolute():
        hash_file = root / hash_file

    source_hash, _ = compute_pnpm_sources_hash(lockfile=lockfile)
    stored_hash = read_pnpm_stored_hash(hash_file)

    if not force and output.exists() and stored_hash == source_hash:
        print("Flatpak pnpm generated sources are up to date (hash match).")
        return False

    if force:
        print("Regenerating flatpak pnpm sources (forced by --force).")
    elif not output.exists():
        print(f"Regenerating flatpak pnpm sources (missing output: {output}).")
    elif stored_hash is None:
        print(f"Regenerating flatpak pnpm sources (missing hash file: {hash_file}).")
    else:
        print("Regenerating flatpak pnpm sources (lockfile hash changed).")

    generate_pnpm_sources(lockfile=lockfile, output=output)
    write_pnpm_stored_hash(hash_file=hash_file, value=source_hash)
    print(f"Updated Flatpak pnpm sources hash: {hash_file}")
    return True


def _resolve_paths(paths: Iterable[Path], root: Path) -> List[Path]:
    resolved: List[Path] = []
    for path in paths:
        resolved.append(path if path.is_absolute() else root / path)
    return resolved


def _discover_nuget_projects(search_root: Path) -> List[Path]:
    projects = [
        path
        for path in collect_nuget_input_files(search_root=search_root)
        if path.suffix.lower() == ".csproj"
    ]
    if not projects:
        raise FileNotFoundError(f"No .csproj files found under: {search_root}")
    return projects


def generate_nuget_sources(
    projects: List[Path],
    output: Path,
    dotnet: str,
    freedesktop: str,
    destdir: str,
    runtime: str,
) -> None:
    info = ensure_venv(install_packages=True)
    root = repo_root()

    cmd = [
        str(info.python_exe),
        str(info.flatpak_dotnet_generator),
        "--dotnet",
        dotnet,
        "--freedesktop",
        freedesktop,
        "--destdir",
        destdir,
        str(output),
        *[str(project) for project in projects],
        "--runtime",
        runtime,
    ]

    run_command(cmd, cwd=root)


def sync_generated_nuget_sources(
    search_root: Path,
    projects: Optional[List[Path]],
    output: Path,
    hash_file: Path,
    dotnet: str,
    freedesktop: str,
    destdir: str,
    runtime: str,
    force: bool = False,
) -> bool:
    root = repo_root()
    if not search_root.is_absolute():
        search_root = root / search_root
    if not output.is_absolute():
        output = root / output
    if not hash_file.is_absolute():
        hash_file = root / hash_file

    if projects:
        projects = _resolve_paths(projects, root)
    else:
        projects = _discover_nuget_projects(search_root)

    for project in projects:
        if not project.exists():
            raise FileNotFoundError(f"NuGet project not found: {project}")

    source_hash, _ = compute_nuget_sources_hash(search_root=search_root)
    stored_hash = read_nuget_stored_hash(hash_file)

    if not force and output.exists() and stored_hash == source_hash:
        print("Flatpak NuGet sources are up to date (hash match).")
        return False

    if force:
        print("Regenerating Flatpak NuGet sources (forced by --force).")
    elif not output.exists():
        print(f"Regenerating Flatpak NuGet sources (missing output: {output}).")
    elif stored_hash is None:
        print(f"Regenerating Flatpak NuGet sources (missing hash file: {hash_file}).")
    else:
        print("Regenerating Flatpak NuGet sources (project hash changed).")

    generate_nuget_sources(
        projects=projects,
        output=output,
        dotnet=dotnet,
        freedesktop=freedesktop,
        destdir=destdir,
        runtime=runtime,
    )
    write_nuget_stored_hash(hash_file=hash_file, value=source_hash)
    print(f"Updated Flatpak NuGet sources hash: {hash_file}")
    return True


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Generate Flatpak source manifests. "
            "By default this updates both generated-sources.json and "
            "generated-nuget-sources.json."
        )
    )

    parser.add_argument(
        "--only",
        choices=("all", "yarn", "pnpm", "nuget"),
        default="all",
        help="Select which source types to sync (default: all)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Always regenerate selected source files, even when hashes match",
    )

    nuget_group = parser.add_argument_group("nuget options")
    nuget_group.add_argument(
        "--search-root",
        default=DEFAULT_NUGET_SEARCH_ROOT,
        help="Root directory to scan for NuGet dependency changes (default: extensions)",
    )
    nuget_group.add_argument(
        "--project",
        action="append",
        default=[],
        help=(
            "Project file path (repeat for multiple projects). "
            "If omitted, all .csproj files under --search-root are used"
        ),
    )

    return parser


def main() -> None:
    args = _build_parser().parse_args()

    run_yarn = args.only in {"all", "yarn"}
    run_pnpm = args.only in {"all", "pnpm"}
    run_nuget = args.only in {"all", "nuget"}

    if run_yarn:
        sync_generated_sources(
            lockfile=Path(DEFAULT_LOCKFILE),
            output=Path(DEFAULT_YARN_OUTPUT),
            hash_file=Path(DEFAULT_YARN_HASH_FILE),
            recursive=True,
            force=args.force,
        )

    if run_pnpm:
        sync_generated_pnpm_sources(
            lockfile=Path(DEFAULT_PNPM_LOCKFILE),
            output=Path(DEFAULT_PNPM_OUTPUT),
            hash_file=Path(DEFAULT_PNPM_HASH_FILE),
            force=args.force,
        )

    if run_nuget:
        projects = [Path(project) for project in args.project] if args.project else None

        sync_generated_nuget_sources(
            search_root=Path(args.search_root),
            projects=projects,
            output=Path(DEFAULT_NUGET_OUTPUT),
            hash_file=Path(DEFAULT_NUGET_HASH_FILE),
            dotnet=DEFAULT_DOTNET,
            freedesktop=DEFAULT_FREEDESKTOP,
            destdir=DEFAULT_DESTDIR,
            runtime=DEFAULT_RUNTIME,
            force=args.force,
        )


if __name__ == "__main__":
    main()
