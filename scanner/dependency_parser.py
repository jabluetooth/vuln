import json
import re
import logging
import pathlib
import tomllib

logger = logging.getLogger(__name__)

# Directories to skip during recursive scanning
EXCLUDE_DIRS = {
    '.git', 'node_modules', '.venv', 'venv', 'target',
    '__pycache__', '.tox', 'dist', 'build', '.eggs',
}


def normalize_name(name: str) -> str:
    """Normalize package name for deduplication (lowercase, dashes over underscores)."""
    return name.lower().replace('_', '-')


def find_files(filename: str, root: str = '.') -> list[str]:
    """Recursively find all files matching filename, skipping non-source dirs."""
    results = []
    for path in pathlib.Path(root).rglob(filename):
        if not any(part in EXCLUDE_DIRS for part in path.parts):
            results.append(str(path))
    return sorted(results)


# ── PyPI parsers ─────────────────────────────────────────────────────────────

def parse_requirements_txt(filepath: str) -> list[dict]:
    packages = []
    try:
        with open(filepath) as f:
            for line in f:
                line = line.split('#')[0].strip()
                if not line:
                    continue
                match = re.match(r'^([A-Za-z0-9][A-Za-z0-9._-]*)\s*[=><~!]+\s*([^\s,;]+)', line)
                if match:
                    packages.append({
                        "name": match.group(1),
                        "version": match.group(2),
                        "ecosystem": "PyPI",
                        "source_file": filepath,
                    })
    except FileNotFoundError:
        logger.info("%s not found, skipping.", filepath)
    logger.info("Parsed %d package(s) from %s", len(packages), filepath)
    return packages


def parse_poetry_lock(filepath: str) -> list[dict]:
    packages = []
    try:
        with open(filepath, 'rb') as f:
            data = tomllib.load(f)
        for pkg in data.get('package', []):
            name = pkg.get('name', '')
            version = pkg.get('version', '')
            if name and version:
                packages.append({
                    "name": name,
                    "version": version,
                    "ecosystem": "PyPI",
                    "source_file": filepath,
                })
    except FileNotFoundError:
        logger.info("%s not found, skipping.", filepath)
    except Exception as e:
        logger.error("Failed to parse %s: %s", filepath, e)
    logger.info("Parsed %d package(s) from %s", len(packages), filepath)
    return packages


def parse_pipfile(filepath: str) -> list[dict]:
    packages = []
    try:
        with open(filepath, 'rb') as f:
            data = tomllib.load(f)
        for section in ['packages', 'dev-packages']:
            for name, spec in data.get(section, {}).items():
                version = spec.get('version', '') if isinstance(spec, dict) else str(spec)
                version = version.strip().lstrip('^~=>< ')
                if version and version not in ('*', 'latest', ''):
                    packages.append({
                        "name": name,
                        "version": version,
                        "ecosystem": "PyPI",
                        "source_file": filepath,
                    })
    except FileNotFoundError:
        logger.info("%s not found, skipping.", filepath)
    except Exception as e:
        logger.error("Failed to parse %s: %s", filepath, e)
    logger.info("Parsed %d package(s) from %s", len(packages), filepath)
    return packages


def parse_pipfile_lock(filepath: str) -> list[dict]:
    packages = []
    try:
        with open(filepath) as f:
            data = json.load(f)
        for section in ['default', 'develop']:
            for name, info in data.get(section, {}).items():
                version = info.get('version', '').lstrip('=')
                if version:
                    packages.append({
                        "name": name,
                        "version": version,
                        "ecosystem": "PyPI",
                        "source_file": filepath,
                    })
    except FileNotFoundError:
        logger.info("%s not found, skipping.", filepath)
    except (json.JSONDecodeError, KeyError) as e:
        logger.error("Failed to parse %s: %s", filepath, e)
    logger.info("Parsed %d package(s) from %s", len(packages), filepath)
    return packages


# ── npm parsers ───────────────────────────────────────────────────────────────

def parse_package_json(filepath: str) -> list[dict]:
    packages = []
    try:
        with open(filepath) as f:
            data = json.load(f)
        for section in ['dependencies', 'devDependencies']:
            for name, version in data.get(section, {}).items():
                clean = version.strip().lstrip('^~=>< ')
                if clean and clean not in ('*', 'latest', 'x'):
                    packages.append({
                        "name": name,
                        "version": clean,
                        "ecosystem": "npm",
                        "source_file": filepath,
                    })
    except FileNotFoundError:
        logger.info("%s not found, skipping.", filepath)
    except json.JSONDecodeError as e:
        logger.error("Failed to parse %s: %s", filepath, e)
    logger.info("Parsed %d package(s) from %s", len(packages), filepath)
    return packages


def parse_package_lock_json(filepath: str) -> list[dict]:
    packages = []
    try:
        with open(filepath) as f:
            data = json.load(f)
        # lockfileVersion 2/3 — use "packages" key
        pkg_dict = data.get('packages', {})
        for path_key, info in pkg_dict.items():
            if not path_key:
                continue
            name = path_key.removeprefix('node_modules/').lstrip('/')
            version = info.get('version', '')
            if name and version and not info.get('dev', False):
                packages.append({
                    "name": name,
                    "version": version,
                    "ecosystem": "npm",
                    "source_file": filepath,
                })
        # lockfileVersion 1 — fall back to "dependencies" key
        if not pkg_dict:
            for name, info in data.get('dependencies', {}).items():
                version = info.get('version', '').lstrip('^~=> ')
                if version:
                    packages.append({
                        "name": name,
                        "version": version,
                        "ecosystem": "npm",
                        "source_file": filepath,
                    })
    except FileNotFoundError:
        logger.info("%s not found, skipping.", filepath)
    except (json.JSONDecodeError, KeyError) as e:
        logger.error("Failed to parse %s: %s", filepath, e)
    logger.info("Parsed %d package(s) from %s", len(packages), filepath)
    return packages


# ── Rust parsers ──────────────────────────────────────────────────────────────

def parse_cargo_toml(filepath: str) -> list[dict]:
    packages = []
    try:
        with open(filepath, 'rb') as f:
            data = tomllib.load(f)
        for section in ['dependencies', 'dev-dependencies', 'build-dependencies']:
            for name, spec in data.get(section, {}).items():
                if isinstance(spec, str):
                    version = spec.lstrip('^~=>< ')
                elif isinstance(spec, dict):
                    version = spec.get('version', '').lstrip('^~=>< ')
                else:
                    continue
                if version:
                    packages.append({
                        "name": name,
                        "version": version,
                        "ecosystem": "crates.io",
                        "source_file": filepath,
                    })
    except FileNotFoundError:
        logger.info("%s not found, skipping.", filepath)
    except Exception as e:
        logger.error("Failed to parse %s: %s", filepath, e)
    logger.info("Parsed %d package(s) from %s", len(packages), filepath)
    return packages


def parse_cargo_lock(filepath: str) -> list[dict]:
    packages = []
    try:
        with open(filepath, 'rb') as f:
            data = tomllib.load(f)
        for pkg in data.get('package', []):
            name = pkg.get('name', '')
            version = pkg.get('version', '')
            if name and version:
                packages.append({
                    "name": name,
                    "version": version,
                    "ecosystem": "crates.io",
                    "source_file": filepath,
                })
    except FileNotFoundError:
        logger.info("%s not found, skipping.", filepath)
    except Exception as e:
        logger.error("Failed to parse %s: %s", filepath, e)
    logger.info("Parsed %d package(s) from %s", len(packages), filepath)
    return packages


# ── Go parser ─────────────────────────────────────────────────────────────────

def parse_go_mod(filepath: str) -> list[dict]:
    packages = []
    try:
        with open(filepath) as f:
            content = f.read()
        # Single-line: require module v1.2.3
        for match in re.finditer(r'^require\s+(\S+)\s+v([\d][^\s/]+)', content, re.MULTILINE):
            packages.append({
                "name": match.group(1),
                "version": match.group(2),
                "ecosystem": "Go",
                "source_file": filepath,
            })
        # Block: require ( ... )
        for match in re.finditer(r'^\s+(\S+)\s+v([\d][^\s/]+)', content, re.MULTILINE):
            packages.append({
                "name": match.group(1),
                "version": match.group(2),
                "ecosystem": "Go",
                "source_file": filepath,
            })
    except FileNotFoundError:
        logger.info("%s not found, skipping.", filepath)
    except Exception as e:
        logger.error("Failed to parse %s: %s", filepath, e)
    logger.info("Parsed %d package(s) from %s", len(packages), filepath)
    return packages


# ── Aggregator ────────────────────────────────────────────────────────────────

# Maps filename → parser function
PARSERS = {
    'requirements.txt': parse_requirements_txt,
    'poetry.lock':      parse_poetry_lock,
    'Pipfile':          parse_pipfile,
    'Pipfile.lock':     parse_pipfile_lock,
    'Cargo.toml':       parse_cargo_toml,
    'Cargo.lock':       parse_cargo_lock,
    'go.mod':           parse_go_mod,
    'package.json':     parse_package_json,
    'package-lock.json': parse_package_lock_json,
}


def get_all_packages(root: str = '.') -> list[dict]:
    """Recursively discover and parse all supported dependency files, deduplicating by name+version+ecosystem."""
    packages = []
    seen: set[tuple] = set()

    for filename, parser_fn in PARSERS.items():
        for filepath in find_files(filename, root):
            for pkg in parser_fn(filepath):
                key = (normalize_name(pkg['name']), pkg['version'], pkg['ecosystem'])
                if key not in seen:
                    seen.add(key)
                    packages.append(pkg)

    logger.info("Total unique packages found: %d", len(packages))
    return packages
