import json
import re
import logging

logger = logging.getLogger(__name__)


def parse_requirements_txt(filepath="requirements.txt"):
    packages = []
    try:
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Strip inline comments
                line = line.split("#")[0].strip()
                # Handle package names with dots (e.g. zope.interface) and spaces around operators
                match = re.match(r'^([A-Za-z0-9][A-Za-z0-9._-]*)\s*[=><~!]+\s*([^\s,;]+)', line)
                if match:
                    packages.append({
                        "name": match.group(1),
                        "version": match.group(2),
                        "ecosystem": "PyPI",
                        "source_file": filepath
                    })
                else:
                    logger.debug("Skipped unparseable line: %s", line)
    except FileNotFoundError:
        logger.info("%s not found, skipping.", filepath)
    logger.info("Parsed %d package(s) from %s", len(packages), filepath)
    return packages


def parse_package_json(filepath="package.json"):
    packages = []
    try:
        with open(filepath) as f:
            data = json.load(f)
        for section in ["dependencies", "devDependencies"]:
            for name, version in data.get(section, {}).items():
                clean = version.strip().lstrip("^~=>< ")
                if not clean or clean in ("*", "latest", "x"):
                    logger.debug("Skipping %s — unresolvable version specifier: %s", name, version)
                    continue
                packages.append({
                    "name": name,
                    "version": clean,
                    "ecosystem": "npm",
                    "source_file": filepath
                })
    except FileNotFoundError:
        logger.info("%s not found, skipping.", filepath)
    except json.JSONDecodeError as e:
        logger.error("Failed to parse %s: %s", filepath, e)
    logger.info("Parsed %d package(s) from %s", len(packages), filepath)
    return packages


def get_all_packages():
    packages = []
    packages.extend(parse_requirements_txt("requirements.txt"))
    packages.extend(parse_package_json("package.json"))
    return packages
