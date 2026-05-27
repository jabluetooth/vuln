import json
import re


def parse_requirements_txt(filepath="requirements.txt"):
    """Parse a requirements.txt file and return a list of packages."""
    packages = []
    try:
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    match = re.match(r'([a-zA-Z0-9_\-]+)[=><~!]+([^\s]+)', line)
                    if match:
                        packages.append({
                            "name": match.group(1),
                            "version": match.group(2),
                            "ecosystem": "PyPI",
                            "source_file": filepath
                        })
    except FileNotFoundError:
        print(f"[INFO] {filepath} not found, skipping.")
    return packages


def parse_package_json(filepath="package.json"):
    """Parse a package.json file and return a list of packages."""
    packages = []
    try:
        with open(filepath) as f:
            data = json.load(f)
        for section in ["dependencies", "devDependencies"]:
            for name, version in data.get(section, {}).items():
                packages.append({
                    "name": name,
                    "version": version.lstrip("^~"),
                    "ecosystem": "npm",
                    "source_file": filepath
                })
    except FileNotFoundError:
        print(f"[INFO] {filepath} not found, skipping.")
    return packages


def get_all_packages():
    """Collect packages from all supported dependency files."""
    packages = []
    packages.extend(parse_requirements_txt("requirements.txt"))
    packages.extend(parse_package_json("package.json"))
    # Add more parsers here (e.g., Cargo.toml, go.mod)
    return packages
