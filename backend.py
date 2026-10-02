"""Dependency-free PEP 517 wheel builder for this pure Python project."""
import base64
import csv
import hashlib
import io
import json
from pathlib import Path
import zipfile
ROOT = Path(__file__).resolve().parent

def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    info = json.loads((ROOT / "package.json").read_text())
    name, version = info["distribution"], info["version"]
    dist = name.replace("-", "_")
    folder = dist + "-" + version + ".dist-info"
    files = {str(p.relative_to(ROOT / "src")): p.read_bytes() for p in (ROOT / "src").rglob("*")
             if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"}
    files[folder + "/METADATA"] = ("Metadata-Version: 2.1\nName: " + name + "\nVersion: " + version +
        "\nRequires-Python: >=3.10\nLicense: " + info["license"] + "\n\n" + info["description"] + "\n").encode()
    files[folder + "/WHEEL"] = b"Wheel-Version: 1.0\nGenerator: cvp-host-stdlib-backend\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    files[folder + "/entry_points.txt"] = ("[console_scripts]\n" + info["command"] + " = " + info["package"] + ".cli:main\n").encode()
    for filename in ["LICENSE", "NOTICE", "ORIGIN.md"]:
        if (ROOT / filename).exists():
            files[folder + "/" + filename] = (ROOT / filename).read_bytes()
    output = io.StringIO(); writer = csv.writer(output, lineterminator="\n")
    for key, data in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        writer.writerow([key, "sha256=" + digest, len(data)])
    writer.writerow([folder + "/RECORD", "", ""])
    files[folder + "/RECORD"] = output.getvalue().encode()
    wheel = dist + "-" + version + "-py3-none-any.whl"
    with zipfile.ZipFile(Path(wheel_directory) / wheel, "w", zipfile.ZIP_DEFLATED) as archive:
        for key, data in sorted(files.items()):
            archive.writestr(key, data)
    return wheel
