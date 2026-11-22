import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "bindings" / "python"))

from apixray import ApiXray  # noqa: E402

xray = ApiXray()
print("apixray", xray.version())

fake = xray.generate_fake("github")
print("fake key:", fake)

report = xray.analyze(fake)
print("provider:", report["provider"])
print("risk:", report["risk"])
print("verdict:", report["verdict"])
print("segments:", len(report["segments"]))

found = xray.scan(f"token = {fake}")
print("found in text:", len(found))
