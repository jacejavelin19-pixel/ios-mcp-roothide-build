#!/usr/bin/env python3
"""Validate prefs English strings and run the Foundation resolver on macOS.

Run: python3 tests/prefs_localization_test.py
"""
import json
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RESOURCES = ROOT / "prefs/Resources"
LANGUAGES = ("en", "zh-Hans", "zh-Hant")
HAN = re.compile(r"[\u3400-\u9fff]")
OBJC_STRINGS = re.compile(r'@"(?:\\.|[^"\\])*"(?:\s*@"(?:\\.|[^"\\])*")*')
FORMATS = re.compile(r"%(?:\d+\$)?[-+ #0]*(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:hh|ll|[hljztL])?[@diuoxXfFeEgGaAcCsSpn%]")


def read_strings(path):
    return json.loads(subprocess.check_output(
        ["plutil", "-convert", "json", "-o", "-", str(path)]))


@unittest.skipUnless(sys.platform == "darwin", "Requires macOS Foundation and Xcode command-line tools")
class PreferencesLocalizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tables = {lang: read_strings(RESOURCES / f"{lang}.lproj/Localizable.strings")
                      for lang in LANGUAGES}
        cls.scratch = tempfile.TemporaryDirectory(prefix="ios-mcp-prefs-localization-")
        cls.addClassCleanup(cls.scratch.cleanup)
        work = Path(cls.scratch.name)
        cls.bundle = work / "iosmcpprefs.bundle"
        contents = cls.bundle / "Contents"
        binary = contents / "MacOS/iosmcpprefs"
        binary.parent.mkdir(parents=True)
        resource_dir = contents / "Resources"
        resource_dir.mkdir()
        for lang in LANGUAGES:
            shutil.copytree(RESOURCES / f"{lang}.lproj", resource_dir / f"{lang}.lproj")
        info = plistlib.loads((RESOURCES / "Info.plist").read_bytes())
        (contents / "Info.plist").write_bytes(plistlib.dumps(info))
        subprocess.run(["xcrun", "clang", "-dynamiclib", "-fobjc-arc", "-framework", "Foundation",
                        str(ROOT / "prefs/IOSMCPLocalization.m"), "-o", str(binary)], check=True)
        cls.host = work / "host"
        subprocess.run(["xcrun", "clang", "-fobjc-arc", "-framework", "Foundation",
                        str(ROOT / "tests/prefs_localization_host.m"), "-o", str(cls.host)], check=True)
        cls.keys_file = work / "keys.json"
        cls.keys_file.write_text(json.dumps(list(cls.tables["en"]) + ["iOS MCP", "8090", "UNKNOWN_KEY"]),
                                 encoding="utf-8")

    def resolve(self, preferences):
        apple_languages = "(" + ",".join(f'"{lang}"' for lang in preferences) + ")"
        return json.loads(subprocess.check_output(
            [str(self.host), str(self.bundle), str(self.keys_file), "-AppleLanguages", apple_languages]))

    def test_resources_are_full_english(self):
        expected_keys = set(self.tables["en"])
        for lang, table in self.tables.items():
            with self.subTest(language=lang):
                self.assertEqual(set(table), expected_keys)
                for key, value in table.items():
                    self.assertTrue(value, key)
                    self.assertFalse(HAN.search(value), f"Non-English value for {key}: {value}")
                self.assertEqual(FORMATS.findall(table["MCP_PROMPT"]), ["%@", "%@"])
                self.assertEqual(re.findall(r"^\d+\.", table["MCP_PROMPT"], re.M),
                                 [f"{i}." for i in range(1, 13)])

    def test_visible_source_strings_are_english(self):
        source = (ROOT / "prefs" / "IOSMCPRootListController.m").read_text(encoding="utf-8")
        for match in OBJC_STRINGS.finditer(source):
            value = "".join(json.loads(token[1:]) for token in
                            re.findall(r'@"(?:\\.|[^"\\])*"', match.group()))
            self.assertFalse(HAN.search(value), f"Non-English literal in IOSMCPRootListController.m: {value}")
        root = plistlib.loads((RESOURCES / "Root.plist").read_bytes())
        for item in root["items"]:
            for prop in ("label", "footerText", "placeholder", "caption"):
                value = item.get(prop, "")
                self.assertFalse(HAN.search(value), f"Non-English value in Root.plist {prop}: {value}")
                self.assertNotIn("wechat", value.lower())


if __name__ == "__main__":
    unittest.main(verbosity=2)
