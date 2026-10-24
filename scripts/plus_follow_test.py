#!/usr/bin/env python3
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import plus_follow


class PlusFollowTests(unittest.TestCase):
    def test_patch_and_minor_bumps(self) -> None:
        self.assertEqual(plus_follow.bump_plus("0.0.1", "2.3.10", "2.3.11"), "0.0.2")
        self.assertEqual(plus_follow.bump_plus("0.0.2", "2.3.11", "2.4.0"), "0.1.0")
        self.assertEqual(plus_follow.bump_plus("0.1.3", "2.4.0", "3.0.0"), "0.2.0")

    def test_refuses_older_or_equal_lite(self) -> None:
        with self.assertRaises(SystemExit):
            plus_follow.bump_plus("0.0.1", "2.3.10", "2.3.10")
        with self.assertRaises(SystemExit):
            plus_follow.bump_plus("0.0.1", "2.3.10", "2.3.9")

    def test_ours_keeps_plus_agent_install_urls(self) -> None:
        ours = (pathlib.Path(__file__).resolve().parent / "follow-ours-web.txt").read_text(encoding="utf-8")
        self.assertIn("src/utils/agentInstall.ts", ours)
        self.assertIn("tests/agentInstall.test.ts", ours)

    def test_c_class_covers_i18n_and_mcp(self) -> None:
        web = (pathlib.Path(__file__).resolve().parent / "follow-c-web.txt").read_text(encoding="utf-8")
        server = (pathlib.Path(__file__).resolve().parent / "follow-c-server.txt").read_text(encoding="utf-8")
        self.assertIn("src/i18n/locales/zh_CN.json", web)
        self.assertIn("web/mcp/oauth.go", server)

    def test_theme_git_ref(self) -> None:
        self.assertEqual(plus_follow.theme_git_ref(""), "v1.2.9")
        self.assertEqual(plus_follow.theme_git_ref("1.2.9"), "v1.2.9")
        self.assertEqual(plus_follow.theme_git_ref("v1.2.9"), "v1.2.9")
        self.assertEqual(plus_follow.theme_git_ref("main"), "main")

    def test_validate_and_rewrite_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            (root / "utils").mkdir()
            (root / "utils" / "version.go").write_text('CurrentVersion = "0.0.1"\n', encoding="utf-8")
            plus_follow.write_baseline(
                root / "plus-baseline.json",
                {
                    "plus": "0.0.1",
                    "lite": "2.3.10",
                    "lite_web": "2.3.10",
                    "lite_agent": "2.3.10.0",
                    "lite_theme": "1.2.9",
                },
            )
            plus_follow.validate_baseline(root / "plus-baseline.json")
            plus_follow.rewrite_server(root, "0.0.2", "2.3.11", "2.3.11", "2.3.10.0", "1.2.9")
            self.assertIn('CurrentVersion = "0.0.2"', (root / "utils" / "version.go").read_text(encoding="utf-8"))
            data = plus_follow.validate_baseline(root / "plus-baseline.json")
            self.assertEqual(data["plus"], "0.0.2")
            self.assertEqual(data["lite"], "2.3.11")

    def test_rewrite_web_keeps_plus_package_name(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            (root / "package.json").write_text(
                '{"name": "lite-web", "version": "2.3.11"}\n',
                encoding="utf-8",
            )
            (root / "package-lock.json").write_text(
                '{"name": "lite-web", "version": "2.3.11", "packages": {"": {"name": "lite-web", "version": "2.3.11"}}}\n',
                encoding="utf-8",
            )
            plus_follow.rewrite_web(root, "0.0.2", "2.3.11", "2.3.11", "2.3.10.0", "1.2.9")
            pkg = json.loads((root / "package.json").read_text(encoding="utf-8"))
            self.assertEqual(pkg["name"], "lite-plus-web")
            self.assertEqual(pkg["version"], "0.0.2")
            lock = json.loads((root / "package-lock.json").read_text(encoding="utf-8"))
            self.assertEqual(lock["name"], "lite-plus-web")
            self.assertEqual(lock["packages"][""]["version"], "0.0.2")


if __name__ == "__main__":
    unittest.main()
