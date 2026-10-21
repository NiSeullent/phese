import copy
import hashlib
import base64
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import tempfile
import unittest

from phese import pages

ROOT = Path(__file__).resolve().parents[1]


class Elements(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)


class PageTests(unittest.TestCase):
    def setUp(self):
        # /tmp is intentionally rejected by the production trust policy. Keep
        # fixtures inside the already-trusted project tree instead.
        self.temporary = tempfile.TemporaryDirectory(prefix=".phese-pages-test-", dir=ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.config = self.base / "theme.json"
        self.output = self.base / "output"
        pages.init_theme(self.config)
        self.theme = json.loads(self.config.read_text())

    def save(self, theme):
        self.config.write_text(json.dumps(theme, ensure_ascii=False))

    def test_packaged_and_sample_defaults_match_and_init_never_overwrites(self):
        self.assertEqual(self.config.read_bytes(), (ROOT / "themes/default.json").read_bytes())
        self.assertEqual(self.theme["redirects"][2]["url"], "https://www.youtube.com/watch?v=dQw4w9WgXcQ")
        before = self.config.read_bytes()
        with self.assertRaises(pages.PagesError):
            pages.init_theme(self.config)
        self.assertEqual(self.config.read_bytes(), before)

    def test_build_hash_tokens_modes_and_read_only_source(self):
        original = (ROOT / "web/blocked.html").read_bytes()
        result = pages.build_page(self.config, self.output)
        page = (self.output / "blocked.html").read_text()
        script = re.search(r"<script>([\s\S]*?)</script>", page).group(1)
        digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
        self.assertIn("'sha256-" + digest + "'", result["csp"])
        ini = (self.output / "phese-page.ini").read_text()
        self.assertIn(f'phese.block_page = "{self.output / "blocked.html"}"', ini)
        self.assertIn(f'phese.block_csp = "{result["csp"]}"', ini)
        self.assertEqual(page.count("{{EVENT_ID}}"), 1)
        self.assertEqual(page.count("{{TIMESTAMP}}"), 1)
        self.assertIn("choice < 9800 ? 0 : choice < 9900 ? 1 : 2", script)
        self.assertIn("4294960000", script)
        self.assertNotIn("@@", page)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o755)
        for name, mode in [("blocked.html", 0o644), ("phese-page.ini", 0o644), (pages.MANIFEST, 0o600)]:
            self.assertEqual((self.output / name).stat().st_mode & 0o777, mode)
        self.assertEqual(set(path.name for path in self.output.iterdir()), pages.OUTPUTS | {pages.MANIFEST})
        self.assertEqual((ROOT / "web/blocked.html").read_bytes(), original)

    def test_text_quotes_markup_and_template_markers_are_data(self):
        theme = copy.deepcopy(self.theme)
        theme["text"]["page_title"] = '</title><script>alert("x")</script>'
        theme["text"]["heading_lines"] = ['<img src=x onerror="alert(1)">', "O'Reilly & @@COLOR_BLUE@@"]
        theme["media"]["image_alt"] = '" onload="alert(1)'
        page, _ = pages.render_page(theme)
        text = page.decode()
        parsed = Elements()
        parsed.feed(text)
        self.assertEqual(parsed.tags.count("script"), 1)
        self.assertEqual(parsed.tags.count("img"), 1)
        self.assertIn("&lt;/title&gt;&lt;script&gt;", text)
        self.assertIn("O&#x27;Reilly &amp; @@COLOR_BLUE@@", text)
        self.assertIn('alt="&quot; onload=&quot;alert(1)"', text)

    def test_javascript_json_cannot_close_script_or_add_markup(self):
        raw = ["</script><img>&\u2028\u2029"]
        value = pages._js_json(raw)
        self.assertNotIn("<", value)
        self.assertNotIn(">", value)
        self.assertNotIn("&", value)
        self.assertNotIn("\u2028", value)
        self.assertEqual(json.loads(value), raw)

    def test_custom_origin_colors_and_weights_generate_only_the_required_csp(self):
        theme = copy.deepcopy(self.theme)
        theme["media"]["image_url"] = "https://cdn.example.test:8443/ward.png?x=1&y=2"
        theme["colors"]["blue"] = "#123ABC"
        for route, weight in zip(theme["redirects"], [50, 25, 25]):
            route["weight"] = weight
        page, csp = pages.render_page(theme)
        self.assertIn("img-src https://cdn.example.test:8443", csp)
        self.assertNotIn("https://i.ibb.co", csp)
        self.assertIn("--blue:#123ABC", page.decode())
        self.assertIn("choice < 5000 ? 0 : choice < 7500 ? 1 : 2", page.decode())
        self.assertIn("ward.png?x=1&amp;y=2", page.decode())

    def test_invalid_urls_are_rejected_before_output(self):
        invalid = [
            "javascript:alert(1)", "http://youtu.be/zmfAMMwMOQc",
            "https://user:password@www.youtube.com/watch?v=UBiXxfeiWq4",
            "https://www.youtube.com.evil.test/watch?v=UBiXxfeiWq4",
            "https://www.youtube.com:443/watch?v=UBiXxfeiWq4",
            "https://www.youtube.com/redirect?v=UBiXxfeiWq4",
            "https://www.youtube.com/watch?v=UBiXxfeiWq4&next=https://evil.test",
            "https://www.youtube.com/watch?v=UBiXxfeiWq4&v=dQw4w9WgXcQ",
            "https://youtu.be/zmfAMMwMOQc#fragment",
            "https://youtu.be/zmfAMMwMOQc?next=evil",
            "https://www.youtube.com/watch?v=dQw4w9WgXc",
            "https://youtu.be/zmfAMMwMOQc\\@evil.test",
        ]
        for value in invalid:
            with self.subTest(url=value):
                theme = copy.deepcopy(self.theme)
                theme["redirects"][0]["url"] = value
                with self.assertRaises(pages.PagesError):
                    pages.render_page(theme)
        for value in ["http://cdn.test/a.png", "https://user:secret@cdn.test/a.png", "data:image/png;base64,AAAA", "https://cdn.test/a\n.png"]:
            theme = copy.deepcopy(self.theme)
            theme["media"]["image_url"] = value
            with self.assertRaises(pages.PagesError):
                pages.render_page(theme)

    def test_bad_schema_colors_video_and_weights(self):
        for weight in [0, -1, True, "98", 98.0, 101]:
            theme = copy.deepcopy(self.theme)
            theme["redirects"][0]["weight"] = weight
            with self.subTest(weight=weight), self.assertRaises(pages.PagesError):
                pages.render_page(theme)
        for mutate in [
            lambda t: t["redirects"][0].update(weight=97),
            lambda t: t.update(redirects=[]),
            lambda t: t["text"].update(heading_lines=["one"]),
            lambda t: t["text"].update(unknown={}),
            lambda t: t["colors"].update(blue="#fff;}</style>"),
            lambda t: t["media"].update(youtube_video_id="</script>"),
        ]:
            theme = copy.deepcopy(self.theme)
            mutate(theme)
            with self.assertRaises(pages.PagesError):
                pages.render_page(theme)
        with self.assertRaises(pages.PagesError):
            pages._load_json(b'{"text": {}, "text": {}}')

    def test_owned_build_is_idempotent_and_theme_updates_change_csp(self):
        first = pages.build_page(self.config, self.output)
        second = pages.build_page(self.config, self.output)
        self.assertTrue(first["changed"])
        self.assertFalse(second["changed"])
        old_manifest = json.loads((self.output / pages.MANIFEST).read_text())
        theme = copy.deepcopy(self.theme)
        theme["redirects"][0]["weight"], theme["redirects"][1]["weight"] = 97, 2
        theme["text"]["button_text"] = "다른 영상으로 이동"
        self.save(theme)
        third = pages.build_page(self.config, self.output)
        self.assertTrue(third["changed"])
        self.assertNotEqual(first["csp"], third["csp"])
        new_manifest = json.loads((self.output / pages.MANIFEST).read_text())
        self.assertNotEqual(old_manifest["files"], new_manifest["files"])
        self.assertFalse(pages.build_page(self.config, self.output)["changed"])

    def test_foreign_output_and_changed_managed_files_are_never_overwritten(self):
        self.output.mkdir()
        page = self.output / "blocked.html"
        page.write_text("foreign page")
        with self.assertRaises(pages.PagesError):
            pages.build_page(self.config, self.output)
        self.assertEqual(page.read_text(), "foreign page")
        page.unlink()
        pages.build_page(self.config, self.output)
        ini = (self.output / "phese-page.ini").read_bytes()
        page.write_text("manual change")
        with self.assertRaises(pages.PagesError):
            pages.build_page(self.config, self.output)
        self.assertEqual(page.read_text(), "manual change")
        self.assertEqual((self.output / "phese-page.ini").read_bytes(), ini)

    def test_symlink_config_output_parent_and_managed_file_are_rejected(self):
        alias = self.base / "alias"
        alias.symlink_to(self.base, target_is_directory=True)
        link = self.base / "config-link.json"
        link.symlink_to(self.config)
        for config, output in [(link, self.output), (alias / "theme.json", self.output), (self.config, alias / "output")]:
            with self.subTest(config=config, output=output), self.assertRaises(OSError):
                pages.build_page(config, output)
        pages.build_page(self.config, self.output)
        page = self.output / "blocked.html"
        page.unlink()
        page.symlink_to(self.config)
        before = self.config.read_bytes()
        with self.assertRaises(OSError):
            pages.build_page(self.config, self.output)
        self.assertEqual(self.config.read_bytes(), before)

    def test_shared_or_untrusted_parent_is_rejected(self):
        shared = self.base / "shared"
        shared.mkdir()
        shared.chmod(0o777)
        with self.assertRaises(pages.PagesError):
            pages.build_page(self.config, shared / "output")
        if os.geteuid() == 0:
            shared.chmod(0o755)
            os.chown(shared, 65534, 65534)
            try:
                with self.assertRaises(pages.PagesError):
                    pages.build_page(self.config, shared / "output")
            finally:
                os.chown(shared, 0, 0)


if __name__ == "__main__":
    unittest.main()
