"""What the manifest check lets two images differ in, and what it does not."""

import unittest

from check_esp32_manifests import check


def image(board, bsp, default=(), **features):
    table = {
        "default": [board, *default],
        "board-a": ["chip"],
        "board-b": ["chip"],
        "chip": [],
        "ble": ["dep:host", f"{bsp}/ble"],
        "wifi": ["radio/wifi"],
    }
    table.update(features)
    return {
        "features": table,
        "dependencies": {"umsh-bsp-esp32": {}, bsp: {}, "host": {"optional": True}},
    }


class ManifestCheckTests(unittest.TestCase):
    def test_images_differing_only_in_what_selects_them_agree(self):
        manifests = {
            "a": image("board-a", "umsh-bsp-a", default=["ble"]),
            "b": image("board-b", "umsh-bsp-b", default=["wifi"]),
        }
        self.assertEqual(check(manifests), [])

    def test_a_feature_one_image_lacks_is_reported(self):
        manifests = {
            "a": image("board-a", "umsh-bsp-a", psram=[]),
            "b": image("board-b", "umsh-bsp-b"),
        }
        problems = check(manifests)
        self.assertIn("feature `psram` differs:", problems)
        self.assertIn("    b: not declared", problems)

    def test_a_feature_defined_differently_is_reported(self):
        manifests = {
            "a": image("board-a", "umsh-bsp-a"),
            "b": image("board-b", "umsh-bsp-b", wifi=["radio/wifi", "radio/coex"]),
        }
        self.assertIn("feature `wifi` differs:", check(manifests))

    def test_a_board_definition_must_match_even_where_it_is_unused(self):
        manifests = {
            "a": image("board-a", "umsh-bsp-a"),
            "b": image("board-b", "umsh-bsp-b", **{"board-a": ["chip", "ble"]}),
        }
        self.assertIn("feature `board-a` differs:", check(manifests))

    def test_a_chip_only_dependency_may_be_named_by_some_images(self):
        with_blob = image("board-a", "umsh-bsp-a", wifi=["radio/wifi", "dep:esp-wifi-sys-esp32s3"])
        manifests = {"a": with_blob, "b": image("board-b", "umsh-bsp-b")}
        self.assertEqual(check(manifests), [])

    def test_two_images_of_one_board_share_their_dependencies(self):
        standard = image("board-a", "umsh-bsp-a", default=["ble"])
        variant = image("board-a", "umsh-bsp-a", default=["wifi"])
        self.assertEqual(check({"a": standard, "a-variant": variant}), [])
        variant["dependencies"]["host"] = {"optional": True, "version": "2"}
        self.assertEqual(
            check({"a": standard, "a-variant": variant}),
            ["dependency `host` differs between a and a-variant (both board-a)"],
        )

    def test_default_must_select_exactly_one_board(self):
        manifests = {
            "a": image("board-a", "umsh-bsp-a", default=["board-b"]),
            "b": image("board-b", "umsh-bsp-b"),
        }
        self.assertEqual(len(check(manifests)), 1)
        self.assertIn("must select one board", check(manifests)[0])


if __name__ == "__main__":
    unittest.main()
