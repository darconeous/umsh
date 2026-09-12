"""Regression fixtures from the oversized T-Beam startup prologue."""

import unittest

from check_xtensa_stack import function_frames, stack_size


class StackCheckTests(unittest.TestCase):
    def test_large_frame_that_jumps_over_the_guard(self):
        text = """4211cae0 <node_startup>:
4211cae0: 004136 entry a1, 32
4211cae3: 5a1d81 l32r a8, 420f3358 <literal> (e300 <constant>)
4211cae6: c08180 sub a8, a1, a8
4211cae9: 001810 movsp a1, a8
"""
        self.assertEqual(list(function_frames(text))[0][1], 58144)
        available = stack_size("3fcdb700 g *ABS* 0 _stack_start\n"
                               "3fccfcdc g *ABS* 0 _stack_end\n")
        self.assertGreater(list(function_frames(text))[0][1], available)

    def test_small_frame_does_not_count_unrelated_literals(self):
        text = """4211ced8 <node_startup>:
4211ced8: 0c4136 entry a1, 0x620
4211cedb: 57f981 l32r a8, 420f2ec0 <literal> (3c015c9c <VTABLE>)
"""
        self.assertEqual(list(function_frames(text))[0][1], 1568)

    def test_unknown_large_frame_is_not_silently_accepted(self):
        text = """4211cae0 <node_startup>:
4211cae0: 004136 entry a1, 32
4211cae9: 001810 movsp a1, a8
"""
        with self.assertRaises(ValueError):
            list(function_frames(text))


if __name__ == "__main__":
    unittest.main()
