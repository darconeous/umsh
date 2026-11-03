"""Regression fixtures from the oversized T-Beam startup prologue."""

import unittest

from check_xtensa_stack import (
    construction_candidates,
    device_task_construction,
    function_frames,
    stack_size,
    task_construction,
)


class StackCheckTests(unittest.TestCase):
    def test_tbeam_nested_constructor_overflows_despite_individual_frames_fitting(self):
        main = ("firmware_tbeam_supreme::__main::____embassy_main_task::"
                "____embassy_main_task_inner_function::{closure#0}", 22960)
        constructor = ("firmware_tbeam_supreme::device_task", 9024)
        initializer = ("<embassy_executor::raw::util::UninitCell<"
                       "firmware_tbeam_supreme::__device_task_task::"
                       "__device_task_task_inner_function::{closure#0}>>::write_in_place::<"
                       "firmware_tbeam_supreme::device_task::{closure#0}>", 17792)
        frames = [main, constructor, initializer]
        available = 46108
        self.assertTrue(all(size + 20480 <= available for _, size in frames))
        self.assertEqual(sum(size for _, size in device_task_construction(frames)), 49776)
        self.assertGreater(sum(size for _, size in device_task_construction(frames)), available)
        # Inlining the wrapper removes its nested frame; its work is accounted
        # for by the larger caller frame measured in the baseline ELF.
        inlined = [(main[0], 23744), (initializer[0], 17728)]
        self.assertEqual(sum(size for _, size in device_task_construction(inlined)), 41472)
        self.assertLess(41472, 46492)

    def test_radio_task_chain_survives_candidate_filtering(self):
        # Mangled names, as the filter sees them before demangling.
        main = ("_ZN15firmware_tlora_pager6__main20____embassy_main_task"
                "37____embassy_main_task_inner_function28_$u7b$$u7b$closure$u7d$$u7d$"
                "17h0123456789abcdefE", 21000)
        constructor = ("_ZN20firmware_tlora_pager10radio_task17h0123456789abcdefE", 4096)
        initializer = ("_ZN16embassy_executor3raw4util10UninitCell"
                       "__radio_task_task14write_in_place17h0123456789abcdefE", 6144)
        unrelated = ("_ZN20firmware_tlora_pager9gnss_task17h0123456789abcdefE", 30000)
        kept = construction_candidates([main, constructor, initializer, unrelated])
        self.assertEqual(kept, [main, constructor, initializer])
        # The demangled spellings the stage matcher reads.
        demangled = {
            main[0]: "firmware_tlora_pager::__main::____embassy_main_task::"
                     "____embassy_main_task_inner_function::{closure#0}",
            constructor[0]: "firmware_tlora_pager::radio_task",
            initializer[0]: "<embassy_executor::raw::util::UninitCell<"
                            "firmware_tlora_pager::__radio_task_task::"
                            "__radio_task_task_inner_function::{closure#0}>>::write_in_place::<"
                            "firmware_tlora_pager::radio_task::{closure#0}>",
        }
        frames = [(demangled[name], size) for name, size in kept]
        self.assertEqual(sum(size for _, size in task_construction(frames, "radio_task")),
                         21000 + 4096 + 6144)
        # The device-task chain picks up only main's frame from these.
        self.assertEqual(sum(size for _, size in device_task_construction(frames)), 21000)

    def test_large_frame_that_jumps_over_the_guard(self):
        text = """4211cae0 <node_startup>:
4211cae0: 004136 entry a1, 32
4211cae3: 5a1d81 l32r a8, 420f3358 <literal> (e300 <constant>)
4211cae6: c08180 sub a8, a1, a8
4211cae9: 001810 movsp a1, a8
"""
        self.assertEqual(list(function_frames(text.splitlines(keepends=True)))[0][1], 58144)
        available = stack_size("3fcdb700 g *ABS* 0 _stack_start\n"
                               "3fccfcdc g *ABS* 0 _stack_end\n")
        self.assertGreater(list(function_frames(text.splitlines(keepends=True)))[0][1], available)

    def test_small_frame_does_not_count_unrelated_literals(self):
        text = """4211ced8 <node_startup>:
4211ced8: 0c4136 entry a1, 0x620
4211cedb: 57f981 l32r a8, 420f2ec0 <literal> (3c015c9c <VTABLE>)
"""
        self.assertEqual(list(function_frames(text.splitlines(keepends=True)))[0][1], 1568)

    def test_unknown_large_frame_is_not_silently_accepted(self):
        text = """4211cae0 <node_startup>:
4211cae0: 004136 entry a1, 32
4211cae9: 001810 movsp a1, a8
"""
        with self.assertRaises(ValueError):
            list(function_frames(text.splitlines(keepends=True)))


if __name__ == "__main__":
    unittest.main()
