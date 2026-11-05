"""Regression fixtures from the oversized T-Beam startup prologue."""

import unittest

from check_xtensa_stack import (
    PATH_FRAMES,
    code_words,
    communicator_path,
    construction_candidates,
    deepest_path,
    device_task_construction,
    function_frames,
    functions,
    largest_frames,
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


# As mangled: the poll of the communicator task, and the app's constructor.
TASK = ("_RNvMs1_NtCs0_16embassy_executor3rawINtB5_11TaskStorageNCNvNvNtCs1_"
        "8firmware12communicator11___task_task26___task_task_inner_function0E4pollB18_")
APP = "_RINvNtCs1_8firmware8external12communicatorINtNtCs2_7buoyant3app3AppE"


def parsed(text, tables=frozenset()):
    return list(functions(text.splitlines(keepends=True), tables))


def path_through(text, root, tables=frozenset()):
    program = parsed(text, tables)
    graph = {function.address: function for function in program}
    address = next(function.address for function in program if function.name == root)
    return deepest_path(graph, address)[0]


class CallPathTests(unittest.TestCase):
    def test_a_literal_is_an_edge_as_a_direct_call_is(self):
        text = """42000000 <poll>:
42000000: entry a1, 100
42000003: l32r a8, 41ffff00 <literal> (42000100 <view>)
42000006: callx8 a8
42000009: call8 42000200 <small>
42000100 <view>:
42000100: entry a1, 1000
42000103: call8 42000300 <leaf>
42000200 <small>:
42000200: entry a1, 32
42000300 <leaf>:
42000300: entry a1, 64
"""
        self.assertEqual(path_through(text, "poll"),
                         [("poll", 100), ("view", 1000), ("leaf", 64)])

    def test_large_frames_count_on_a_path(self):
        text = """42000000 <poll>:
42000000: entry a1, 32
42000003: l32r a8, 420f3358 <literal> (e300 <constant>)
42000006: sub a8, a1, a8
42000009: movsp a1, a8
4200000c: call8 42000100 <leaf>
42000100 <leaf>:
42000100: entry a1, 64
"""
        self.assertEqual(path_through(text, "poll"), [("poll", 58144), ("leaf", 64)])

    def test_what_starts_no_function_is_no_edge(self):
        text = """42000000 <poll>:
42000000: entry a1, 100
42000003: l32r a8, 41ffff00 <literal> (3c015c9c <VTABLE>)
42000006: j 42000003 <poll+0x3>
42000009: call8 42000104 <leaf+0x4>
42000100 <leaf>:
42000100: entry a1, 64
"""
        self.assertEqual(path_through(text, "poll"), [("poll", 100)])

    def test_a_tail_jump_is_an_edge(self):
        text = """42000000 <thunk>:
42000000: entry a1, 32
42000003: j 42000100 <target>
42000100 <target>:
42000100: entry a1, 64
"""
        self.assertEqual(path_through(text, "thunk"), [("thunk", 32), ("target", 64)])

    def test_a_literal_pool_decoded_as_code_is_no_edge(self):
        # As in the Pager: pool words past a return, reached by a branch
        # around them, that decode to a call and a load of a real function.
        text = """42000000 <poll>:
42000000: entry a1, 100
42000003: beqz.n a2, 42000010 <poll+0x10>
42000005: retw.n
42000007: l32r a1, 41ffff00 <literal> (42000100 <view>)
4200000a: call12 42000100 <view>
4200000d: ee.ld.qacc_l.l.128.ip a6, 0x110
42000010: call8 42000200 <leaf>
42000013: retw.n
42000100 <view>:
42000100: entry a1, 50000
42000200 <leaf>:
42000200: entry a1, 64
"""
        self.assertEqual(path_through(text, "poll"), [("poll", 100), ("leaf", 64)])

    def test_control_stops_at_what_could_not_be_decoded(self):
        text = """42000000 <poll>:
42000000: entry a1, 100
42000003: .byte 0x3c
42000004: call8 42000100 <view>
42000100 <view>:
42000100: entry a1, 50000
"""
        self.assertEqual(path_through(text, "poll"), [("poll", 100)])

    def test_a_jump_table_reaches_the_code_behind_it(self):
        text = """42000000 <poll>:
42000000: entry a1, 100
42000003: jx a9
42000006: l32r a1, 41ffff00 <literal> (42000300 <decoy>)
42000009: call8 42000100 <arm>
42000100 <arm>:
42000100: entry a1, 1000
42000300 <decoy>:
42000300: entry a1, 50000
"""
        self.assertEqual(path_through(text, "poll"), [("poll", 100)])
        self.assertEqual(path_through(text, "poll", {0x42000009}),
                         [("poll", 100), ("arm", 1000)])

    def test_a_branch_and_a_loop_reach_their_targets(self):
        text = """42000000 <poll>:
42000000: entry a1, 100
42000003: bnei a8, 2, 42000010 <poll+0x10>
42000006: loopnez a2, 42000020 <poll+0x20>
42000009: retw.n
42000010: call8 42000100 <one>
42000013: retw.n
42000020: call8 42000200 <two>
42000023: retw.n
42000100 <one>:
42000100: entry a1, 1000
42000200 <two>:
42000200: entry a1, 2000
"""
        self.assertEqual(path_through(text, "poll"), [("poll", 100), ("two", 2000)])

    def test_code_words_are_read_little_endian_from_the_data_columns(self):
        dump = """
firmware:     file format elf32-xtensa-le

Contents of section .rodata:
 3c000120 14e12942 00000000 c8b72942 ffffff3f  ..)B......)B...?
 3c000130 14e12942 7f                          ..)B.
"""
        self.assertEqual(sorted(set(code_words(dump.splitlines()))),
                         [0x4229b7c8, 0x4229e114])

    def test_each_member_of_a_cycle_counts_once(self):
        text = """42000000 <poll>:
42000000: entry a1, 100
42000003: call8 42000100 <a>
42000100 <a>:
42000100: entry a1, 1000
42000103: call8 42000200 <b>
42000200 <b>:
42000200: entry a1, 2000
42000203: call8 42000100 <a>
42000206: call8 42000300 <leaf>
42000300 <leaf>:
42000300: entry a1, 64
"""
        path = path_through(text, "poll")
        self.assertEqual(sum(size for _, size in path), 3164)
        self.assertEqual(len(path), 4)

    def test_the_answer_does_not_depend_on_which_member_is_entered_first(self):
        # A walk that cuts a cycle where it finds it remembers `b` without `a`.
        text = """42000000 <poll>:
42000000: entry a1, 32
42000003: call8 42000100 <a>
42000006: call8 42000200 <b>
42000100 <a>:
42000100: entry a1, 1000
42000103: call8 42000200 <b>
42000200 <b>:
42000200: entry a1, 32
42000203: call8 42000100 <a>
"""
        self.assertEqual(sum(size for _, size in path_through(text, "poll")), 1064)

    def test_the_communicator_path_starts_under_the_constructor(self):
        text = f"""42000000 <{TASK}>:
42000000: entry a1, 2336
42000003: call8 42000100 <{APP}>
42000100 <{APP}>:
42000100: entry a1, 25328
"""
        self.assertEqual(communicator_path(parsed(text)), [(TASK, 2336), (APP, 25328)])

    def test_a_shallower_redraw_keeps_the_gate_when_the_constructor_is_not_deepest(self):
        text = f"""42000000 <{TASK}>:
42000000: entry a1, 32
42000003: call8 42000100 <{APP}>
42000006: call8 42000200 <redraw>
42000100 <{APP}>:
42000100: entry a1, 64
42000200 <redraw>:
42000200: entry a1, 1000
"""
        self.assertEqual(communicator_path(parsed(text)), [(TASK, 32), ("redraw", 1000)])

    def test_a_missing_task_is_not_a_pass(self):
        with self.assertRaises(SystemExit):
            communicator_path(parsed("42000000 <other>:\n42000000: entry a1, 32\n"))

    def test_a_task_that_cannot_be_followed_is_not_a_pass(self):
        text = f"""42000000 <{TASK}>:
42000000: entry a1, 32
42000003: callx8 a8
42000100 <{APP}>:
42000100: entry a1, 25328
"""
        with self.assertRaises(SystemExit):
            communicator_path(parsed(text))

    def test_a_report_keeps_the_largest_frames_in_call_order(self):
        path = [(f"f{size}", size) for size in range(1, PATH_FRAMES + 3)]
        path.reverse()
        kept = largest_frames(path)
        self.assertEqual(len(kept), PATH_FRAMES)
        self.assertEqual(kept[0], ("f12", 12))
        self.assertEqual(kept[-1], ("f3", 3))


if __name__ == "__main__":
    unittest.main()
