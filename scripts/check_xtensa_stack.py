#!/usr/bin/env python3
"""Reject oversized Xtensa frames, the known task construction chains, and,
on a communicator, a main stack that cannot hold the interface's deepest path.

This is a necessary budget check, not an RTOS-task stack proof. Calls through
a vtable are invisible to it, and radio task stacks still need hardware
measurement. Uses the objdump shipped with the ESP toolchain; no Python
dependencies.
"""

import argparse
import collections
import re
import subprocess
import sys

HEADER = re.compile(r"([0-9a-f]+) <(.+)>:")
ENTRY = re.compile(r"\bentry\s+a1,\s*(0x[0-9a-f]+|[0-9]+)")
LOAD = re.compile(r"\bl32r\s+(a\d+),.*\(([0-9a-f]+) <")
SUB = re.compile(r"\bsub\s+(a\d+),\s*a1,\s*(a\d+)")
MOVSP = re.compile(r"\bmovsp\s+a1,\s*(a\d+)")
INSTRUCTION = re.compile(r"\s*([0-9a-f]+):\s+(\S+)\s*(.*)")
# A direct call, or a jump that may be a tail call. A jump within a function
# names an address that starts no function, and so is no edge.
CALL = re.compile(r"\b(?:call\d+|j)\s+([0-9a-f]+)\b")
BRANCH = re.compile(r"(?:b[\w.]*|loop\w*)\s.*?\b([0-9a-f]{8})\b")
# What control does not continue past.
ENDS = frozenset(("retw", "retw.n", "ret", "ret.n", "j", "jx", "ill", "ill.n",
                  "rfe", "rfi", "rfwo", "rfwu"))
# A word of the hex dump's data columns.
DUMP = re.compile(r" [0-9a-f]+ ((?:[0-9a-f]{8} ?){1,4})")
# Where code runs, as a jump table would point to it.
CODE_START = 0x40000000
CODE_END = 0x44000000
# How far into a function its prologue reaches.
PROLOGUE_LINES = 8

# The task the interface runs in, and the constructor it must reach. Both are
# matched as mangled, where a path's identifiers appear whole.
COMMUNICATOR_TASK = re.compile(r"11TaskStorage.*12communicator11___task_task.*4poll")
COMMUNICATOR_APP = re.compile(r"8external12communicator")
# What the main stack needs beyond the task's deepest path. Interrupts run on
# whatever stack they land on: one, and a higher priority one preempting it,
# reach about 1.25 KiB each with their trap frames, and startup and the
# executor sit under the task with a few hundred bytes. That is under 3 KiB
# that can be counted; radio blobs and vtable calls reach further by an amount
# that cannot.
PATH_MARGIN = 4096
# How many of a path's frames a report names.
PATH_FRAMES = 10
# How much of a demangled name a report shows: view types run to thousands of
# characters, where the start says which view and the end which method.
NAME_HEAD = 72
NAME_TAIL = 48

Function = collections.namedtuple("Function", "address name frame targets")


def stack_size(symbols):
    bounds = {}
    for line in symbols.splitlines():
        fields = line.split()
        if fields and fields[-1] in ("_stack_start", "_stack_end"):
            bounds[fields[-1]] = int(fields[0], 16)
    return bounds["_stack_start"] - bounds["_stack_end"]


def prologue_frame(name, lines):
    """Read both ENTRY-immediate and the large-frame MOVSP prologue."""
    size = None
    # Large frames exceed ENTRY's immediate range. LLVM emits ENTRY
    # for the register window, then L32R/SUB/MOVSP for the remainder.
    literal = None
    decrement = None
    for line in lines:
        entry = ENTRY.search(line)
        if entry:
            size = int(entry[1], 0)
        load = LOAD.search(line)
        if load:
            literal = (load[1], int(load[2], 16))
        sub = SUB.search(line)
        if sub and literal and sub[2] == literal[0]:
            decrement = (sub[1], literal[1])
        move = MOVSP.search(line)
        if move:
            if size is None or decrement is None or move[1] != decrement[0]:
                raise ValueError(f"unrecognized stack prologue: <{name}>")
            size += decrement[1]
            break
    return size


def code_words(lines):
    """Each word of objdump's `-s` hex dump that could be a code address.
    Jump tables are made of these, in `.rodata`."""
    for line in lines:
        dump = DUMP.match(line)
        if not dump:
            continue
        for word in dump[1].split():
            if len(word) == 8:
                value = int.from_bytes(bytes.fromhex(word), "little")
                if CODE_START <= value < CODE_END:
                    yield value


def control_targets(instructions, tables):
    """Everything called or loaded from a literal by what control can reach,
    from the function's start and from `tables`, since most calls here are
    an L32R and a CALLX8.

    Reachability is what tells code from data. LLVM puts literal pools inside
    functions, and objdump decodes them as instructions, so a sweep of every
    line finds calls no code makes: a pool word that decodes to an L32R of a
    real function has closed a cycle around the whole view chain.
    """
    places = {address: index for index, (address, _, _) in enumerate(instructions)}
    pending = [0] + [index for address, index in places.items() if address in tables]
    seen = set()
    targets = set()
    while pending:
        index = pending.pop()
        while index < len(instructions) and index not in seen:
            seen.add(index)
            _, mnemonic, operands = instructions[index]
            if mnemonic.startswith("."):
                break
            text = f"{mnemonic} {operands}"
            load = LOAD.search(text)
            if load:
                targets.add(int(load[2], 16))
            target = CALL.search(text) or BRANCH.match(text)
            if target:
                address = int(target[1], 16)
                targets.add(address)
                if address in places:
                    pending.append(places[address])
            if mnemonic in ENDS:
                break
            index += 1
    return targets


def functions(lines, tables=frozenset()):
    """Each function in objdump's disassembly, read a line at a time: only
    one function's instructions are held, so memory stays flat however large
    the program. What starts no function among its targets is dropped when
    the graph is walked."""
    address = None
    name = None
    prologue = []
    instructions = []

    def function():
        return Function(address, name, prologue_frame(name, prologue),
                        control_targets(instructions, tables))

    for line in lines:
        header = HEADER.fullmatch(line.rstrip("\n"))
        if header:
            if name is not None:
                yield function()
            address = int(header[1], 16)
            name = header[2]
            prologue = []
            instructions = []
        elif name is not None:
            if len(prologue) < PROLOGUE_LINES:
                prologue.append(line)
            instruction = INSTRUCTION.match(line)
            if instruction:
                instructions.append((int(instruction[1], 16), instruction[2], instruction[3]))
    if name is not None:
        yield function()


def function_frames(lines):
    """Each function's frame, as `(mangled name, size)`."""
    return [(function.name, function.frame) for function in functions(lines)
            if function.frame is not None]


def deepest_path(graph, root):
    """The costliest call path from `root` through `graph`, a dict of
    `Function` by address, in call order, and every address it can reach.

    Components are completed callees first (Tarjan), so each is summed over
    what is already known of what it calls. A call cycle has no bound that
    can be read from the code, so each of its members counts once: one trip
    around it.
    """
    sys.setrecursionlimit(max(sys.getrecursionlimit(), len(graph) + 100))
    order = {}
    low = {}
    pending = []
    # By address: the component's total, its members, and the costliest
    # component below it.
    deepest = {}

    def visit(address):
        order[address] = low[address] = len(order)
        pending.append(address)
        for target in graph[address].targets:
            if target not in graph:
                continue
            if target not in order:
                visit(target)
                low[address] = min(low[address], low[target])
            elif target not in deepest:
                low[address] = min(low[address], order[target])
        if low[address] != order[address]:
            return
        start = pending.index(address)
        members = pending[start:]
        del pending[start:]
        below = max((deepest[target] for member in members
                     for target in graph[member].targets if target in deepest),
                    key=lambda component: component[0], default=None)
        total = sum(graph[member].frame or 0 for member in members)
        component = (total + (below[0] if below else 0), members, below)
        for member in members:
            deepest[member] = component

    visit(root)
    path = []
    component = deepest[root]
    while component:
        path += [(graph[member].name, graph[member].frame or 0) for member in component[1]]
        component = component[2]
    return path, set(deepest)


def communicator_path(program):
    """The communicator task's deepest path: from its poll, so that the
    frames under the constructor count and the redraw path, which does not
    pass through the constructor, is walked too.

    A task the graph cannot follow would pass with a path of one frame, so
    one that no longer reaches the constructor is an error, not a pass.
    """
    graph = {function.address: function for function in program}
    root = next((function for function in program
                 if COMMUNICATOR_TASK.search(function.name)), None)
    if root is None:
        raise SystemExit("stack check: communicator task not found")
    path, reached = deepest_path(graph, root.address)
    if not any(COMMUNICATOR_APP.search(graph[address].name) for address in reached):
        raise SystemExit("stack check: communicator task does not reach "
                         "external::communicator; the call graph is incomplete")
    return path


def demangle(cxxfilt, names):
    """`names` demangled, without crate disambiguators. Mangled names stay
    short however deep the generics run; demangled, they spell every type
    out, so only names that are matched or reported are demangled."""
    if not names:
        return {}
    out = subprocess.run([cxxfilt, "-i"], input="\n".join(names) + "\n",
                         capture_output=True, text=True, check=True).stdout
    return dict(zip(names, out.splitlines()))


# Tasks whose futures main constructs on its own stack at startup: the
# device task's holds the large boot snapshot, and the radio task's holds
# the whole radio driver, which grows with each chip a board may carry.
TASKS = ("device_task", "radio_task")


def construction_candidates(frames):
    """The frames any task's construction chain could use, by mangled name:
    identifiers appear whole in mangled names, so the candidates are found
    before anything is demangled."""
    return [(name, size) for name, size in frames
            if "embassy_main_task" in name or any(task in name for task in TASKS)]


def task_construction(frames, task):
    """Conservative lower bound for main -> `task` -> future initializer.

    Embassy's generated constructor can copy the large boot snapshot while its
    initializer materializes the entire future. If LLVM keeps the constructor
    out of line, all three frames coexist. Single-frame-plus-reserve checking
    missed this on T-Beam. An inlined stage has no separate frame to add.
    This intentionally checks our known startup path, not a general call graph.
    """
    main = []
    constructor = []
    initializer = []
    for name, size in frames:
        if re.fullmatch(r"firmware_\w+::__main::____embassy_main_task::"
                        r"____embassy_main_task_inner_function::\{closure#0\}", name):
            main.append((name, size))
        elif re.fullmatch(rf"firmware_\w+::{task}", name):
            constructor.append((name, size))
        elif ("UninitCell<" in name and f"::__{task}_task::" in name
              and "::write_in_place::<" in name):
            initializer.append((name, size))
    if not main:
        return []
    return [max(stage, key=lambda frame: frame[1])
            for stage in (main, constructor, initializer) if stage]


def device_task_construction(frames):
    return task_construction(frames, "device_task")


def largest_frames(path):
    """The path's largest frames, still in call order."""
    largest = sorted(path, key=lambda frame: frame[1], reverse=True)[:PATH_FRAMES]
    return [frame for frame in path if frame in largest]


def shortened(name):
    if len(name) <= NAME_HEAD + NAME_TAIL:
        return name
    return f"{name[:NAME_HEAD]} ... {name[-NAME_TAIL:]}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf")
    parser.add_argument("--objdump", default="xtensa-esp32s3-elf-objdump")
    parser.add_argument("--cxxfilt", default=None,
                        help="demangler (default: objdump's sibling c++filt)")
    parser.add_argument("--reserve", type=int, default=8192,
                        help="minimum space left beyond any single frame (default: 8192)")
    parser.add_argument("--communicator", action="store_true",
                        help="also require the communicator task's deepest call path, "
                             f"plus {PATH_MARGIN} bytes, to fit the main stack")
    args = parser.parse_args()
    cxxfilt = args.cxxfilt or re.sub(r"objdump$", "c++filt", args.objdump)
    symbols = subprocess.check_output([args.objdump, "-t", args.elf], text=True)
    available = stack_size(symbols)
    tables = frozenset()
    if args.communicator:
        dump = subprocess.check_output([args.objdump, "-s", "-j", ".rodata", args.elf], text=True)
        tables = frozenset(code_words(dump.splitlines()))
    with subprocess.Popen([args.objdump, "-d", "--no-show-raw-insn", args.elf],
                          stdout=subprocess.PIPE, text=True) as objdump:
        program = list(functions(objdump.stdout, tables))
    if objdump.returncode:
        raise SystemExit(f"stack check: {args.objdump} failed")
    frames = [(function.name, function.frame) for function in program
              if function.frame is not None]
    if not frames:
        raise SystemExit("stack check: no Xtensa function prologues found")
    # Only the startup path's stages and what fails are named.
    failing = [(name, size) for name, size in frames if size + args.reserve > available]
    candidates = construction_candidates(frames)
    path = communicator_path(program) if args.communicator else []
    names = demangle(cxxfilt, sorted({name for name, _ in failing + candidates + path}))
    failures = [(names[name], size) for name, size in failing]
    candidates = [(names[name], size) for name, size in candidates]
    constructions = [(task, task_construction(candidates, task)) for task in TASKS]
    for task, construction in constructions:
        construction_size = sum(size for _, size in construction)
        if construction_size > available:
            print(f"stack check FAILED: {task} construction needs at least "
                  f"{construction_size} bytes > {available} byte main stack")
            for name, size in construction:
                print(f"  {size} bytes: {name}")
            raise SystemExit(1)
    if failures:
        for name, size in failures:
            print(f"stack check FAILED: {size} byte frame + {args.reserve} reserve > "
                  f"{available} byte main stack: {name}")
        raise SystemExit(1)
    if path:
        path_size = sum(size for _, size in path)
        spare = available - path_size - PATH_MARGIN
        needed = (f"communicator path of {len(path)} calls: {path_size} bytes + "
                  f"{PATH_MARGIN} margin")
        if spare < 0:
            print(f"stack check FAILED: {needed} > {available} byte main stack, "
                  f"{-spare} bytes short")
        else:
            print(f"stack check: {needed}, {spare} bytes spare")
        for name, size in largest_frames(path):
            print(f"  {size} bytes: {shortened(names[name])}")
        if spare < 0:
            raise SystemExit(1)
    print(f"stack check: main stack {available} bytes; "
          f"largest individual frame {max(size for _, size in frames)} bytes; "
          f"reserve {args.reserve} bytes")
    for task, construction in constructions:
        if construction:
            construction_size = sum(size for _, size in construction)
            print(f"stack check: {task} construction lower bound "
                  f"{construction_size} bytes; {available - construction_size} bytes "
                  "remain for callers, interrupts, and other nested work")


if __name__ == "__main__":
    main()
