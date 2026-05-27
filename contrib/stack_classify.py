# Copyright (c) 2026, Oracle and/or its affiliates.
"""Match & group tasks by identical segments in their stack trace"""
import argparse
import typing as t

from drgn import Object
from drgn import Program
from drgn.helpers.linux import cpu_curr
from drgn.helpers.linux import for_each_online_cpu
from drgn.helpers.linux import for_each_task
from drgn.helpers.linux import kernel_stack_trace
from drgn.helpers.linux import StackKind
from drgn.helpers.linux import StackSegment
from drgn.helpers.linux import task_state_to_char


SegmentId = t.Tuple[str, ...]


class StackGroup(t.NamedTuple):
    """Represents a group of tasks sharing an identical segment"""

    tasks: t.List[Object]
    """List of ``struct task_struct *`` of tasks sharing the segment"""
    segment_id: SegmentId
    """A hashable identifier of the segment (see segment_id() below)"""
    sample_segment: StackSegment
    """A sample segment fgrom the first task"""


StackRegistry = t.Dict[SegmentId, StackGroup]


def segment_id(segment: StackSegment):
    """
    Return a hashable identifier for a segment based on the segment kind and the
    frame names. EG:

       (IRQ, do_irq, device_irq, ...)
    """
    return tuple(
        [segment.kind.name]
        + [frame.name for frame in segment.frames]
    )


def classify_stacks(prog: Program, tasks: t.Iterable[Object]) -> StackRegistry:
    """
    For each stack segment of each task, create a StackGroup and return all
    aggregated groups as a dictionary.
    """
    segment_to_group = {}
    for task in tasks:
        trace = kernel_stack_trace(task)
        for segment in trace.segments:
            if segment.kind in (StackKind.USER, StackKind.UNKNOWN):
                continue
            seg_id = segment_id(segment)
            if seg_id in segment_to_group:
                segment_to_group[seg_id].tasks.append(task)
            else:
                segment_to_group[seg_id] = StackGroup([task], seg_id, segment)
    return segment_to_group


def print_group(group: StackGroup, indent: int = 0) -> None:
    """
    Print a stack group. The format is intended to be compact: easy to fit many
    groups on a screen, but not too easy to read. This way hundreds or thousands
    of similar stacks could fit into a few screenfuls of information.
    """
    indent_spc = " " * indent
    frames = "/".join(group.segment_id[1:])
    print(f"{indent_spc}GROUP: {group.segment_id[0]}: {frames}")
    samples = []
    for task in group.tasks[:5]:
        comm = task.comm.string_().decode("ascii", errors="backslashreplace")
        pid = task.pid.value_()
        samples.append(f"{comm}({pid})")
    if len(group.tasks) > len(samples):
        samples.append("...")
    samples_str = ", ".join(samples)
    print(f"{indent_spc}TASKS: {len(group.tasks):> 4d}  {samples_str}")


def print_registry(reg: StackRegistry, indent: int = 0, top_n: int = 0, min_count: int = 0) -> None:
    """
    Print the entire registry of stack groups, subject to filtering by top N or
    minimum group size (or both).
    """
    groups = sorted(reg.values(), reverse=True, key=lambda s: len(s.tasks))
    for i, group in enumerate(groups):
        if top_n > 0 and i >= top_n:
            break
        if len(group.tasks) < min_count:
            break
        if i > 0:
            print()
        print_group(group, indent=indent)


def online_classify(prog: Program, top_n: int = 0, min_count: int = 0):
    """
    Classify on-CPU stacks and print the resulting groups
    """
    tasks = (cpu_curr(prog, cpu) for cpu in for_each_online_cpu(prog))
    registry = classify_stacks(prog, tasks)
    if top_n > 0:
        print(f"TOP {top_n} ONLINE STACK SEGMENTS", end="")
    else:
        print("ALL ONLINE STACK SEGMENTS", end="")
    if min_count > 0:
        print(f" WITH >= {min_count} OCCURRENCES")
    else:
        print()
    print_registry(registry, indent=2, top_n=top_n, min_count=min_count)


def hung_classify(prog: Program, top_n: int = 0, min_count: int = 0):
    """
    Classify D-state stacks and print the resulting groups
    """
    tasks = (
        task for task in for_each_task(prog) if task_state_to_char(task) == "D"
    )
    registry = classify_stacks(prog, tasks)
    if top_n > 0:
        print(f"TOP {top_n} D-STATE STACK SEGMENTS", end="")
    else:
        print("ALL D-STATE STACK SEGMENTS", end="")
    if min_count > 0:
        print(f" WITH >= {min_count} OCCURRENCES")
    else:
        print()
    print_registry(registry, indent=2, top_n=top_n, min_count=min_count)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--online", help="group on-CPU stacks", action="store_true"
    )
    group.add_argument(
        "--hung", help="group D-state stacks", action="store_true"
    )
    parser.add_argument(
        "--top-n",
        "-n",
        type=int,
        default=0,
        metavar="N",
        help="print top N results",
    )
    parser.add_argument(
        "--min-count",
        "-m",
        type=int,
        default=0,
        metavar="M",
        help="print results with minimum of M tasks in group",
    )
    args = parser.parse_args()
    prog: Program = globals()["prog"]  # hack to shut up mypy
    if args.online:
        online_classify(prog, top_n=args.top_n, min_count=args.min_count)
    elif args.hung:
        hung_classify(prog, top_n=args.top_n, min_count=args.min_count)
    else:
        print("error: specify either --online or --hung")
