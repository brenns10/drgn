#!/usr/bin/env python3
import typing as t

import drgn
from drgn import TypeKind


def has_member(obj: drgn.Object, name: str) -> bool:
    """
    Return true if a given object has a member with the given name.
    :param obj: Drgn object to check
    :param name: string member name to check
    :returns: whether the object has a member by that name
    """
    try:
        obj.member_(name)
        return True
    except LookupError:
        return False


def task_thread_info(task: drgn.Object) -> drgn.Object:
    """
    Return a task's ``thread_info``

    This is an equivalent to the kernel function / inline / macro
    ``task_thread_info()``, but it must cover a wide variety of versions and
    configurations.

    :param task: Pointer to a ``struct task_struct``
    :returns: Pointer to a ``struct thread_info*`` for this task
    """
    if has_member(task, "thread_info"):
        return task.thread_info.address_of_()
    return drgn.cast("struct thread_info *", task.stack)


def task_cpu(task: drgn.Object) -> int:
    """
    Return the CPU on which a task is running.

    This is an equivalent to the kernel function ``task_cpu()``, but it covers
    a wide variety of variations in kernel version and configuration. It would
    be a bit impractical to spell out all the variants, but essentially, if
    there's a "cpu" field in ``struct task_struct``, then we can just use that.
    Otherwise, we need to get it from the ``thread_info``.

    :param task: Pointer to ``struct task_struct``
    :retruns: The cpu as a Python int
    """
    if has_member(task, "cpu"):
        return task.cpu.value_()
    return task_thread_info(task).cpu.value_()


def frame_name(frame: drgn.StackFrame) -> str:
    """Return a suitable name for a stack frame"""
    if frame.name is not None:
        return frame.name
    try:
        return frame.symbol().name
    except LookupError:
        return f"{frame.pc:016x}"


def is_pt_regs(type_: drgn.Type) -> bool:
    """
    Determine whether a type refers to struct pt_regs, (pointer or direct)
    """
    if type_.kind == TypeKind.POINTER:
        type_ = type_.type
    if type_.kind != TypeKind.STRUCT:
        return False
    return type_.type_name() == "struct pt_regs"


def _bt_internal(
    task: drgn.Object,
    trace: drgn.StackTrace,
    show_vars: bool = False,
    start_index: int = 0,
) -> t.List[drgn.StackFrame]:
    prog = task.prog_
    if start_index == 0:
        cpu = task_cpu(task)
        taskp = task.value_()
        pid = task.pid.value_()
        comm = task.comm.string_().decode()
        print(
            f'PID: {pid:<7d}  TASK: {taskp:x}  CPU: {cpu}  COMMAND: "{comm}"'
        )
    last_pt_regs = None
    res = []
    for i, frame in enumerate(trace):
        res.append(frame)
        sp = frame.sp  # drgn 0.0.22
        intr = "!" if frame.interrupted else " "
        name = frame_name(frame)
        out_line = (
            f"{intr}#{i + start_index:2d} [{sp:x}] {name} at {frame.pc:x}"
        )
        try:
            file_, line, col = frame.source()
            out_line += f" {file_}:{line}:{col}"
        except LookupError:
            pass
        print(out_line)

        # Format the registers, but only when we've reached a stack frame with
        # a different stack pointer than the previous. That is: only when we
        # reach the frame for a non-inline function. Also, only output
        # registers when we have show_vars=True.
        if show_vars and (
            i == len(trace) - 1 or trace[i].sp != trace[i + 1].sp
        ):
            registers = frame.registers()
            regnames = list(registers.keys())
            for i in range(0, len(regnames), 3):
                print(
                    " " * 5
                    + "  ".join(
                        f"{reg.upper():>3s}: {registers[reg]:016x}"
                        for reg in regnames[i : i + 3]
                    )
                )

        # This requires drgn 0.0.22+.
        for local in frame.locals():
            try:
                val = frame[local]
            except KeyError:
                continue
            if is_pt_regs(val.type_) and not val.absent_:
                last_pt_regs = val
            if show_vars:
                val_str = val.format_(dereference=False).replace(
                    "\n", "\n     "
                )
                print(" " * 5 + f"{local} = {val_str}")
    if last_pt_regs is not None:
        # TODO: improve detection of kernel addresses
        sp = last_pt_regs.sp.value_()
        if sp != trace[0].sp and sp & 0xF000000000000000:
            # kernel address
            print(" -- continuing to previous stack -- ")
            res += _bt_internal(
                task,
                prog.stack_trace(last_pt_regs),
                show_vars=show_vars,
                start_index=len(res),
            )
        else:
            # user address
            print(f" -- interrupted user address {last_pt_regs.ip} --")
    else:
        print(" -- end of stack trace, no trailing pt_regs --")
    return res


def bt(
    task: t.Union[drgn.Object, drgn.Thread],
    show_vars: bool = False,
) -> t.List[drgn.StackFrame]:
    """
    Format a crash-like stack trace.

    This formats a stack trace reminiscent of (but not strictly identical to)
    the crash "bt" command. Not all of crash's bt features are yet implemented,
    but there is one feature which already surpasses crash's implementation:
    printing variable values. When enabled, at each stack frame there will be a
    listing of each local variable or function arg, and its value. The value
    may be "absent" if it was optimized out or if the compiler/debuginfo is not
    able to provide enough information to retrieve it.

    This helper also mitigates some issues seen with drgn's built-in stack
    trace functionality: sometimes, the stack trace is truncated (typically at
    a page fault or IRQ boundary). This stack trace formatter looks for
    variables with type ``struct pt_regs *``, which indicates that there's a
    previous interrupted stack. In that case, we continue formatting that
    trace. In order to allow users to view all the stack frames revealed by
    this method, we return a list of stack frames too.

    :param task: Either a task struct pointer, or a drgn Thread object.
    :param show_vars: Whether to enable formatting variables for each frame.
    :returns:
    """
    if isinstance(task, drgn.Thread):
        task = task.object
    elif not isinstance(task, drgn.Object):
        raise ValueError("Need a drgn.Thread or drgn.Object representing task")
    return _bt_internal(
        task,
        task.prog_.stack_trace(task),
        show_vars=show_vars,
    )
