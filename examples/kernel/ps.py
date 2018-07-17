"""A simplified implementation of ps(1) using drgn"""

from drgn.helpers.kernel.pid import for_each_task


print('PID        COMM')
for task in for_each_task(prog):
    pid = task.pid.value_()
    comm = task.comm.string_().decode()
    print(f'{pid:<10} {comm}')