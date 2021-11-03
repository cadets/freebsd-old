CADETS HyperTrace
------------------

This is the main source tree of HyperTrace, a CADETS-derived implementation of
DTrace that supports tracing of virtual machines in real time. HyperTrace works
much like present-day DTrace does, with a few minor user-visible changes.

Currently, HyperTrace only supports one mode of operation where the guest
instruments itself and then uses a hypercall instruction (`vmcall` or `vmmcall`)
to call back a DTrace probe to the host. Different modes of operation are
planned, but not currently supported.


Changes from DTrace
--------------------

High level changes:

  - Support for representing D programs as ELF files after compilation and
    assembly.
  - New linker based on ELF files (currently only in userland).
  - New typing inference and checking algorithms that work on DIF, rather than
    the D language itself. They closely resemble C's typing system, but are
    more strict in some areas, but less strict in others. No additional type
    annotations are needed, everything is inferred.
  - New daemon called `dtraced` which is responsible for transactional
    transmission of assembled D programs between host and any number of guests.
  - New `/etc/rc.d` script for `dtraced`.
  - Added another, optional entry to the DTrace probe specification called
    `target`. Instead of using `provider:module:function:name`, you can now use
    `target:provider:module:function:name`.
  - Support for relocations in DIF (`uload`, `usetx`, `uuload`, `typecast`).
  - `dtrace(1)` is now concurrent and asynchronous, which should be invisible to
    the user unless HyperTrace mode is enabled.
  - The kernel runtime engine for DTrace actions has full tagging in order to
    support dereferencing guest addresses within the host context.

`dtrace(1)` command line interface:

  - Added new command line flag `-E`, specifying that an ELF file should be sent
    to `dtraced` and that `dtrace` is operating in HyperTrace mode.
  - Added new command line flag `-Y`, specifying that an ELF file given to the
    `dtrace` command line utility should be executed.
  - Added new command line flag `-y`, specifying that an ELF file should be
    further processed (applying relocations, etc.) and a new ELF file should be
    produced.

DTrace options:

  - New option: `resolvers`. Currently only on the command line. It takes
    comma-separated arguments, and currently supports `hostname` and `version`,
    signifying that the `target` tuple entry should be resolved as either a
    machine hostname or version of the operating system.
  - New option: `hypertrace`. Specify that we are operating in HyperTrace mode.
    Users should not need to set this manually.

`dtraced` transactional daemon:

  - Manages `/var/ddtrace`.
  - Exposes `/var/ddtrace/sub.sock` that processes can subscribe to.
  - Can only run one instance on the system (`/var/run/dtraced.pid`).
  - Can run in `overlord` mode (usually host machine) or `minion` mode (usually
    guest machines). If you have better naming suggestions, please let me know!
  - Currently doesn't support re-transmission to minions that died with an
    active script. This is planned to be implemented soon.
  - It does not clean up after itself, but launching it again across restarts
    will be done gracefully! All your D programs in ELF file representation will
    be in `/var/ddtrace/base`.


Setup
------

At some point, there will be an `ansible` playbook for use on any machine.
Presently, the playbooks we have are private and specific to our testing
infrastructure. Once we've cleaned it up and have one ready for public
consumption, it will be linked here. Until then, these are the steps necessary
to set up HyperTrace manually:


First, build the source code:

```
make buildworld
make buildkernel
```


and follow the usual FreeBSD installation procedure from source.

```
make installkernel && reboot
```

Once you boot back in:

```
make installworld && reboot
```

With that, you should have HyperTrace installed. However, it is not yet ready
for full use. Enable `dtraced` in `/etc/rc.conf`.

For host machine:

```
dtraced_enable="YES"
dtraced_type="overlord"
```

For guest machine:

```
dtraced_enable="YES"
dtraced_type="minion"
```

And then run

```
service dtraced start
```

You now have a fully functional HyperTrace installation. However, HyperTrace on
its own is not terribly useful. You need some VMs. We suggest that for now, you
just build a VM from the same source and follow the setup for guests described
above using your preferred method.


Running things and Examples
----------------------------


Once you have a full HyperTrace setup, you are ready to run things! Try these
example scripts to start with (make sure `dtraced` is running on both host and
your guests).

Assuming `${TARGET}` is set to the hostname or version of the OS you want to
trace, or a valid glob:


```
dtrace -E -n "$TARGET:syscall:::entry { @[vmname, execname] = count(); }"
dtrace -E -n "$TARGET:syscall:::entry { @[curthread->td_ucred->cr_ruid, curthread->td_cred->cr_rgid] = count(); }"
dtrace -E -n "$TARGET:syscall:::entry { self->ts = timestamp; } $TARGET:syscall:::entry/self->ts/ { @[vmname, probefunc] = quantize(timestamp - self->ts); self->ts = 0; }"
```

Each of the above scripts demonstrates a couple of interesting properties.
Firstly, we show a simple aggregation smoke-test. The second script shows that
HyperTrace can correctly poke into guest memory with the right offsets for guest
types, rather than using those on the host. Finally, the last script shows that
HyperTrace can deal with collision of thread IDs in the kernel without being
confused about namespaces across different guests (and the host). Furthermore,
the timestamps gathered in the last script are in fact gathered on the host, so
they don't suffer any of the traditional issues when it comes to time on virtual
machines.


Source Code Guide
------------------

libdtrace (`cddl/contrib/opensolaris/lib/libdtrace/common`) changes:

New files:

 - `dt_elf.c, dt_elf.h` -- Implements conversion from a DTrace program to ELF.
 - `dt_typefile.c, dt_typefile.h, _dt_typefile.h` -- Similar to
   `dt_module.{c,h}`, but intended for use with HyperTrace, as the API differs
   a little bit.
 - `dt_cfg.{c,h}` -- Control flow graph implemntation for DIF.
 - `dt_basic_block.c, dt_basic_block.h, _dt_basic_block.h` -- Basic block
   implementation for DIF.
 - `dt_ifg.{c,h} -- Information flow graph implementation for DIF.
 - `dt_ifgnode.c, dt_ifgnode.h, _dt_ifgnode_h` -- helpers for IFG.
 - `dt_typing*` -- Implementation of a type inference & checking system on top
   of DIF. Similar to D and C type systems.
 - `dt_resolver.{c,h}` -- A simple implementation to compare the 5th tuple entry
   (standing for target) to various names of the current machine, such as an IP
   address, hostname, FreeBSD version, etc.
 - `dt_prog_link.{c,h}` -- Linking implementation (applying relocations,
   patching up return types, etc.).
 - `dt_linker_subr.{c,h}` -- Linking helpers.
 - `dt_analysis.{c,h}` -- Various helpers.
 - `dt_benchmark.{c,h}` -- DTrace benchmarking API.
 - `dt_hashmap.{c,h}` -- Hash map implementation for DTrace.

There are plenty of changes in existing libdtrace files as well.


dtraced (`cddl/contrib/opensolaris/cmd/dtraced`):

 - `dtraced.c` -- `main` function, initialization, main thread.
 - `dtraced_chld.{c,h}` -- child management.
 - `dtraced_*job.{c,h}` -- processing functions of various jobs.
 - `dtraced_connection.{c,h}, _dtraced_connection.h` -- management of dtraced
   socket connections.
 - `dtraced_directory.{c,h}` -- directory-related functionality.
 - `dtraced_dttransport.{c,h}` -- dtraced communication with dttransport.
 - `dtraced_errmsg.{c,h}` -- logging functions.
 - `dtraced.h` -- main includes.
 - `dtraced_lock.{c,h}` -- locking helpers.
 - `dtraced_misc.{c,h}` -- various functions that don't fit anywhere else.
 - `dtraced_state.{c,h}` -- state management.

dttransport (`sys/dev/dttransport`):

 - `dttransport.{c,h}` -- simple kernel module to forward DTrace-related
   events from the virtio frontend to userspace.

dtvirt (`sys/cddl/dev/dtvirt`):

 - `dtvirt.{c,h}` -- shim layer to bhyve from `dtrace.ko`.

virtio-dtrace:

 - `sys/dev/virtio/dtrace/virtio_dtrace.{c,h}` -- virtio dtrace frontend.
 - `usr.sbin/bhyve/pci_virtio_dtrace.c` -- virtio dtrace backend.

hypertrace (`sys/cddl/dev/hypertrace`):

 - `hypertrace.{c,h}` -- a kernel module for safely managing HyperTrace state.
 - `hypertrace_map.c` -- probe map helpers.

packet tagging:

 - `sys/kern/subr_mbufid.c` -- Core implementation of packet tagging.
 - `sys/sys/_mbufid.h` -- structs/defines.
 - `sys/sys/mbufid.h` -- mbuf tagging header.
 - `sys/kern/subr_msgid.c` -- light-weight alternative to UUIDs (used for tags).
 - `sys/sys/_msgid.h` -- structs/defines.
 - `sys/sys/msgid.h` -- msgid header.

Packet tagging includes many changes in various existing files revolving around
networking, such as tap, tun, bpf, various mbuf copy routines and virtio-net.

dtracedctl (`cddl/contrib/opensolaris/cmd/dtracedctl`):

 - `dtracedctl.{c,h}` -- A simple interface to `dtraced`.

hypercall interface:
 - `sys/amd64/amd64/bhyve_hypercall.S` -- implementation of hypercalls.
 - `sys/amd64/include/bhyve_hypercall.h` -- header for hypercalls.

This functionality also involves heavy changes to the bhyve kernel module
(`vmm.ko`).

Nested page table walk:

 - `sys/cddl/dev/dtrace/amd64/dtrace_vm_subr.c` -- Implements a nested page
   table walk suitable for use inside the DTrace probe context.

