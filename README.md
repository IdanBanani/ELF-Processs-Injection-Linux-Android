Pull requests are welcomed.

- [ ] Try to run the given injection techniques code.
- [ ] Understand how each technique works
- [ ] Understand the attack vector and the different parts (stages) of the chain    
  (i.e the bridgehead shellcode, injection to process memory,LPE, when to create a new process etc.)
- [ ] Describe the need for a custom statically PIC compiled elf (Shared object library) loader shellcode.  
- [ ] Injection vs patching at runtime?
- [ ] Implement / improve it by yourself.

# Modern Android Notes

This repository is a research index, not a copy-paste implementation guide. The
useful question for modern Android is no longer only "how do I call `dlopen` in
another process?". The harder questions are:

- Which process lifecycle point do you control?
- Which SELinux/domain and ptrace constraints apply?
- Who maps the library: Android's linker or a custom loader?
- How deterministic does the mapped address need to be?
- How will native code cross into ART/JNI/DEX code once it is resident?

The notes below assume an authorized post-exploitation research setting. When
this document says "RCE" in the Android target-entry discussion, read that as
shorthand for a completed chain: native code execution already exists, privilege
escalation to a useful system/root-equivalent context has already happened, and
SELinux/domain restrictions have either been bypassed, changed by policy, or are
otherwise not the blocker being studied. This repository is about what the
loader/injector does after that point.

## Short Conclusions

- For a modern zygote or `system_server` lifecycle model, study
  [ReZygisk](https://github.com/PerformanC/ReZygisk) before old BinderJack-style
  examples. Its interesting part is not the module API; it is the early zygote
  tracer, custom loader, and hooks around app/system-server specialization.
- For late injection into an already-running, attachable process, study
  [AndKittyInjector](https://github.com/MJx0/AndKittyInjector). It is a more
  complete modern ptrace-based injector than the older examples listed below.
- For linker namespace and symbol-resolution work after code is already inside
  the target process, study [xDL](https://github.com/hexhacking/xDL).
- For linker-managed placement, do not skip `android_dlextinfo`. The
  `ANDROID_DLEXT_RESERVED_ADDRESS`, `ANDROID_DLEXT_RESERVED_ADDRESS_HINT`, and
  `ANDROID_DLEXT_RESERVED_ADDRESS_RECURSIVE` flags are the public Android
  interface for asking the linker to use caller-provided address space.
- For true custom ELF loading, compare against Chromium/NDK Crazy Linker and
  AOSP bionic's linker. For in-memory linker-mediated loading, compare against
  LibcoreSyscall's `DlExtLibraryLoader`.
- For native or ART hooks after residency, study
  [ShadowHook](https://github.com/bytedance/android-inline-hook),
  [ByteHook](https://github.com/bytedance/bhook), and
  [LSPlant](https://github.com/LSPosed/LSPlant). These are not process injectors
  by themselves.
- Treat [injectvm-binderjack](https://github.com/Chainfire/injectvm-binderjack)
  and simple ptrace examples as historical references. They are useful for
  understanding the idea, but they do not model modern Android linker namespaces,
  zygote timing, ART changes, or current policy boundaries well enough.

## Mental Model

Think about process injection as a chain of separate problems:

1. **Target entry**: how execution first crosses into the target process.
   Common families are late ptrace attach, early zygote tracing, preload/module
   frameworks, or already-running in-process code.
2. **Remote memory**: how scratch memory, file bytes, and final executable
   mappings appear in the target address space.
3. **ELF loading**: whether Android's linker performs `dlopen` /
   `android_dlopen_ext`, or whether a custom loader maps `PT_LOAD` segments and
   applies relocations itself.
4. **Symbol discovery**: how addresses are located in the target, usually from
   `/proc/<pid>/maps`, ELF parsing, local-to-remote offsets for the same mapped
   object, linker metadata, or ART/runtime exports.
5. **Execution handoff**: whether the injected library starts through an
   exported function, `JNI_OnLoad`, a zygote module callback, a JNI native-method
   replacement, or an ART hook.
6. **Managed-code bridge**: native residency is not enough for DEX execution.
   DEX bytes still need an ART-visible loading path, a recoverable `JavaVM *`,
   a current-thread `JNIEnv *`, a class loader context, and compatibility with
   hidden API and process lifecycle restrictions.

## Memory Mapping and Placement

The address where an injected shared library lands is determined by the loading
path, not just by the fact that a remote call happened.

**System linker path**

When the target process executes `dlopen` or `android_dlopen_ext`, Android's
linker owns the final mapping choices, relocation processing, dependency
resolution, and constructor calls. A memfd-backed load changes the backing object
and avoids a normal filesystem path, but it does not by itself make the final
base address deterministic. ASLR, existing VMAs, linker namespace rules, and
architecture-specific loader behavior still matter.

This is the path used by many late injectors. For example, AndKittyInjector
resolves remote `dlopen` / `__loader_dlopen` and can use memfd plus
`ANDROID_DLEXT_USE_LIBRARY_FD` through `android_dlopen_ext`.

**`android_dlextinfo` reserved-address path**

`android_dlopen_ext` accepts Android-specific loading options through
`android_dlextinfo`. This is the important middle ground between "let the linker
choose everything" and "write a full custom ELF loader".

The placement-relevant fields are `reserved_addr` and `reserved_size`; they only
matter when paired with the reserved-address flags below.

This means a remote `mmap` call can matter to final library placement only if
the reserved region it creates is then handed to the target process linker via
`android_dlopen_ext` and `android_dlextinfo`. A scratch `mmap` used only for
strings, temporary buffers, or RPC arguments does not constrain where `dlopen`
maps the final shared object.

**Injector process versus target process**

Actions in the injector process do not directly reserve memory, change linker
state, or choose load addresses in the target process. Android processes have
separate virtual address spaces and separate dynamic-linker state. A local
`dlopen` / `android_dlopen_ext` experiment can help identify ABI, API-level
behavior, ELF size, dependency closure, SONAME, relocation style, and symbol
offsets for the same on-disk library, but it does not make the target process
pick the same base address.

The useful relationship is indirect:

- **Static metadata** can be learned locally. Segment spans, alignment,
  `DT_NEEDED` dependencies, exported symbol offsets, and RELRO size are
  properties of the ELF files. Those values can help estimate how large a
  target-side reservation would need to be.
- **Absolute addresses are process-local.** A `dlsym` result in the injector is
  not a target address. At most, if the exact same library build is mapped in
  both processes, the symbol offset relative to that library's load bias can be
  reused after finding the target's own mapping.
- **Post-fork local loads do not propagate.** Loading a library inside an app
  process after it forked from zygote affects that process only.
- **Pre-fork zygote state can propagate.** Mappings and reserved holes created
  in zygote before fork can be inherited by app processes and `system_server`.
  WebView's reserved-address/RELRO design relies on this kind of controlled
  lifecycle, not on a random injector process influencing another process after
  the fact.
- **Shared RELRO is explicit.** A RELRO file created in one process is useful to
  another only when the library and relevant dependencies are loaded at the same
  addresses and the target load uses the matching `android_dlextinfo` flags.

So the rule is: local actions can inform a target-side loading plan, and
pre-fork zygote actions can shape descendants, but target layout is affected
only by target-side mappings, inherited mappings, and the `android_dlopen_ext`
arguments actually used by the target process.

Other `android_dlextinfo` flags solve adjacent problems. Read them as linker
policy inputs, not as a generic remote-memory API:

| Flag | What it changes | Important caveat |
| --- | --- | --- |
| `ANDROID_DLEXT_RESERVED_ADDRESS` | Requires the linker to load into the caller-supplied reserved range. | The range must already exist in the target process and must be large enough, or loading fails. |
| `ANDROID_DLEXT_RESERVED_ADDRESS_HINT` | Treats the caller-supplied range as preferred placement. | If the range is unsuitable, the linker can ignore the hint and choose another address. |
| `ANDROID_DLEXT_RESERVED_ADDRESS_RECURSIVE` | Extends reserved-address and RELRO behavior to newly loaded dependencies. | `reserved_size` must cover the main library plus new dependencies. Existing already-loaded dependencies are not included, so reproducibility depends on the target's prior load state. |
| `ANDROID_DLEXT_USE_LIBRARY_FD` | Reads the library from `library_fd` instead of opening it by path. | The `filename` argument still identifies the library to the linker. |
| `ANDROID_DLEXT_USE_LIBRARY_FD_OFFSET` | Starts reading from `library_fd_offset`. | Only valid together with `ANDROID_DLEXT_USE_LIBRARY_FD`; useful for embedded libraries such as uncompressed ZIP entries. |
| `ANDROID_DLEXT_FORCE_LOAD` | Avoids the normal already-loaded check based on `stat(2)`. | It can load another file with the same filename, but dependency resolution can still prefer the first library when `DT_SONAME` overlaps. It is not a placement control. |
| `ANDROID_DLEXT_USE_NAMESPACE` | Requests loading in `library_namespace`. | Marked internal in the public docs because the NDK does not expose a namespace API. |
| `ANDROID_DLEXT_WRITE_RELRO` | Writes relocated GNU RELRO pages to `relro_fd`. | Useful only when another process can later map the same library at the same address. Implies `ANDROID_DLEXT_USE_RELRO`. |
| `ANDROID_DLEXT_USE_RELRO` | Reuses identical relocated RELRO pages from `relro_fd`. | Mostly useful for WebView-style shared-library layouts where address placement and dependency state are controlled. |

The recursive reserved-address mode is the closest public linker feature to
deterministic multi-library placement: newly loaded dependencies are placed
consecutively from `reserved_addr` in `DT_NEEDED` order. That determinism is
conditional. It depends on the reserved region being large enough and on the set
of dependencies that were not already loaded being stable.

**RELRO sharing is not placement**

`ANDROID_DLEXT_WRITE_RELRO` and `ANDROID_DLEXT_USE_RELRO` are often seen next to
reserved-address loading, but they solve a different problem. `WRITE_RELRO`
serializes the already-relocated GNU RELRO pages to `relro_fd`. `USE_RELRO`
later compares the target process's already-relocated RELRO pages with that file
and maps file-backed pages over the matching page ranges.

That means RELRO sharing depends on layout sameness; it does not create layout
sameness. If the library or its newly loaded dependencies land at different base
addresses, many RELRO pages can differ because they contain relocated absolute
pointers. The linker can then skip the non-matching pages and still complete the
load. So `USE_RELRO` by itself is not a strict deterministic-placement check and
not a way to force the linker to choose the original address.

The deterministic WebView-style pattern is the combination:

- reserve a sufficiently large address range at a controlled lifecycle point;
- load once with `ANDROID_DLEXT_RESERVED_ADDRESS`,
  `ANDROID_DLEXT_RESERVED_ADDRESS_RECURSIVE`, and `ANDROID_DLEXT_WRITE_RELRO`;
- load later with the same reserved range and `ANDROID_DLEXT_USE_RELRO`;
- keep the set and order of newly loaded dependencies consistent.

In that pattern, reserved-address loading is the placement mechanism and RELRO is
the memory-sharing/result-reuse mechanism. RELRO can reveal partial sameness
because identical pages are remapped from the file, but it should not be treated
as the thing that makes the layout deterministic.

**Choosing a reserved range**

There is no universal "close to 100%" fixed start address for a late arbitrary
target. The reliable primitive is not guessing a magic hole; it is creating the
reservation in the target address space and then giving the exact returned range
to the target linker.

For one already-running target process, the most reliable model is:

- create a target-side anonymous `PROT_NONE` reservation large enough for the
  intended linker-managed load;
- let the target kernel choose the address rather than hard-coding one;
- keep that reservation alive until `android_dlopen_ext` consumes it through
  `reserved_addr` / `reserved_size`;
- treat the returned address as valid only for that target process and that
  moment in time.

That can make the range "available now" in the target, but it does not make the
address deterministic across different processes or launches. If the requirement
is the same address across a family of processes, the stronger design is
pre-fork reservation in zygote or another controlled lifecycle point. That is
why WebView reserves in zygote instead of trying to discover a perfect hole
after every app process already exists.

Picking a fixed address by reading `/proc/<pid>/maps` and looking for a large
gap is only a heuristic. It can work in quiet processes, but it has race and
portability problems: other target threads can allocate between observation and
reservation, ART/JIT/native allocations can change the VMA layout, ASLR policies
vary, and 32-bit processes have much less room. If fixed placement must be
attempted, a non-clobbering reservation primitive is preferable. On Linux,
`MAP_FIXED_NOREPLACE` was added for this kind of atomic "use this exact range or
fail" behavior; older kernels may not honor it in the same way, so robust code
must verify that the returned address is actually the requested address. Plain
`MAP_FIXED` is dangerous for this purpose because overlap can discard existing
mappings.

"Big enough" also has a precise meaning. For the main ELF, start with the span
of all `PT_LOAD` segments after page alignment, not the file size. Bionic's
linker computes this load span from the program headers before reserving address
space. On newer devices, page-size migration and 16 KiB compatibility can add
padding. For `ANDROID_DLEXT_RESERVED_ADDRESS_RECURSIVE`, the reservation must
also cover every dependency that will be newly loaded, in the order the linker
will load them. Dependencies already present in the target do not consume that
reserved range, which is another reason that reproducibility depends on the
target's prior linker state.

On 64-bit, oversized reservations are often practical enough that production
code can reserve generously; current WebView uses a large zygote reservation for
that reason. On 32-bit, large reservations are much more likely to fail or starve
the process, so a precise dependency/load-span estimate matters more.

**Known public uses of reserved-address flags**

The canonical production use is Android WebView, not a public injector. WebView
reserves address space in the zygote, creates a RELRO file by loading the native
library into that region, and later loads the same library in WebView processes
with the same reserved region plus the RELRO file. Current AOSP loader code uses
combinations of:

- `ANDROID_DLEXT_RESERVED_ADDRESS`
- `ANDROID_DLEXT_RESERVED_ADDRESS_RECURSIVE`
- `ANDROID_DLEXT_WRITE_RELRO`
- `ANDROID_DLEXT_USE_RELRO`
- `ANDROID_DLEXT_USE_NAMESPACE`

That is exactly the reliability model these flags were designed for: controlled
multi-process loading where the loader controls the reserved address range,
namespace, RELRO file, and dependency set. It is not a general guarantee that an
arbitrary late injector can force deterministic placement with one remote
`mmap`.

Bionic's own `dlext_test.cpp` also exercises the behavior directly:
`RESERVED_ADDRESS` loads inside a pre-reserved range, `RESERVED_ADDRESS_HINT`
falls back when the range is unsuitable, too-small strict reservations fail, and
recursive reserved-address loads are tested with dependencies and RELRO sharing.

Chromium's historical Crazy Linker is adjacent but not the same interface: it
implemented its own fixed-address loading and RELRO sharing before modern
WebView/Trichrome paths relied more on `android_dlopen_ext`. The idea is similar:
prearrange enough address space so multiple processes can load the same native
code layout and share RELRO pages.

In the public injector-style projects checked for this repository, this is less
common. AndKittyInjector's memfd path uses `ANDROID_DLEXT_USE_LIBRARY_FD`, not
the reserved-address flags. LibcoreSyscall's `DlExtLibraryLoader` builds an
`android_dlextinfo` and exposes extension flags, but its main documented value is
in-memory linker-mediated loading, not a WebView-style deterministic reserved
layout. ReZygisk goes the other direction with custom loader behavior rather
than relying on `android_dlextinfo` reserved placement.

In other words: `android_dlextinfo` can affect the target layout, but it affects
the linker's mapping decision. It does not retroactively change the behavior of
an unrelated remote allocation.

**Remote syscall or RPC path**

Remote calls, ptrace register manipulation, and remote syscalls are transports.
They can allocate scratch buffers or reserve address ranges in the target, but
if the final handoff is still plain `dlopen`, the linker still controls the
library mapping. To make the remote allocation influence a linker-managed load,
the loader path must carry that reserved region through `android_dlextinfo`.
This is why "I can call remote `mmap`" and "I can choose exactly where the final
`.so` loads" are different claims.

**Custom loader path**

A custom ELF loader can make placement more deterministic because it can reserve
an address range and map `PT_LOAD` segments relative to a chosen load bias. That
comes with real complexity: relocations, imported symbols, TLS, init arrays,
memory protections, RELRO, namespace assumptions, and Android/architecture
differences. ReZygisk's remote CSOLoader path is a much more relevant modern
example of this direction than older "just call remote dlopen" projects.

## Custom ELF Loader Examples

Be strict about terminology. A real custom ELF loader is not just "load bytes
from memory" and is not just a wrapper around `dlopen`. In the strict sense it
does most of the linker's job itself:

- parse ELF headers and program headers;
- reserve address space and map `PT_LOAD` segments with the right protections;
- parse `PT_DYNAMIC`;
- load or locate dependencies;
- resolve imported symbols;
- apply `REL`, `RELA`, `RELR`, PLT/GOT, and architecture-specific relocations;
- set final memory protections, including RELRO where relevant;
- run preinit/init/init-array code in the correct order;
- bridge into JNI when the payload expects `JNI_OnLoad`.

Useful examples fall into three different buckets:

| Project | Category | Why it matters |
| --- | --- | --- |
| Chromium / NDK Crazy Linker | Strict custom linker, historical | Maps shared libraries itself, supports fixed-address and file-offset loads, handles dependencies/relocations, and implements RELRO sharing. Old, but one of the best public Android custom-linker references. |
| ReZygisk `remote_csoloader.c` | Purpose-built remote loader | Not a general replacement for Android's linker, but relevant because it shows custom loading as part of zygote/process residency instead of a normal local `dlopen`. |
| LibcoreSyscall `DlExtLibraryLoader` | In-memory, linker-mediated loader | Strong modern reference for loading a `.so` from memory using Java/native-memory tricks and `android_dlopen_ext`. It is useful, but it is not a full custom linker because Android's linker still performs the final load/relocation work. |
| AOSP bionic linker | Reference implementation | Not custom, but this is the behavior custom loaders are trying to reproduce or intentionally avoid: segment mapping, relocation, namespaces, TLS, constructors, RELRO, and linker bookkeeping. |

Python2 can appear at runtime if it is frozen into a native executable or if a
CPython runtime is embedded. It can also use native ELF libraries or bindings,
such as `libelf`/elfutils-style parsers, if those dependencies are bundled or
otherwise loadable in the target process. So the language is not the deciding
factor.

The deciding factor is where the real loader semantics live. If frozen Python
only coordinates native helpers, calls a bundled C extension, or hands bytes to
Android's linker, it is a Python-fronted loader or orchestrator. If the embedded
runtime itself parses the ELF, chooses mappings, drives target `mmap`/`mprotect`
or equivalent primitives, applies architecture relocations, handles symbol
resolution, and runs init/JNI entry points inside the target process, then it is
fair to call it a Python-implemented custom loader.

In practice, C/C++, Java/Kotlin with native memory primitives, or a small
assembly/shellcode stub are more common for the in-target loader core because
they avoid shipping a large interpreter, reduce dependency/bootstrap problems,
and make architecture-specific relocation, TLS, cache maintenance, and signal or
thread-state constraints easier to control. Python or Python2 is more often seen
around the loader as tooling, a packer/generator, an exploit orchestrator, or a
frozen carrier.

The quick filter is simple: if a project does not map `PT_LOAD`, parse
`PT_DYNAMIC`, resolve symbols, apply relocations, set segment protections, run
init arrays, and handle `JNI_OnLoad` when JNI is expected, it is probably not a
strict custom Android ELF loader. It may still be a very useful `dlopen`,
`android_dlopen_ext`, memfd, in-memory loading, or hook framework.

## Symbol Location in the Target

Do not assume that a symbol address from the injector process is valid in the
target process. The common pattern is:

- find the library mapping in the target process;
- identify the equivalent local library or parse the target ELF directly;
- compute symbol offsets relative to the mapped object, then rebase those
  offsets onto the target mapping;
- account for Android version, APEX paths, linker namespace behavior, stripped
  symbols, and architecture.

For ART/JNI work, modern projects tend to avoid the old direct
`android::AndroidRuntime::mJavaVM` assumption. A more portable in-process pattern
is to recover a `JavaVM *` through exported JNI/ART entry points when available,
then obtain a `JNIEnv *` for the current thread with `GetEnv` or
`AttachCurrentThread`. Another valid pattern is to run at a lifecycle point where
Android passes a current-thread `JNIEnv *` into the hook or callback.
AndKittyInjector, for example, looks for `JNI_GetCreatedJavaVMs` in the target's
`libart.so` and then invokes `JNI_OnLoad` if it can recover a valid `JavaVM`.

For linker namespace and symbol discovery once code is resident, xDL is a useful
source-level reference because it contains Android-version-specific handling for
linker internals and caller-address-sensitive loads.

## DEX and Managed Code

Writing DEX bytes into a target process is only storage. It is not the same as
loading Java/Kotlin code into ART.

A managed-code bridge normally needs:

- native code already running in the target process;
- a valid `JavaVM *` plus a `JNIEnv *` for the current attached thread;
- a compatible class loader strategy, such as a process-appropriate loader or an
  in-memory loader on Android versions that support it;
- awareness of hidden API restrictions, process classpath, target UID/domain,
  and whether the process is pre-specialization, post-specialization, or already
  running normal framework code.

For zygote and `system_server`, the lifecycle point matters more than the DEX
container. Code that runs before specialization has different visibility,
permissions, file descriptors, mount namespace, and classloader assumptions than
code injected into a long-running process.

## Source-Informed Project Notes

| Project | What to study | Why it matters |
| --- | --- | --- |
| [ReZygisk](https://github.com/PerformanC/ReZygisk) | Early zygote tracing, custom remote loader, zygote JNI hooks, app/server specialize callbacks | Best modern public source for understanding zygote and `system_server` lifecycle injection concepts. |
| [AndKittyInjector](https://github.com/MJx0/AndKittyInjector) | Late ptrace attach, remote function/syscall calls, memfd + `android_dlopen_ext`, `JNI_OnLoad` handoff | Stronger modern baseline for direct injection into an already-running attachable process. Its current memfd path uses `ANDROID_DLEXT_USE_LIBRARY_FD`; reserved-address `android_dlextinfo` behavior is a separate placement concern. |
| Chromium / NDK Crazy Linker | Custom ELF mapping, dependency loading, relocation, fixed-address loading, RELRO sharing | Best historical public Android custom linker to compare against when evaluating "custom loader" claims. |
| LibcoreSyscall `DlExtLibraryLoader` | In-memory `.so` loading, Java native-memory primitives, `android_dlopen_ext`, manual `JNI_OnLoad` | Useful modern in-process loader reference; not a remote injector and not a strict custom linker. |
| AOSP bionic linker | Android's real linker implementation | Reference behavior for namespaces, relocation, TLS, RELRO, constructors, and linker-managed mapping. |
| [xDL](https://github.com/hexhacking/xDL) | Linker namespace bypass concepts, enhanced `dlopen` / `dlsym`, `dl_iterate_phdr` handling | Useful after residency for locating libraries and symbols under modern Android linker behavior. |
| [ShadowHook](https://github.com/bytedance/android-inline-hook) | Inline native hooks | Post-injection native instrumentation, not target-entry by itself. |
| [ByteHook](https://github.com/bytedance/bhook) | PLT/GOT hooks and `dlopen` monitoring | Post-injection hook management and dynamic library load monitoring. |
| [LSPlant](https://github.com/LSPosed/LSPlant) | ART method hooking | Managed/ART behavior after native code is already resident. |
| [AndroidPtraceInject](https://github.com/SsageParuders/AndroidPtraceInject) | Educational ptrace `mmap` + `dlopen` flow | Good for learning the classic shape, weak as a modern Android design. |
| [injectvm-binderjack](https://github.com/Chainfire/injectvm-binderjack) | Historical `system_server` experiment, `AndroidRuntime::mJavaVM`, Binder swapping | Valuable historical context, but not a modern baseline. |

## Technique Matrix

This section is intentionally source-level and comparative. It is meant to help
readers understand project design choices and prerequisites, not to provide an
ordered privileged-process injection recipe.

**ReZygisk**

- Target-entry trick: monitors process birth from a root/module context, traces
  `init` fork/exec events, detects `app_process` / zygote startup, then hands the
  new zygote process to an ABI-matching tracer.
- Memory/loading trick: maps its zygisk library during early process startup
  using a custom remote CSOLoader path. This is closer to a purpose-built ELF
  mapper than to a simple remote `dlopen`.
- RPC trick: uses ptrace register control, `process_vm_readv` /
  `process_vm_writev`, remote syscalls, and a controlled return/fault point to
  regain tracer control after target-side execution.
- ART/JNI trick: once resident, it initializes JNI hooks from inside the process.
  It looks up `JNI_GetCreatedJavaVMs`, obtains `JavaVM`, calls `GetEnv` for the
  current thread, and also hooks zygote native methods where Android naturally
  passes a current-thread `JNIEnv *`.
- Lifecycle trick: hooks variants of `nativeForkAndSpecialize`,
  `nativeSpecializeAppProcess`, and `nativeForkSystemServer`, giving it pre/post
  app and server specialization callbacks.
- Main prerequisites: root/module environment, ability to trace `init`/zygote,
  compatible ABI, writable module files, SELinux policy support, and ability to
  restart or catch zygote early enough.

**AndKittyInjector**

- Target-entry trick: attaches to an already-running target PID with
  `PTRACE_SEIZE` where possible, falling back to `PTRACE_ATTACH`.
- Memory/loading trick: uses remote scratch memory and remote calls into the
  target linker. It can load by path, or copy the library into a target-side
  memfd and invoke `android_dlopen_ext` with `ANDROID_DLEXT_USE_LIBRARY_FD`.
- RPC trick: builds remote function calls by saving target registers, placing
  arguments in target registers/stack according to ABI, setting PC to the target
  function, waiting for completion, then restoring state.
- Symbol trick: scans the target maps/ELF objects, resolves `dlopen`,
  `android_dlopen_ext`, `dlsym`, `dlclose`, and linker symbols in the target
  address space instead of reusing local addresses directly.
- ART/JNI trick: after the library is mapped, it finds `JNI_GetCreatedJavaVMs`
  in target `libart.so`, remote-calls it to recover `JavaVM`, then calls the
  injected library's `JNI_OnLoad(JavaVM *, key)`. The library can then obtain
  its own current-thread `JNIEnv *` through normal JNI rules.
- Main prerequisites: native code execution as a process that may ptrace the
  target, matching 32/64-bit ABI, target readable maps/memory, target linker
  symbols available enough for the chosen path, SELinux/domain permission, and
  a target process that can safely be interrupted.

**injectvm-binderjack**

- Target-entry trick: classic ptrace attach to a target such as
  `system_server`, followed by remote calls into target libc/linker functions.
- Memory/loading trick: allocates target memory with remote `calloc`, writes
  strings/parameters, then remote-calls `dlopen`.
- VM trick: resolves `android::AndroidRuntime::mJavaVM` from
  `libandroid_runtime.so` in the injector process, rebases that symbol into the
  target process, and passes the resulting `JavaVM **` to an exported payload
  function.
- Managed-code trick: the payload calls `AttachCurrentThread` to obtain
  a current-thread `JNIEnv *`, creates or reuses a class loader, loads Java
  classes, and registers native methods for its Binder experiment.
- Why historical: this depends on old framework internals, linker namespace
  assumptions, Binder object layout assumptions, and a rooted shell-style
  execution model. It is useful for learning, not as a modern baseline.

**AndroidPtraceInject**

- Target-entry trick: direct `PTRACE_ATTACH` to a target PID.
- Memory/loading trick: remote-calls `mmap`, writes a library path into target
  memory, remote-calls `dlopen`, then optionally remote-calls a symbol resolved
  with `dlsym`.
- ART/JNI trick: none built in. It is a native-loader example, not a modern
  ART/DEX bridge.
- Main prerequisites: ptrace permission, ABI compatibility, permissive-enough
  SELinux/domain state, a path the target linker can load, and tolerance for
  stopping the target process.

**xDL, ShadowHook, ByteHook, LSPlant**

- Target-entry trick: none. These libraries assume code is already resident in
  the process.
- xDL helps with linker namespace and symbol lookup once resident.
- ShadowHook and ByteHook help with native inline/PLT/GOT hooks once resident.
- LSPlant helps with ART method hooks once resident and initialized from a thread
  that has a valid `JNIEnv *`, plus ART symbol resolution support.

## JavaVM, JNIEnv, and DEX Notes

On modern Android, "find the Dalvik VM in memory" is usually the wrong mental
model. Modern Android uses ART, and `JNIEnv *` is thread-local. A stable global
`JNIEnv *` is not normally what these projects recover or store.

The usual patterns are:

- recover or receive a `JavaVM *`, then call `GetEnv` or `AttachCurrentThread`
  whenever a specific thread needs its own valid `JNIEnv *`;
- run inside a native JNI method hook where Android already passed `JNIEnv *`;
- call `JNI_OnLoad` in the injected library with a valid `JavaVM *`, so the
  library can initialize using normal JNI conventions.

For DEX loading, native memory writes are only the first step. The target process
still needs an ART-visible loading path, a suitable class loader, and a thread
attached to the VM. BinderJack demonstrates the older `PathClassLoader` style;
modern in-memory loading or zygote-time loading has different constraints and
depends strongly on Android version, hidden API policy, and target process
lifecycle.

## Access Model

Physical access is not the core technical requirement. Equivalent post-chain
execution context is.

For this document's baseline, assume the earlier chain has already produced the
capabilities normally provided by adb/root shell, a Magisk/KernelSU/APatch module
context, or a privileged native process: native execution, system/root-equivalent
privilege, and enough SELinux/domain control to trace, map, write, or restart the
processes being discussed. A non-physical case is therefore in scope only after
the authorized exploit chain has already reached that state.

Important boundaries:

- If you deliberately narrow the assumption back down to only unprivileged
  app-process RCE, the rest of these notes no longer apply directly: that state
  is not enough to ptrace `zygote`, `system_server`, or arbitrary
  higher-privileged processes on a production Android device.
- Late ptrace injectors require permission to trace/read/write the target
  process and must match target ABI.
- Zygote lifecycle approaches assume root/module-level or equivalent control and
  are easier when the device can restart zygote or reboot.
- Libraries such as xDL, ShadowHook, ByteHook, and LSPlant do not solve target
  entry. They only become useful after native code is already resident.

## Commercial Spyware Comparison

Commercial Android spyware seen in public reporting should be compared as an
end-to-end system, not as a standalone injector. The implant loader is only one
stage. A typical remote 0-click or 1-click operation has at least four layers:

1. **Delivery and exploit chain**: link, browser, messaging, network injection,
   or another remote vector that obtains initial code execution.
2. **Sandbox escape / privilege escalation**: enough privilege to cross from the
   first compromised process into a useful Android security context.
3. **Loader / stager**: code that prepares memory, process residency, IPC, and
   persistence conditions for the implant.
4. **Implant framework**: long-lived surveillance logic, module loading,
   command/control, data collection, anti-forensics, and update handling.

That is why comparing an open-source injector directly to commercial spyware can
be misleading. Projects like AndKittyInjector mainly model stage 3 after the
operator already has equivalent local privilege. ReZygisk models a zygote-aware
loader/lifecycle framework, but it assumes a module/root environment rather than
bringing its own remote exploit chain.

**Older commercial examples**

- Hacking Team RCS Android is a useful historical comparison for older Android
  tradecraft, but not because it is a modern zygote injector. Citizen Lab's
  public analysis describes a malicious APK seeded through social links, a
  legacy rooting exploit check, and a dropped privileged helper named `rilcap`
  that behaved like a hidden root command bridge. Its relevance here is the
  operator mindset: once code is on-device, the loader/helper exists to create
  durable privilege and broad control. It is less useful as a modern
  process-injection baseline.
- Pegasus for Android / Chrysaor, as documented by Lookout and Google, is an
  example where the Android side differed from the iOS zero-day story. Public
  reporting said it used a known rooting technique and had a permissions-based
  fallback if rooting failed. For this repository, the lesson is that commercial
  Android implants often optimize for operational reliability across device
  states, not only for the most elegant memory loader.
- Cytrox / Intellexa Predator is the more relevant modern comparison. Google TAG
  reported exploit chains delivering ALIEN, a loader associated with PREDATOR,
  after browser and Android/kernel stages. TAG described ALIEN as living inside
  multiple privileged processes and receiving commands from PREDATOR over IPC.
  Cisco Talos later assessed ALIEN as more than a simple loader: it helped set
  up low-level capabilities used by the spyware and interacted with privileged
  Android process contexts.

**Loader/injector lens**

| Reported family | Publicly visible loader shape | Closest public research analogue | Important mismatch |
| --- | --- | --- | --- |
| Hacking Team RCS Android | APK-stage implant plus root/persistence helper; privilege is converted into command execution and filesystem/system control. | Classic Android root-era tooling, not a specific project in this repo. | It models old persistence/helper design more than cross-process ELF loading into ART-era privileged services. |
| Pegasus for Android / Chrysaor | Root attempt plus permissions fallback, with implant behavior continuing when full privilege is unavailable. | Access-model comparison only. | Public reporting is more useful for operational fallback design than for loader internals. |
| Cytrox / Intellexa Predator | ALIEN acts as loader/worker around PREDATOR, with privileged-process residency, binder/IPC coordination, and zygote/process-context awareness. | ReZygisk for lifecycle shape, AndKittyInjector for late native loading concepts, ByteHook/xHook-style libraries for in-process hooks. | Commercial chain includes remote exploit delivery, sandbox escape, privilege escalation, stealth, and implant orchestration that public research injectors deliberately do not implement. |

The most useful comparison is therefore architectural:

- Hacking Team-era Android tradecraft often looks like "gain root, drop helper,
  persist, expose privileged operations".
- Simple open-source injectors look like "given enough local privilege, map or
  `dlopen` this shared library in another process".
- Predator-era reporting looks like "use exploit-chain output to place a loader
  inside privileged Android processes, then coordinate a modular implant around
  process privileges and IPC".

That last category is where ReZygisk is conceptually informative despite being a
root/module project: it demonstrates why zygote timing, process specialization,
JNI availability, and multi-process lifecycle hooks matter. It still does not
replace the exploit-chain and privilege-transition layers needed for a remote
0-click or 1-click case.

**How this maps to the open-source projects**

| Commercial spyware need | Closest public research analogue | Gap |
| --- | --- | --- |
| Remote delivery and initial RCE | None in this repo | This belongs to exploit-chain research, not ELF loader research. |
| Sandbox escape / LPE / SELinux-domain crossing | None directly | Public injectors usually assume this is already solved. |
| Late native library load into an attachable process | AndKittyInjector, AndroidPtraceInject | Requires ptrace/memory permissions and compatible ABI. |
| Zygote-aware process lifecycle control | ReZygisk | Assumes root/module control instead of a remote exploit chain. |
| Linker namespace and symbol discovery after residency | xDL | Does not provide target entry. |
| Native/ART hooks after residency | ShadowHook, ByteHook, LSPlant | Does not provide target entry or persistence. |
| Multi-process implant coordination | ReZygisk is conceptually closer than late ptrace injectors | Spyware implementations add stealth, IPC, update, collection, and anti-forensics. |

**Remote 0-click / 1-click prerequisite reality**

For a non-physical case, the loader is not the hard starting point. The hard
starting point is obtaining a process and privilege state where the loader is
allowed to do anything useful. Public reporting on commercial spyware repeatedly
shows exploit chains combining browser or app RCE, sandbox escape, and Android
kernel or privilege bugs before an implant loader can operate in privileged
contexts. Without that earlier chain, a loader that works from adb/root or a
Magisk-style module does not become remotely deployable.

Keep this distinction clear:

- **Exploit chain**: gets code execution and privileges.
- **Loader/injector**: places and starts code in the chosen process.
- **Implant**: performs long-lived collection, control, and update behavior.

This repository is mainly about the second layer and the Android runtime/linker
internals around it.

## iOS In-the-Wild Comparison

It does make sense to compare modern iOS in-the-wild chains, but only at the
architecture layer. The platform primitives are different enough that iOS code
should not be treated as an Android implementation reference.

[DarkSword](https://github.com/ghh-jb/DarkSword/blob/24c9d1419540dd3675a15fb73285d3a4171ae86f/pe_main.js)
is useful here because public reporting and the recovered source show the same
high-level pattern seen in serious Android spyware:

1. get initial browser/JIT/runtime execution;
2. escape the first sandbox;
3. obtain stronger process or kernel primitives;
4. choose target processes for their security context;
5. inject a higher-level runtime/payload into those processes;
6. run task-specific modules from inside the chosen process context.

The closest Android analogy is not "DarkSword equals `dlopen`". The better
analogy is "DarkSword's loader layer equals a privileged-process residency and
runtime execution layer", similar in role to the ALIEN/PREDATOR relationship
reported on Android.

**What DarkSword shows**

- Runtime loading instead of only Mach-O loading: `pe_main.js` loads
  JavaScriptCore into a remote target, creates a `JSContext`, wires a native-call
  bridge, and evaluates injected JavaScript inside that target process.
- Process-context selection: payloads are placed into processes such as
  `configd`, `wifid`, `securityd`, `UserEventAgent`, and a main agent process
  because those processes have useful sandbox, entitlement, filesystem, or
  data-access properties.
- Remote-call machinery: the code builds target-side function calls from Mach
  task/thread knowledge, exception-port handling, thread-state manipulation,
  PAC-aware address signing, and scratch memory in the remote task.
- Sandbox handoff: `launchd` and sandbox-extension logic are used as part of
  moving useful access into remote tasks.
- Staged chain design: Google GTIG reported DarkSword as a full iOS exploit
  chain, with WebKit/JavaScriptCore RCE, GPU-process and sandbox stages, XNU
  privilege escalation, and JavaScript final payloads.

**How that differs from Android**

| Question | Android focus in this repo | iOS DarkSword-style focus |
| --- | --- | --- |
| Process primitive | `ptrace`, `/proc/<pid>/maps`, `process_vm_*`, SELinux/domain checks, zygote lifecycle | Mach task/thread objects, exception ports, launchd, sandbox extensions, PAC-signed thread state |
| Loader/runtime | Android linker, `android_dlopen_ext`, custom ELF loader, ART/JNI/DEX bridge | `dyld`/`dlopen`, JavaScriptCore injection, Objective-C runtime, remote `JSContext` execution |
| Address control | Linker choice, `android_dlextinfo` reserved ranges, or custom ELF mapping | Mach VM mappings and task memory primitives; final payload may be JS rather than a native image |
| Managed-code bridge | Recover `JavaVM *`, obtain per-thread `JNIEnv *`, load DEX/classes, handle ART constraints | Create or reuse JSC/Objective-C runtime objects and evaluate JavaScript in the selected process |
| Process choice | UID, SELinux domain, zygote/system_server/app lifecycle | sandbox profile, entitlement/data access, daemon role, launchd-managed process context |

So the comparison is valuable because it highlights what modern commercial
chains optimize for: not just "load a library", but "turn exploit-chain output
into a reusable remote-call/runtime substrate, then run modules inside processes
whose existing privileges solve the data-access problem". That lesson transfers
cleanly to Android. The API details do not.

## Source Landmarks

These are useful starting points for reading the actual implementations:

- ReZygisk monitor and handoff from `init`/`app_process`:
  [monitor.c](https://github.com/PerformanC/ReZygisk/blob/e337a086b916923d6190c6fe078abaf0368f0d69/loader/src/ptracer/monitor.c#L544-L779)
- ReZygisk early zygote injection and return-to-entry logic:
  [ptracer.c](https://github.com/PerformanC/ReZygisk/blob/e337a086b916923d6190c6fe078abaf0368f0d69/loader/src/ptracer/ptracer.c#L230-L430)
- ReZygisk custom remote ELF mapping path:
  [remote_csoloader.c](https://github.com/PerformanC/ReZygisk/blob/e337a086b916923d6190c6fe078abaf0368f0d69/loader/src/ptracer/remote_csoloader.c#L701-L960)
- ReZygisk zygote JNI hooks for app and system-server specialization:
  [jni_hooks.h](https://github.com/PerformanC/ReZygisk/blob/e337a086b916923d6190c6fe078abaf0368f0d69/loader/src/injector/jni_hooks.h#L422-L458)
- ReZygisk `JavaVM` recovery and current-thread `JNIEnv` setup before JNI hook setup:
  [hook.c](https://github.com/PerformanC/ReZygisk/blob/e337a086b916923d6190c6fe078abaf0368f0d69/loader/src/injector/hook.c#L450-L510)
- Crazy Linker public API and feature summary:
  [crazy_linker.h](https://android.googlesource.com/platform/ndk/+/0f5c91926653588a6811e633fcfc9b15f6ef2e5f/sources/android/crazy_linker/include/crazy_linker.h)
- Crazy Linker `PT_LOAD` mapping and fixed-address load logic:
  [crazy_linker_elf_loader.cpp](https://chromium.googlesource.com/android_tools/+/53862978424412e190e9bc40c7637a71fdd7d298/ndk/sources/android/crazy_linker/src/crazy_linker_elf_loader.cpp)
- Crazy Linker relocation implementation:
  [crazy_linker_elf_relocator.cpp](https://chromium.googlesource.com/android_tools/+/53862978424412e190e9bc40c7637a71fdd7d298/ndk/sources/android/crazy_linker/src/crazy_linker_elf_relocator.cpp)
- Chromium notes on Android native libraries, Crazy Linker, and RELRO sharing:
  [android_native_libraries.md](https://chromium.googlesource.com/chromium/src/+/main/docs/android_native_libraries.md)
- LibcoreSyscall in-memory `android_dlopen_ext` loader:
  [DlExtLibraryLoader.java](https://github.com/cinit/LibcoreSyscall/blob/086efbb58549b27ab147419ad7d8854953d43663/core-syscall/src/main/java/dev/tmpfs/libcoresyscall/elfloader/DlExtLibraryLoader.java#L139-L407)
- LibcoreSyscall ELF view and symbol parsing:
  [ElfView.java](https://github.com/cinit/LibcoreSyscall/blob/086efbb58549b27ab147419ad7d8854953d43663/core-syscall/src/main/java/dev/tmpfs/libcoresyscall/elfloader/ElfView.java#L116-L160)
- LibcoreSyscall manual `JNI_OnLoad` example:
  [TestNativeLoader.java](https://github.com/cinit/LibcoreSyscall/blob/086efbb58549b27ab147419ad7d8854953d43663/demo-app/src/main/java/com/example/test/app/TestNativeLoader.java#L116-L130)
- AOSP bionic linker segment mapping and relocation reference:
  [linker_phdr.cpp](https://android.googlesource.com/platform/bionic/+/master/linker/linker_phdr.cpp) and
  [linker_relocate.cpp](https://android.googlesource.com/platform/bionic/+/master/linker/linker_relocate.cpp)
- Bionic linker load-span calculation and caller-supplied reservation handling:
  [linker_phdr.cpp](https://android.googlesource.com/platform/bionic/+/master/linker/linker_phdr.cpp#415)
- Bionic GNU RELRO serialize/map behavior used by `WRITE_RELRO` and
  `USE_RELRO`:
  [linker_phdr.cpp](https://android.googlesource.com/platform/bionic/+/master/linker/linker_phdr.cpp#1231)
- Linux `mmap(2)` notes on `MAP_FIXED`, `MAP_FIXED_NOREPLACE`, and kernel-chosen
  addresses:
  [mmap(2)](https://man7.org/linux/man-pages/man2/mmap.2.html)
- AOSP WebView Java-side address-space reservation and RELRO orchestration:
  [WebViewLibraryLoader.java](https://android.googlesource.com/platform/frameworks/base/+/main/core/java/android/webkit/WebViewLibraryLoader.java#173)
- AOSP WebView native loader using reserved-address, recursive, namespace, and
  RELRO flags with `android_dlopen_ext`:
  [native/webview/loader/loader.cpp](https://android.googlesource.com/platform/frameworks/base/+/master/native/webview/loader/loader.cpp#90)
- Bionic tests for reserved-address, hint, recursive, and RELRO-sharing behavior:
  [dlext_test.cpp](https://android.googlesource.com/platform/bionic/+/master/tests/dlext_test.cpp#267)
- AndKittyInjector ptrace attach and ABI sanity checks:
  [main.cpp](https://github.com/MJx0/AndKittyInjector/blob/a3fd7e6b3b9de54b55d77df8355bba23e5c53f9b/AndKittyInjector/src/main.cpp#L192-L250)
- AndKittyInjector remote linker symbol resolution:
  [KittyInjector.cpp](https://github.com/MJx0/AndKittyInjector/blob/a3fd7e6b3b9de54b55d77df8355bba23e5c53f9b/AndKittyInjector/src/Injector/KittyInjector.cpp#L82-L123)
- AndKittyInjector memfd + `android_dlopen_ext` path:
  [KittyInjector.cpp](https://github.com/MJx0/AndKittyInjector/blob/a3fd7e6b3b9de54b55d77df8355bba23e5c53f9b/AndKittyInjector/src/Injector/KittyInjector.cpp#L551-L623)
- AndKittyInjector target `JavaVM` discovery and `JNI_OnLoad` handoff:
  [KittyInjector.cpp](https://github.com/MJx0/AndKittyInjector/blob/a3fd7e6b3b9de54b55d77df8355bba23e5c53f9b/AndKittyInjector/src/Injector/KittyInjector.cpp#L1171-L1247)
- BinderJack remote call primitive:
  [inject.cpp](https://github.com/Chainfire/injectvm-binderjack/blob/8eb5fee9085d1192fb0c268eefe5f517f36c154e/app/src/main/jni/libinject/inject.cpp#L303-L375)
- BinderJack VM lookup rationale:
  [README.md](https://github.com/Chainfire/injectvm-binderjack/blob/8eb5fee9085d1192fb0c268eefe5f517f36c154e/README.md#L157-L205)
- Google TAG on Cytrox/Predator Android exploit chains and ALIEN/PREDATOR:
  [Protecting Android users from 0-Day attacks](https://blog.google/threat-analysis-group/protecting-android-users-from-0-day-attacks/)
- Cisco Talos on ALIEN/PREDATOR implant architecture:
  [Mercenary mayhem](https://blog.talosintelligence.com/mercenary-intellexa-predator/)
- Lookout on Pegasus for Android / Chrysaor:
  [Pegasus for Android](https://www.lookout.com/threat-intelligence/article/pegasus-android)
- Citizen Lab on Hacking Team RCS Android:
  [Hacking Team's Tradecraft and Android Implant](https://citizenlab.ca/research/backdoor-hacking-teams-tradecraft-android-implant/)
- Google GTIG on DarkSword's iOS exploit chain and payload staging:
  [The Proliferation of DarkSword](https://cloud.google.com/blog/topics/threat-intelligence/darksword-ios-exploit-chain)
- DarkSword recovered `pe_main.js` process/runtime injection layer:
  [pe_main.js](https://github.com/ghh-jb/DarkSword/blob/24c9d1419540dd3675a15fb73285d3a4171ae86f/pe_main.js)
- xDL Android-version-specific linker internals:
  [xdl_linker.c](https://github.com/hexhacking/xDL/blob/7112b158e7926cfa932169a8c9ea9813338614ef/xdl/src/main/cpp/xdl_linker.c#L35-L108)
- xDL caller-address-sensitive force-load path:
  [xdl_linker.c](https://github.com/hexhacking/xDL/blob/7112b158e7926cfa932169a8c9ea9813338614ef/xdl/src/main/cpp/xdl_linker.c#L197-L230)
- ByteHook dynamic loader monitoring across Android versions:
  [bh_dl_monitor.c](https://github.com/bytedance/bhook/blob/6dc79330472327ac89617e51ecfcc3ee97f311cc/bytehook/src/main/cpp/bh_dl_monitor.c#L53-L70)
- Android NDK `android_dlextinfo` structure and flag semantics:
  [android_dlextinfo](https://developer.android.com/ndk/reference/structandroid/dlextinfo) and
  [Dynamic Linker flags](https://developer.android.com/ndk/reference/group/libdl)
- BinderJack historical `system_server` injection path:
  [inject.cpp](https://github.com/Chainfire/injectvm-binderjack/blob/8eb5fee9085d1192fb0c268eefe5f517f36c154e/app/src/main/jni/libinject/inject.cpp#L528-L604)

## Reading Questions

- Is the target already attachable, or do you need to win an earlier lifecycle
  point such as zygote startup?
- Does the design require deterministic base addresses, or only reliable symbol
  rebasing after load?
- If deterministic placement matters, is linker-managed reserved-address loading
  enough, or do dependencies/relocations force a custom loader design?
- Is `dlopen` enough, or do linker namespace and backing-file constraints require
  `android_dlopen_ext`, memfd, or a custom loader?
- Are you trying to run native code only, or eventually bridge into ART/DEX?
- Which assumptions break across Android version, architecture, vendor build,
  APEX layout, and SELinux domain?

# Research Papers and Articles
- [Linkers & Loaders](https://www.wh0rd.org/books/linkers-and-loaders/linkers_and_loaders.pdf) by John R. Levine (1999)
- [Using procfs to execute ELF without touching the disk](https://blog.entysec.com/2023-04-02-remote-elf-loading/)
- [The Nexus between Static and Position Independent Code](https://tmpout.sh/1/10/)
- [Enabling SHELF Loading in Chrome for fun and profit](https://tmpout.sh/2/5.html)
- [General Linux Process injection techniques](https://github.com/itaymigdal/awesome-injection#linux-injection)
  
# Projects and Code Repositories

## 2023
- [Playstation5 ELF Manipulation](https://github.com/astrelsky/libhijacker/blob/msg/libhijacker/source/elf/elf.cpp)

## 2022
- [NASM Linux x86_64 Pure Shared Library](https://github.com/therealdreg/nasm_linux_x86_64_pure_sharedlib)

## 2018
- ARM: [SamyGOso Next-Gen](https://github.com/openlgtv/samyGOso_ng/blob/master/core/samyGOso.c)
  - Based on 2014 ARM: [HideAndroidEmulator ADBI Hook System Call](https://github.com/MindMac/HideAndroidEmulator/blob/master/HITCON/DemoCode/adbi_hook_systemcall/hijack/hijack.c)
- [Reflective Injection for Linux](https://github.com/haidragon/ReflectiveInjection/blob/master/linux%E7%89%88/inject/src/inject.c)

## 2017
- [DarkElf - Linux ELF Injector](https://github.com/jordan9001/darkelf/tree/master)

## 2016
- [XHook JNI Hijack](https://github.com/hello2mao/XHook/blob/master/ref/jni/hijack_ref/hijack.c)
- [ReflectiveSOInjection](https://github.com/infosecguerrilla/ReflectiveSOInjection/)

## 2014
- [Insecurity - Elves for Linux](https://github.com/nima/insecurity/blob/master/elvez/elves.c)

# Appendix / Somewhat Related / Need to organize

## Ptrace related (most implementations are based on it)
**TODO**: how likely is it that the process you wish to inject to has already ptraced (attached) itself?, what would you do in such scenario?  
- [Linux ptrace introduction AKA injecting into sshd for fun - XPN InfoSec Blog](https://blog.xpnsec.com/linux-process-injection-aka-injecting-into-sshd-for-fun/)
- [Linux Kernel Dirty COW PTRACE_POKEDATA Privilege Escalation - exploit database | Vulners.com](https://vulners.com/packetstorm/PACKETSTORM:139923)
- [Code search results on GitHub (ProcDump for Linux - ptrace)](https://github.com/search?q=repo%3ASysinternals%2FProcDump-for-Linux%20ptrace&type=code)
- [HookProcessEvent: PtraceInject.h at main · Jingle-BF/HookProcessEvent](https://github.com/Jingle-BF/HookProcessEvent/blob/main/app/src/main/cpp/include/PtraceInject/include/PtraceInject.h)
- [Code search results on GitHub (PTRACE_SETREGSET, NT_PRSTATUS, PTRACE_SETREGS, CPSR_T_MASK)](https://github.com/search?q=%22ptrace%28PTRACE_SETREGSET%22+NT_PRSTATUS+PTRACE_SETREGS+PTRACE_CONT+CPSR_T_MASK+PTRACE_POKEDATA&type=code)
- [W3ndige/linux-process-injection: Proof of concept for injecting simple shellcode via ptrace](https://github.com/W3ndige/linux-process-injection)
  ### TODO: Check if helpful
- [Ptrace pokedata Input/output error in memory injection - Stack Overflow](https://stackoverflow.com/questions/76393009/ptrace-pokedata-input-output-eror-in-memory-injection)
- [Ptrace(PTRACE_PEEKDATA, ...) error: data dump - Stack Overflow](https://stackoverflow.com/questions/53213591/ptraceptrace-peekdata-error-data-dump)
Watch for ptrace alignment issues?

## 2018
- [Saruman ELF Virus](https://github.com/elfmaster/saruman/blob/master/launcher.c)

## Miscellaneous
- [ElfMaster - ELF Internals projects (Injection, Patching etc.)](https://github.com/elfmaster)
- [DEF CON 31 - Revolutionizing ELF binary patching w Shiva - ElfMaster](https://www.youtube.com/watch?v=TDMWejaucdg)
- [CVE-2022-34918 Shellcode Generation](https://github.com/jiayy/android_vuln_poc-exp/blob/master/linux/CVE-2022-34918/generate_shellcode/gen_shellcode.sh)
- [DDexec - Linux Binary Execution Technique](https://github.com/arget13/DDexec-)
- [bhook - Android PLT Hook Library](https://github.com/bytedance/bhook)

- [vfsfitvnm/intruducer](https://github.com/vfsfitvnm/intruducer)
- [arget13/memdlopen](https://github.com/arget13/memdlopen)
- [Shared Library Injection in Android](https://shunix.com/shared-library-injection-in-android/)
- [Shellcode Android Internals CTF ex4](https://dev.to/wireless90/shellcode-android-internals-ctf-ex4-4357)
- [Paper: 46043 - Android System Tracing: A Real-Life Story](https://www.exploit-db.com/papers/46043)
- [ELF Shared Library Injection Forensics](https://engineering.backtrace.io/2016-04-14-elf-shared-library-injection-forensics/)


# Android specific open-source material  


## Riru
- [Riru (C++)](https://github.com/KitsuneMagisk/Riru/tree/master)
- [Riru Project](https://github.com/RikkaApps/Riru)
  - Inject into zygote process (see also Zygisk project)

## Android NDK
- [NDK Build Guide](https://developer.android.com/ndk/guides/ndk-build)

## Android Linker and Libraries
- [Modern Linker JNI (Chromium)](https://cs.android.com/android/platform/superproject/main/+/main:base/android/linker/modern_linker_jni.cc;l=1)
- [dlext.h](https://cs.android.com/android/platform/superproject/main/+/main:bionic/libc/include/android/dlext.h;l=1?q=dlext.h&sq=&ss=android%2Fplatform%2Fsuperproject%2Fmain)
- [dlext_test.cpp](https://cs.android.com/android/platform/superproject/main/+/main:bionic/tests/dlext_test.cpp;l=1?q=dlext_test.cpp&sq=&ss=android%2Fplatform%2Fsuperproject%2Fmain)
- [dlfcn.cpp](https://cs.android.com/android/platform/superproject/main/+/main:bionic/linker/dlfcn.cpp;l=1?q=dlfcn.cpp&sq=&ss=android%2Fplatform%2Fsuperproject%2Fmain)
- [WebView Java loader](https://android.googlesource.com/platform/frameworks/base/+/main/core/java/android/webkit/WebViewLibraryLoader.java)
- [WebView native loader](https://android.googlesource.com/platform/frameworks/base/+/master/native/webview/loader/loader.cpp)
- [oat_file.cc](https://cs.android.com/android/platform/superproject/main/+/main:art/runtime/oat/oat_file.cc;l=1?q=oat_file.cc%20&sq=&ss=android%2Fplatform%2Fsuperproject%2Fmain)

## Obfuscation
- [DJI: The Art of Obfuscation](https://blog.quarkslab.com/dji-the-art-of-obfuscation.html)

## VNDK Linker Namespace
- [Linker Namespace](https://source.android.com/docs/core/architecture/vndk/linker-namespace)

## Projects
- [AndKittyInjector (C++)](https://github.com/MJx0/AndKittyInjector)

## Android Dynamic Linker
- [Android Dynamic Linker (Marshmallow)](https://zhenhuaw.me/assets/paper/Android%20Dynamic%20Linker%20-%20Marshmallow.pdf)
- [Android Dynamic Linker Blog](https://zhenhuaw.me/blog/2016/android-dynamic-linker.html)
- [Android Linker (Part 1)](http://pwn4.fun/2017/07/02/Android-Linker%EF%BC%88%E4%B8%80%EF%BC%89/)
- [Linker Explanation](https://github.com/nzcv/note/blob/master/linker/10why_three.md/readme.md)
- [Linker Blog Post](https://github.com/xuanxuanblingbling/xuanxuanblingbling.github.io/blob/master/_posts/2018-02-23-so.md)
- [Fake Linker](https://github.com/sanfengAndroid/fake-linker)

## dlopen_ext.h and android_dlopen_ext
- [libdl Group](https://developer.android.com/ndk/reference/group/libdl)
- [android_dlextinfo Struct](https://developer.android.com/ndk/reference/structandroid/dlextinfo)
- [dlopen Manual](https://linux.die.net/man/3/dlopen)
- [Loading SO Files in Android](http://gttiankai.github.io/2018/01/03/android%E7%B3%BB%E7%BB%9F%E5%8A%A0%E8%BD%BDso%E7%9A%84%E6%BA%90%E7%A0%81%E5%88%86%E6%9E%90/)

## Dlopen Examples
- [Dlopen Greylisted Libraries or Custom LD_LIBRARY_PATH (Android 5.0+)](https://gist.github.com/khanhduytran0/faee2be9c8fd1282783b936156a03e1c)

## Blog Posts
- [CSDN Blog on Android](https://blog.csdn.net/god_wen/article/details/136527072)

## Linker PLT Hook
- [Linker PLT Hook](https://github.com/CrackerCat/simpread/blob/main/md/Android%20%E5%8A%A8%E6%80%81%E4%BF%AE%E6%94%B9%20Linker%20%E5%AE%9E%E7%8E%B0%20LD_PRELOAD%20%E5%85%A8%E5%B1%80%E5%BA%93%20PLT%20Hook%20%7C%20sfAndroid%20%E7%A7%BB%E5%8A%A8%E5%AE%89%E5%85%A8.md)

## System.loadLibrary
- [System.loadLibrary Analysis](https://github.com/CrackerCat/simpread/blob/main/md/%E5%AE%89%E5%8D%93%2010%20%E6%BA%90%E7%A0%81%E5%BC%80%E5%8F%91%E5%AE%9A%E5%88%B6%20(28)System.loadLibrary%20%E6%B5%81%E7%A8%8B%E5%88%86%E6%9E%90.md)
- [CSDN Blog on System.loadLibrary](https://blog.csdn.net/weixin_30736301/article/details/99779643)
- [Things About System.loadLibrary](https://github.com/imlk0/imlk0.github.io/blob/master/content/posts/things-about-system-loadibrary.md)

## SO Section Headers
- [SoRebuilder](https://github.com/giglf/SoRebuilder)

## Hook dlopen
- [Hook Dlopen](https://github.com/ogli324/Learn-and-Think-More/blob/master/Android%20Security/Android%E5%BA%94%E7%94%A8%E5%8A%A0%E5%9B%BA/Native%20Hook%E6%B3%A8%E5%85%A5/Android9.0%20hook%20dlopen%E9%97%AE%E9%A2%98%E5%A6%82%E4%BD%95hook%20dlopen%E7%9B%B8%E5%85%B3%E5%87%BD%E6%95%B0%20.md)

## Rust Bindings
- [Rust Mobile Android Activity](https://github.com/rust-mobile/android-activity)
- [Rust Mobile NDK](https://github.com/rust-mobile/ndk?tab=readme-ov-file)

## Miscellaneous
- [Jianshu Article](https://www.jianshu.com/p/764960e933a7)

## Webview Loader
- [Webview Loader Blog](https://blog.csdn.net/Luoshengyang/article/details/53209199)
