Pull requests are welcomed.

- [ ] Try to run the given injection techniques code.
- [ ] Understand how each technique works
- [ ] Understand the attack vector and the different parts (stages) of the chain    
  (i.e the bridgehead shellcode, injection to process memory,LPE, when to create a new process etc.)
- [ ] Describe the need for a custom statically PIC compiled elf (Shared object library) loader shellcode.  
- [ ] Injection vs patching at runtime?
- [ ] Implement / imporve it by yourself.

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
- [Webview Loader](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/native/opengl/libs/EGL/Loader.cpp;l=1?q=Loader.cpp%20&sq=&ss=android%2Fplatform%2Fsuperproject%2Fmain)
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
