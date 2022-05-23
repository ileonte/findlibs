# findlibs

Small program that reads dynamic linker cache files (`ld.so.conf`) and extracts paths to certain system libraries as well as a list of directories containing system libraries.

Test data from various distributions can be found under `testdata/`.

Run `./compile` to build the program (binary will be generated under the `build/` directory).

Examples:
* print 64bit libs and search directories for a Gentoo system:
```
$ ./build/findlibs testdata/gentoo
Library search paths: [/usr/lib64,/lib64,/usr/lib/gcc/x86_64-pc-linux-gnu/11.3.0,/usr/lib/rust/lib,/usr/lib,/usr/lib/llvm/14/lib64]
System libs:
  dynamic linker : /lib64/ld-linux-x86-64.so.2
  libc.so        : /lib64/libc.so.6
  libm.so        : /lib64/libm.so.6
  libpthread.so  : /lib64/libpthread.so.0
  librt.so       : /lib64/librt.so.1
```
* print 32bit libs and search directories for a Gentoo system:
```
$ ./build/findlibs testdata/gentoo 32
Library search paths: [/lib,/usr/lib/gcc/x86_64-pc-linux-gnu/11.3.0/32,/usr/lib]
System libs:
  dynamic linker : /lib/ld-linux.so.2
  libc.so        : /lib/libc.so.6
  libm.so        : /lib/libm.so.6
  libpthread.so  : /lib/libpthread.so.0
  librt.so       : /lib/librt.so.1
```
