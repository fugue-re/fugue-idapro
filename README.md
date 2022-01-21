# Fugue FDB IDB exporter

- Supports IDA 7.x.
- Works on Windows, MacOS, and Linux.

## Build

Copy your unpacked IDA Pro SDK to `third-party/`. For example, for `idasdk75.zip`, you should have a directory called `third-party/idasdk75`.

```
cmake -DCMAKE_BUILD_TYPE=Release -B build
cmake --build build --config Release --parallel
```

## Install

Copy `fugue.{dll/dylib/so}` and `fugue64.{dll/dylib/so}` to `${IDA_INSTALL_DIR}/plugins`.

## Usage (command line)

```
idat64 -A -OFugueOutput:/tmp/ls-x86_64.fdb -OFugueForceOverwrite:true -o/tmp/ls.i64 /bin/ls
```
