# Fugue FDB IDB exporter

- Supports IDA 7.x.
- Works on Windows (including wine for Linux and CrossOver for MacOS) and
  Linux.

## Building

Copy your unpacked IDA Pro SDK to `third-party/`. For example, for `idasdk75.zip`, you should have a directory called `third-party/idasdk75`.

### Linux

```
cmake -DCMAKE_BUILD_TYPE=Release -B build && cmake --build build --parallel
```

### Windows/wine/CrossOver

We can use a docker-based build environment to cross-compile the IDA plugins.
Set the following environment:

```
function vcwine() { docker run -v$HOME:/host/$HOME -w/host/$PWD -u $(id -u):$(id -g) -eMSVCARCH=$MSVCARCH --rm -t -i xorpse/windev:15 "$@"; }
```

Then, build using:
```
vcwine cmake -DCMAKE_BUILD_TYPE=Release -B build
vcwine cmake --build build
```

## Installing

### Linux

- Copy `fugue.so` and `fugue64.so` to `${IDA_INSTALL_DIR}/plugins`.


### Windows/wine/CrossOver

- Copy `fugue.dll` and `fugue64.dll` to `${IDA_INSTALL_DIR}/plugins`.

## Usage

Linux:

```
idat64 -A -OFugueOutput:/tmp/ls-x86_64.fdb -OFugueForceOverwrite:true /usr/bin/ls
```

Using CrossOver for MacOS (with IDA Pro installed in the bottle named
`IDA Pro 7.5`):

```
wine --bottle 'IDA Pro 7.5' --cx-app idat64 -A -OFugueOutput:/tmp/ls-x86_64.fdb /bin/ls
```

## Pre-built plugins for IDA Pro 7.5 (Windows/wine/CrossOver)

- Browse latest: [link](https://git.simulacra.to/fugue/fugue-idapro/-/jobs/artifacts/master/browse?job=build).
- Download latest: [link](https://git.simulacra.to/fugue/fugue-idapro/-/jobs/artifacts/master/download?job=build).

## CrossOver bottle for IDA Pro 7.5

- Download: [link](https://fugue.kr/reveng/tools/ida-pro-7.5.cxarchive)
