# Fugue FDB exporter

Ghidra extension to use FDB format in scripts

## Prerequisites

```
git submodule sync --recursive
git submodule update --recursive
flatc --java -b -o src/main/java/ extra/schema/fugue.fbs
```

## Build

```
GHIDRA_INSTALL_DIR=/opt/ghidra/ gradle buildExtension
```

## Install

```
unzip -q -o -d "${GHIDRA_INSTALL_DIR}"/Ghidra/Extensions/ dist/$(ls -1t dist | head -n1)
```

## Debug

```
capnp convert packed:text extra/fugue_db.capnp Database < /tmp/output.fdb | less
```
