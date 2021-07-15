# Fugue FDB exporter

Ghidra extension to use FDB format in scripts

## Prerequisites

```
capnp compile --src-prefix=extra -ojava:src/main/java/fugue/serialise extra/fugue_db.capnp
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
