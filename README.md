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

## Debug

```
capnp convert packed:text extra/fugue_db.capnp Database < /tmp/output.fdb | less
```
