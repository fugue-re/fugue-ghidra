# Fugue FDB exporter

- Supports Ghidra 10.x.y.
- Exports both Ghidra projects and binaries supported by Ghidra's loaders.
- GUI-based export plugin via `Script Manager -> External -> FugueExport.java`

## Prerequisites

Install the flatbuffers compiler `flatc`.

Run the following commands:

```
git submodule init
git submodule update --recursive

# make sure that the flatc version is the same
# as the flatbuffers-java version in build.gradle
flatc --java -b -o src/main/java/ extra/schema/fugue.fbs
```

## Build

```
GHIDRA_INSTALL_DIR=/opt/ghidra/ ./gradlew buildExtension
```

## Install

```
unzip -qod "${GHIDRA_INSTALL_DIR}"/Ghidra/Extensions/ dist/$(ls -1t dist | head -n1)
```
