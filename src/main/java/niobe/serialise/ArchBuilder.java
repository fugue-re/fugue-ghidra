package niobe.serialise;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

public class ArchBuilder {
  public String name;
  public String variant;
  public int bits;
  public boolean endian;

  @Override
  public int hashCode() {
    int hash = 7;
    hash = 31 * hash + bits;
    hash = 31 * hash + (endian ? 1 : 0);
    hash = 31 * hash + (name == null ? 0 : name.hashCode());
    hash = 31 * hash + (variant == null ? 0 : variant.hashCode());
    return hash;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null) return false;
    ArchBuilder other = (ArchBuilder)o;
    return variant.equals(other.variant)
      && name.equals(other.name)
      && bits == other.bits
      && endian == other.endian;
  }

  public ArchBuilder(Program currentProgram, Address addr) {
    var meta = currentProgram.getMetadata();
    bits = Integer.parseInt(meta.get("Address Size"));
    endian = meta.get("Endian").equals("Big");
    name = currentProgram.getLanguage()
      .getLanguageDescription()
      .getVariant()
      .replaceFirst("[^ ]* \\(([^)]*)\\)", "$1");
    variant = meta.get("Processor");

    switch (variant) {
      case "x86": {
        if (bits == 64) variant = "X86-64";
        if (bits == 32) variant = "X86";
        break;
      }
      case "ARM": {
        if (bits == 64) variant = "AARCH64";
        if (bits == 32) {
          if (addr != null) {
            var tmode = currentProgram.getRegister("TMode");
            var value = currentProgram.getProgramContext().getRegisterValue(tmode, addr);
            variant = value.getUnsignedValueIgnoreMask().longValue() == 1 ? "THUMB" : "ARM";
          } else {
            variant = "ARM";
          }
        }
        break;
      }
      case "PowerPC": {
        if (bits == 64) variant = "PPC64";
        if (bits == 32) variant = "PPC";
        break;
      }
      case "v850": {
        variant = "V850";
        break;
      }
    }
  }

  public ArchBuilder(Program currentProgram) {
    this(currentProgram, null);
  }
}
