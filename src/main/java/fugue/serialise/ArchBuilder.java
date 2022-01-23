package fugue.serialise;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

public class ArchBuilder {
  public String processor;
  public String variant;
  public int bits;
  public boolean endian;

  @Override
  public int hashCode() {
    int hash = 7;
    hash = 31 * hash + bits;
    hash = 31 * hash + (endian ? 1 : 0);
    hash = 31 * hash + (processor == null ? 0 : processor.hashCode());
    hash = 31 * hash + (variant == null ? 0 : variant.hashCode());
    return hash;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null) return false;
    ArchBuilder other = (ArchBuilder)o;
    return variant.equals(other.variant)
      && processor.equals(other.processor)
      && bits == other.bits
      && endian == other.endian;
  }

  public ArchBuilder(Program currentProgram, Address _addr) {
    var ldef = currentProgram.getLanguage().getLanguageDescription();
    processor = ldef.getProcessor().toString();
    endian = ldef.getEndian().isBigEndian();
    variant = ldef.getVariant();
    bits = ldef.getSize();
  }

  public ArchBuilder(Program currentProgram) {
    this(currentProgram, null);
  }
}
