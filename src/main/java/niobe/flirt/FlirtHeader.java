package niobe.flirt;

import java.nio.charset.StandardCharsets;

import java.io.IOException;

import java.util.Arrays;


public class FlirtHeader {
  private byte version;
  private byte arch;
  private int fileTypes;
  private short osTypes;
  private short appTypes;
  private short features;
  private short oldNFunctions;
  private short crc16;
  private byte[] cType;
  private short cTypesCrc16;
  private int nFunctions;
  private short patternSize;
  private String libraryName;

  public static final short FEATURE_STARTUP       = 0x01;
  public static final short FEATURE_CTYPE_CRC     = 0x02;
  public static final short FEATURE_2BYTE_CTYPE   = 0x04;
  public static final short FEATURE_ALT_CTYPE_CRC = 0x08;
  public static final short FEATURE_COMPRESSED    = 0x10;

  public FlirtHeader(FlirtByteBuffer buf) throws IOException {
    if (!Arrays.equals(buf.read(6), "IDASGN".getBytes(StandardCharsets.US_ASCII))) {
      throw new IOException("invalid magic bytes");
    }

    version = buf.read8();

    if (version < 5 || version > 10) {
      throw new IOException("unsupported version");
    }

    arch = buf.read8();
    fileTypes = buf.read32le();
    osTypes = buf.read16le();
    appTypes = buf.read16le();
    features = buf.read16le();
    oldNFunctions = buf.read16le();
    crc16 = buf.read16le();
    cType = buf.read(12);
    var libraryNameLen = buf.read8();
    cTypesCrc16 = buf.read16le();

    if (version >= 6) {
      nFunctions = buf.read32le();
      if (version >= 8) {
        patternSize = buf.read16le();
        if (version > 9) {
          buf.read16le();
        }
      }
    }

    libraryName = new String(buf.read(libraryNameLen), StandardCharsets.US_ASCII);
  }

  public byte getVersion() {
    return version;
  }

  public short getFeatures() {
    return features;
  }

  public boolean isCompressed() {
    return (features & FEATURE_COMPRESSED) != 0;
  }
}
