package niobe.flirt;

public class FlirtParseResult<T> {
  private T result;
  private byte flags;
  private int offset;

  public static final byte PARSE_MORE_PUBLIC_NAMES          = 0x01;
  public static final byte PARSE_READ_TAIL_BYTES            = 0x02;
  public static final byte PARSE_READ_REFERENCED_FUNCTIONS  = 0x04;
  public static final byte PARSE_MORE_MODULES_WITH_SAME_CRC = 0x08;
  public static final byte PARSE_MORE_MODULES               = 0x10;

  public FlirtParseResult(T result, byte flags) {
    this.result = result;
    this.flags = flags;
    this.offset = 0;
  }

  public FlirtParseResult(T result, byte flags, int offset) {
    this(result, flags);
    this.offset = offset;
  }

  public T getResult() {
    return result;
  }

  public byte getFlags() {
    return flags;
  }

  public int getOffset() {
    return offset;
  }
}
