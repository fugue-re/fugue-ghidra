package niobe.flirt;

import java.io.IOException;
import java.util.ArrayList;

public class FlirtTailByte {
  private int offset;
  private byte value;

  public FlirtTailByte(FlirtByteBuffer buf, byte version) throws IOException {
    offset = (version >= 9) ? buf.readMultipleBytes() : (buf.readMaxTwoBytes() & 0xffff);
    value = buf.read8();
  }

  public static ArrayList<FlirtTailByte> parseAll(FlirtByteBuffer buf, byte version) throws IOException {
    var length = (version >= 8) ? (buf.read8() & 0xff) : 1;
    var tailBytes = new ArrayList<FlirtTailByte>();
    for (var i = 0; i < length; ++i) {
      tailBytes.add(new FlirtTailByte(buf, version));
    }
    return tailBytes;
  }

  public int getOffset() {
    return offset;
  }

  public byte getValue() {
    return value;
  }
}
