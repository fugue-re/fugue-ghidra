package niobe.flirt;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;

public class FlirtFunction {
  private boolean isLocal;
  private boolean isCollision;
  private boolean negativeOffset;
  private int offset;
  private String name;

  public static final byte FUNCTION_LOCAL = 0x02;
  public static final byte FUNCTION_UNRESOLVED_COLLISION = 0x08;
  public static final int MAX_NAME_LEN = 1024;

  public FlirtFunction(String name, int offset, boolean negativeOffset, boolean isLocal, boolean isCollision) {
    this.name = name;
    this.offset = offset;
    this.negativeOffset = negativeOffset;
    this.isLocal = isLocal;
    this.isCollision = isCollision;
  }

  public static FlirtFunction parseReferencedFunction(FlirtByteBuffer buf, byte version) throws IOException {
    var offset = (version >= 9) ? buf.readMultipleBytes() : (buf.readMaxTwoBytes() & 0xffff);
    int nameLength = buf.read8() & 0xff;
    if (nameLength == 0) {
      nameLength = buf.readMultipleBytes();
    }

    if (nameLength < 0) {
      throw new IOException("referenced function name length < 0");
    }

    var nameBytes = buf.read(nameLength);
    var negativeOffset = false;
    if (nameBytes[nameLength-1] == 0) {
      nameBytes = Arrays.copyOf(nameBytes, nameLength-1);
      negativeOffset = true;
    }

    var name = new String(nameBytes, StandardCharsets.US_ASCII);

    return new FlirtFunction(name, offset, negativeOffset, false, false);
  }

  public static ArrayList<FlirtFunction> parseReferencedFunctions(FlirtByteBuffer buf, byte version) throws IOException {
    var length = (version >= 8) ? buf.read8() : 1;
    var referencedFunctions = new ArrayList<FlirtFunction>();
    for (var i = 0; i < length; ++i) {
      referencedFunctions.add(FlirtFunction.parseReferencedFunction(buf, version));
    }
    return referencedFunctions;
  }

  public static FlirtParseResult<FlirtFunction> parsePublicFunction(FlirtByteBuffer buf, byte version, int offset) throws IOException {
    var isLocal = false;
    var isCollision = false;

    offset += (version >= 9) ? buf.readMultipleBytes() : (buf.readMaxTwoBytes() & 0xffff);

    var b = buf.read8();
    if (b < 0x20) {
      isLocal = (b & FlirtFunction.FUNCTION_LOCAL) != 0;
      isCollision = (b & FlirtFunction.FUNCTION_UNRESOLVED_COLLISION) != 0;
      b = buf.read8();
    }

    var nameBytes = new byte[FlirtFunction.MAX_NAME_LEN];
    var actualProcessed = 0;
    // var nameFinished = false;

    while (actualProcessed < FlirtFunction.MAX_NAME_LEN) {
      if (b < 0x20) {
        // nameFinished = true;
        break;
      }
      nameBytes[actualProcessed++] = b;
      b = buf.read8();
    }

    var flags = b;
    var name = new String(Arrays.copyOfRange(nameBytes, 0, actualProcessed), StandardCharsets.US_ASCII);

    return new FlirtParseResult<FlirtFunction>(new FlirtFunction(name, offset, false, isLocal, isCollision), flags, offset);
  }

  public String getName() {
    return name;
  }

  public int getOffset() {
    return offset;
  }

  public boolean isOffsetNegative() {
    return negativeOffset;
  }
}
