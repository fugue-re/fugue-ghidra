package niobe.flirt;

import ghidra.app.script.GhidraScript;
import ghidra.program.database.code.CodeManager;
import ghidra.program.model.address.Address;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Set;
import java.util.function.BiConsumer;

public class FlirtModule {
  private short crcLength;
  private short crc16;
  private int length;
  private ArrayList<FlirtFunction> publicFunctions;
  private ArrayList<FlirtFunction> referencedFunctions;
  private ArrayList<FlirtTailByte> tailBytes;

  public FlirtModule(byte crcLength, short crc16, int length, ArrayList<FlirtFunction> publicFunctions, ArrayList<FlirtFunction> referencedFunctions, ArrayList<FlirtTailByte> tailBytes) {
    this.crcLength = crcLength;
    this.crc16 = crc16;
    this.length = length;
    this.publicFunctions = publicFunctions;
    this.referencedFunctions = referencedFunctions;
    this.tailBytes = tailBytes;
  }

  public static FlirtParseResult<FlirtModule> parse(FlirtByteBuffer buf, byte version, byte crcLength, short crc16) throws IOException {
    var length = (version >= 9) ? buf.readMultipleBytes() : (buf.readMaxTwoBytes() & 0xffff);
    var publicFunctions = new ArrayList<FlirtFunction>();
    var offset = 0;
    byte lastFlags = 0;

    while (true) {
      var result = FlirtFunction.parsePublicFunction(buf, version, offset);
      publicFunctions.add(result.getResult());
      offset = result.getOffset();
      lastFlags = (byte)(result.getFlags() & 0xff);
      if ((lastFlags & FlirtParseResult.PARSE_MORE_PUBLIC_NAMES) == 0) {
        break;
      }
    }

    var tailBytes = ((lastFlags & FlirtParseResult.PARSE_READ_TAIL_BYTES) != 0) ? FlirtTailByte.parseAll(buf, version) : new ArrayList<FlirtTailByte>();
    var referencedFunctions = ((lastFlags & FlirtParseResult.PARSE_READ_REFERENCED_FUNCTIONS) != 0) ? FlirtFunction.parseReferencedFunctions(buf, version) : new ArrayList<FlirtFunction>();

    return new FlirtParseResult<>(new FlirtModule(crcLength, crc16, length, publicFunctions, referencedFunctions, tailBytes), lastFlags);
  }

  public static ArrayList<FlirtModule> parseAll(FlirtByteBuffer buf, byte version) throws IOException {
    var modules = new ArrayList<FlirtModule>();
    var lastFlag = 0;
    while (true) {
      var crcLength = buf.read8();
      var crc16 = buf.read16be();

      while (true) {
        var result = FlirtModule.parse(buf, version, crcLength, crc16);
        modules.add(result.getResult());
        if ((result.getFlags() & FlirtParseResult.PARSE_MORE_MODULES_WITH_SAME_CRC) == 0) {
          lastFlag = result.getFlags();
          break;
        }
      }

      if ((lastFlag & FlirtParseResult.PARSE_MORE_MODULES) == 0) {
        break;
      }
    }
    return modules;
  }

  public short getCrc16() {
    return crc16;
  }

  public ArrayList<FlirtFunction> getReferencedFunctions() {
    return referencedFunctions;
  }

  public ArrayList<FlirtFunction> getPublicFunctions() {
    return publicFunctions;
  }

  public boolean matches(GhidraScript gs, byte[] buf, Address addr, int offset, ArrayList<FlirtRefPass> secondPass, Set<String> knownFunctions, CodeManager codeManager, BiConsumer<Address, FlirtFunction> callback) {
    int bufSize = buf.length - offset;
    int crcLen = crcLength & 0xff;
    if (crcLen > 0 && !(crcLen < bufSize && crc16 == FlirtCrc16.crc16(buf, offset, crcLen/*ByteBuffer.wrap(buf, offset, crcLen)*/))) {
      return false;
    }

    for (var tailByte : tailBytes) {
      if (!(crcLen + tailByte.getOffset() < bufSize && buf[offset+crcLen+tailByte.getOffset()] == tailByte.getValue())) {
        return false;
      }
    }

    for (var r : referencedFunctions) {
      if (!knownFunctions.contains(r.getName())) {
        secondPass.add(new FlirtRefPass(addr, this, callback));
        return false;
      }
    }

    // all refs, if they exist are resolved; attempt a match
    if (referencedFunctions.size() > 0) {
      var pass = new FlirtRefPass(addr, this, callback);
      return pass.matches(gs, gs.getCurrentProgram().getFunctionManager(), codeManager);
    }

    for (var f : publicFunctions) {
      callback.accept(addr.add(f.getOffset()), f);
    }

    return true;
  }
}
