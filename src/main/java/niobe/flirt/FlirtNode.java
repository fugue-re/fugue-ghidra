package niobe.flirt;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Set;
import java.util.function.BiConsumer;

import ghidra.app.script.GhidraScript;
import ghidra.program.database.code.CodeManager;
import ghidra.program.model.address.Address;

public class FlirtNode {
  private int length;
  private long variantMaskValue;
  private ArrayList<Boolean> variantMask;
  private ArrayList<Byte> pattern;
  private ArrayList<FlirtNode> children;
  private ArrayList<FlirtModule> modules;

  public FlirtNode(FlirtByteBuffer buf, byte version, boolean isRoot) throws IOException {
    variantMask = new ArrayList<>();
    pattern = new ArrayList<>();
    if (isRoot) {
      length = 0;
      variantMaskValue = 0;
    } else {
      length = buf.read8() & 0xff;
      variantMaskValue = buf.readNodeVariantMask(length);
      buf.readNodeBytes(length, variantMaskValue, pattern, variantMask);
    }

    children = new ArrayList<>();
    var nodes = buf.readMultipleBytes();
    if (nodes == 0) {
      modules = FlirtModule.parseAll(buf, version);
    } else {
      modules = new ArrayList<>();
      for (var i = 0; i < nodes; ++i) {
        children.add(new FlirtNode(buf, version, false));
      }
    }
  }

  public ArrayList<FlirtNode> getChildren() {
    return children;
  }

  public ArrayList<FlirtModule> getModules() {
    return modules;
  }

  public ArrayList<Byte> getPattern() {
    return pattern;
  }

  public ArrayList<Boolean> getVariantMask() {
    return variantMask;
  }

  public boolean matchesPattern(GhidraScript gs, byte[] buf, int offset) {
    if (buf.length < offset + pattern.size()) {
      return false;
    }

    for (var i = 0; i < pattern.size(); ++i) {
      if (variantMask.get(i).booleanValue()) {
        continue;
      }
      if (buf[offset+i] != pattern.get(i).byteValue()) {
        return false;
      }
    }
    return true;
  }

  public boolean matches(GhidraScript gs, byte[] buf, Address addr, int offset, ArrayList<FlirtRefPass> secondPass, Set<String> knownFunctions, CodeManager codeManager, BiConsumer<Address, FlirtFunction> callback) {
    if (matchesPattern(gs, buf, offset)) {
      if (children.size() > 0) {
        for (var child : children) {
          if (child.matches(gs, buf, addr, offset + length, secondPass, knownFunctions, codeManager, callback)) {
            return true;
          }
        }
      } else {
        for (var module : modules) {
          if (module.matches(gs, buf, addr, offset + length, secondPass, knownFunctions, codeManager, callback)) {
            return true;
          }
        }
      }
    }
    return false;
  }
}
