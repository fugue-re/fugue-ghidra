package niobe.flirt;

import java.io.IOException;

import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Set;
import java.util.function.BiConsumer;

import ghidra.app.script.GhidraScript;
import ghidra.program.database.code.CodeManager;
import ghidra.program.model.address.Address;

import java.nio.file.FileSystems;

public class FlirtFile {
  private FlirtByteBuffer bytesView;
  private FlirtHeader header;
  private FlirtNode treeRoot;

  public FlirtFile(String path) throws IOException {
    var view = new FlirtByteBuffer(Files.readAllBytes(FileSystems.getDefault().getPath(path)));

    this.header = new FlirtHeader(view);
    this.bytesView = verifyAndDeflate(view);
    this.treeRoot = new FlirtNode(this.bytesView, this.header.getVersion(), true);
  }

  private FlirtByteBuffer verifyAndDeflate(FlirtByteBuffer buf) throws IOException {
    if (header.isCompressed()) {
      if (header.getVersion() == 5) {
        throw new IOException("compression unsupported on Flirt versions <= 5");
      }

      return buf.deflateFrom();
    }
    return buf;
  }

  public FlirtHeader getHeader() {
    return header;
  }

  public FlirtNode getTreeRoot() {
    return treeRoot;
  }

  public boolean matchesFunction(GhidraScript gs, byte[] buf, Address addr, ArrayList<FlirtRefPass> secondPass, Set<String> knownFunctions, CodeManager codeManager, BiConsumer<Address, FlirtFunction> callback) {
    var i = 0;
    for (var child : getTreeRoot().getChildren()) {
      if (child.matches(gs, buf, addr, 0, secondPass, knownFunctions, codeManager, callback)) {
        return true;
      }
    }
    return false;
  }
}
