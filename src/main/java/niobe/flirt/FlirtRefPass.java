package niobe.flirt;

import java.util.function.BiConsumer;

import ghidra.app.script.GhidraScript;
import ghidra.program.database.code.CodeManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FunctionManager;

public class FlirtRefPass {
  private Address addr;
  private FlirtModule module;
  private BiConsumer<Address, FlirtFunction> callback;

  public FlirtRefPass(Address addr, FlirtModule module, BiConsumer<Address, FlirtFunction> callback) {
    this.addr = addr;
    this.module = module;
    this.callback = callback;
  }

  public boolean matches(GhidraScript gs, FunctionManager functionManager, CodeManager codeManager) {
loopStart:
    for (var ref : module.getReferencedFunctions()) {
      var refAddr = ref.isOffsetNegative() ? addr.subtract(ref.getOffset()) : addr.add(ref.getOffset());
      var instruction = codeManager.getInstructionContaining(refAddr);
      if (instruction == null) {
        return false;
      }
      var seenData = false;
      var onlyData = true;

      for (var refTo : instruction.getReferencesFrom()) {
        if (refTo.getReferenceType().isCall()) {
          var f = functionManager.getFunctionContaining(refTo.getToAddress());
          if (f == null) { continue; }
          onlyData = false;
          if (f.getName().equals(ref.getName())) {
            continue loopStart;
          } else {
            return false;
          }
        }
        if (refTo.getReferenceType().isData()) {
          //gs.println("Try: " + ref.getName() + " at " + refAddr);
          var f = functionManager.getFunctionContaining(refTo.getToAddress());
          if (f != null) {
            if (f.getName().equals(ref.getName())) {
              //gs.println("Found R: " + f.getName());
              onlyData = false;
              continue loopStart;
            }
            return false;
          }
          seenData = true;
        } else {
          onlyData = false;
        }
      }
      if (seenData && onlyData) continue loopStart;
      return false;
    }

    for (var f : module.getPublicFunctions()) {
      //gs.println("R: " + f.getName() + " to " + addr.add(f.getOffset()));
      callback.accept(addr.add(f.getOffset()), f);
    }
    return true;
  }
}
