package niobe.flirt;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashSet;

import ghidra.program.model.address.Address;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.code.CodeManager;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;

import niobe.serialise.ArchBuilder;

public class Flirt {
  private String archDir;
  private int totalRenamed;
  private CodeManager codeManager;
  private ProgramDB program;
  private FunctionManager functionManager;
  private Memory memory;
  private HashSet<String> knownFunctionNames;
  private GhidraScript associatedScript;

  private FlirtFile lastApplied;

  private static final int VIEW_SIZE = 0x400;

  public Flirt(String baseDir, ArchBuilder arch, Program program) {
    this.archDir = String.join(File.separator, baseDir, Flirt.normalisedArchName(arch));
    this.totalRenamed = 0;
    this.program = (ProgramDB)program;
    this.codeManager = this.program.getCodeManager();
    this.functionManager = this.program.getFunctionManager();
    this.memory = this.program.getMemory();
    this.knownFunctionNames = new HashSet<>();
    this.lastApplied = null;

    for (var f : this.functionManager.getFunctions(true)) {
      this.knownFunctionNames.add(f.getName());
    }
  }

  private static String normalisedArchName(ArchBuilder arch) {
    switch (arch.variant) {
      case "X86": case "X86-64":
        return "pc";
      case "ARM": case "THUMB": case "AARCH64":
        return "arm";
      case "MIPS":
        return "mips";
      default:
        return "";
    }
  }

  public FlirtFile loadSignature(String name) throws IOException {
    var path = String.join(File.separator, this.archDir, name + ".sig");
    return new FlirtFile(path);
  }

  private void renameFunction(Address addr, FlirtFunction f) {
    var ghidraF = functionManager.getFunctionAt(addr);
    if (ghidraF == null || !(ghidraF.getName().startsWith("FUN_") || ghidraF.getName().startsWith("thunk_FUN_"))) {
      return;
    }
    var name = f.getName().replaceFirst("\\?*", "");
    if (!name.equals("")) {
      var renameIndex = name;
      var index = 0;
      while (!associatedScript.getGlobalFunctions(renameIndex).isEmpty()) {
        renameIndex = name + "_" + index;
        index += 1;
      }

      try {
        ghidraF.setName(renameIndex, SourceType.USER_DEFINED);
        knownFunctionNames.add(renameIndex);
        totalRenamed += 1;
      } catch (Exception _ex) {
        // do nothing
      }
    }
  }

  public FlirtFile getLastApplied() {
    return this.lastApplied;
  }

  public int loadAndApplySignatureTo(String name, Address fcn, GhidraScript gs) throws IOException {
    this.associatedScript = gs;
    var sig = loadSignature(name);
    lastApplied = sig;

    var function = functionManager.getFunctionAt(fcn);
    var secondPass = new ArrayList<FlirtRefPass>();

    var entryAddress = function.getEntryPoint();
    var highAddress = entryAddress.add(Flirt.VIEW_SIZE);
    var size = highAddress.subtract(entryAddress);

    if (size <= 0 || size > Integer.MAX_VALUE) {
      return 0;
    }

    var bytes = new byte[(int)size];
    try {
      memory.getBytes(entryAddress, bytes);
    } catch (MemoryAccessException _ex) {
      return 0;
    }
    sig.matchesFunction(gs, bytes, entryAddress, secondPass, knownFunctionNames, codeManager, (addr, f) -> renameFunction(addr, f));

    for (var tryAgain : secondPass) {
      tryAgain.matches(gs, functionManager, codeManager);
    }

    return 1;
  }

  public int loadAndApplySignature(String name, GhidraScript gs) throws IOException {
    this.associatedScript = gs;
    var sig = loadSignature(name);
    lastApplied = sig;
    var secondPass = new ArrayList<FlirtRefPass>();
    for (var function : functionManager.getFunctionsNoStubs(true)) {
      var entryAddress = function.getEntryPoint();
      var highAddress = entryAddress.add(Flirt.VIEW_SIZE);
      var size = highAddress.subtract(entryAddress);

      if (size <= 0 || size > Integer.MAX_VALUE) {
        continue;
      }

      var bytes = new byte[(int)size];
      try {
        memory.getBytes(entryAddress, bytes);
      } catch (MemoryAccessException _ex) {
        continue;
      }
      sig.matchesFunction(gs, bytes, entryAddress, secondPass, knownFunctionNames, codeManager, (addr, f) -> renameFunction(addr, f));
    }

    for (var tryAgain : secondPass) {
      tryAgain.matches(gs, functionManager, codeManager);
    }

    return totalRenamed;
  }
}
