package niobe.serialise;

import java.io.FileOutputStream;
import java.io.IOException;

import java.nio.ByteBuffer;
import java.nio.channels.Channels;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.HashMap;
import java.util.Map;
import java.util.HashSet;
import java.util.Set;

import com.google.common.collect.Iterables;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.DecoderException;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.CancelledException;

import niobe.serialise.Database.Project;
import niobe.serialise.ArchBuilder;

public class DatabaseBuilder {
    private org.capnproto.MessageBuilder message;
    private Project.Builder projectBuilder;

    private LinkedHashMap<ArchBuilder, Integer> arches;
    private HashMap<Long, Integer> functionMap;

    private Program currentProgram;
    private TaskMonitor monitor;

    public static long startTime = 0;

    public DatabaseBuilder(Program currentProgram, TaskMonitor monitor) {
      this.currentProgram = currentProgram;
      this.monitor = monitor;

      message = new org.capnproto.MessageBuilder();
      projectBuilder = message.initRoot(Project.factory);

      arches = new LinkedHashMap<>();
      functionMap = new HashMap<>();
    }

    public static void setStartTime() {
        startTime = System.currentTimeMillis() * 1000000L;
    }

    private void makeExportInfo() {
      var meta = currentProgram.getMetadata();
      var exportInfo = projectBuilder.getExportInfo();

      exportInfo.setInputPath(meta.get("Executable Location"));

      try {
        byte[] sha256bytes = Hex.decodeHex(meta.get("Executable SHA256").toCharArray());
        exportInfo.setInputSha256(sha256bytes);
      } catch (DecoderException ex) {
        ex.printStackTrace();
      }

      try {
        byte[] md5bytes = Hex.decodeHex(meta.get("Executable MD5").toCharArray());
        exportInfo.setInputMd5(md5bytes);
      } catch (DecoderException ex) {
        ex.printStackTrace();
      }

      var fileSize = meta.get("# of Bytes");
      exportInfo.setFileSize(Long.parseUnsignedLong(fileSize));
      exportInfo.setExporter("Ghidra v" + meta.get("Created With Ghidra Version"));
    }

    private void makeArchitectures() {
      var architectures = projectBuilder.initArchitectures(arches.size());
      arches.forEach((arch, i) -> {
        architectures.get(i).setName(arch.name);
        architectures.get(i).setEndian(arch.endian);
        architectures.get(i).setBits(arch.bits);
        architectures.get(i).setVariant(arch.variant);
      });
    }

    private int makeArchitecture(Address address) {
      var arch = new ArchBuilder(currentProgram, address);
      var index = this.arches.get(arch);
      if (index == null) {
        index = this.arches.size();
        this.arches.put(arch, index);
      }
      return index;
    }

    private void makeSegments() throws IOException {
      var segments = currentProgram.getMemory().getBlocks();
      var loaded = Arrays.stream(segments).filter(s -> s.isLoaded()).toArray();
      var builder = projectBuilder.initSegments(loaded.length);
      for (var i = 0; i < loaded.length; ++i) {
        var segment = (MemoryBlock)loaded[i];
        var space = segment.getStart().getAddressSpace();
        var segmentBuilder = builder.get(i);

        segmentBuilder.setName(segment.getName());

        segmentBuilder.setAddress(segment.getStart().getUnsignedOffset());
        segmentBuilder.setLength((int)segment.getSize());
        segmentBuilder.setAddressSize(space.getPointerSize());
        segmentBuilder.setAlignment(space.getAddressableUnitSize());

        segmentBuilder.setCode(segment.isExecute());
        segmentBuilder.setData(!segment.isExecute());

        segmentBuilder.setExternal(segment.getName().equals(MemoryBlock.EXTERNAL_BLOCK_NAME));
        segmentBuilder.setExecutable(segment.isExecute());
        segmentBuilder.setReadable(segment.isRead());
        segmentBuilder.setWritable(segment.isWrite());

        var segmentData = segment.getData();
        if (segmentData != null) {
          segmentBuilder.setContent(segmentData.readAllBytes());
        } else {
          segmentBuilder.initContent(0);
        }
      }
    }

    private void makeFormat() {
      var meta = currentProgram.getMetadata();
      var formatFull = meta.get("Executable Format");

      switch (formatFull) {
        case "Executable and Linking Format (ELF)":
          projectBuilder.setFormat("ELF");
          break;
        case "Portable Executable (PE)":
          projectBuilder.setFormat("PE");
          break;
        case "Mac OS X Mach-O":
          projectBuilder.setFormat("Mach-O");
          break;
        default:
          projectBuilder.setFormat("Raw");
      }
    }

    private void makeFunctions() throws CancelledException {
      var blockModel = new BasicBlockModel(currentProgram, true);
      var functionManager = currentProgram.getFunctionManager();
      var referenceManager = currentProgram.getReferenceManager();

      var i = 0;
      for (var function : functionManager.getFunctions(true)) {
        functionMap.put(function.getID(), i++);
      }

      var builder = projectBuilder.initFunctions(i);
      for (var function : functionManager.getFunctions(true)) {
        var myId = functionMap.get(function.getID());
        var fBuilder = builder.get(myId);

        fBuilder.setSymbol(function.getName());
        fBuilder.setAddress(function.getEntryPoint().getUnsignedOffset());

        var incoming = Iterables.toArray(
            Iterables.filter(
              referenceManager.getReferencesTo(function.getEntryPoint()),
              ref -> ref.getReferenceType().isCall() && functionManager.getFunctionContaining(ref.getFromAddress()) != null
            ),
            Reference.class);
        var refsBuilder = fBuilder.initReferences(incoming.length);

        i = 0;
        for (var caller : incoming) {
          var callingFunction = functionManager.getFunctionContaining(caller.getFromAddress());
          var id = functionMap.get(callingFunction.getID());
          var refBuilder = refsBuilder.get(i);
          refBuilder.setAddress(caller.getFromAddress().getUnsignedOffset());
          refBuilder.setSource(id);
          refBuilder.setTarget(myId);
          refBuilder.setCall(true);
          ++i;
        }

        var blocks = new ArrayList<CodeBlock>();
        var blockIter = blockModel.getCodeBlocksContaining(function.getBody(), monitor);
        while (blockIter.hasNext()) {
          blocks.add(blockIter.next());
        }

        var blockCount = blocks.size();
        var blockBuilder = fBuilder.initBlocks(blockCount);
        var blockMap = new HashMap<Address, Integer>();
        i = 0;
        for (var block : blocks) {
          var start = block.getMinAddress();
          blockMap.put(start, i++);
        }

        for (var block : blocks) {
          i = blockMap.get(block.getMinAddress());
          var blockId = ((long)myId << 32L) | (long)i;
          var bBuilder = blockBuilder.get(i);

          var start = block.getMinAddress();
          if (start.equals(function.getEntryPoint())) {
            fBuilder.setEntry((long)myId << 32L | (long)i);
          }
          var end = block.getMaxAddress();

          bBuilder.setAddress(start.getUnsignedOffset());
          bBuilder.setLength((int)(end.subtract(start)+1));
          bBuilder.setArchitecture(makeArchitecture(start));

          var preds = new ArrayList<CodeBlockReference>();
          var predsIter = block.getSources(monitor);
          while (predsIter.hasNext()) {
            var pred = predsIter.next();
            if (blockMap.containsKey(pred.getSourceAddress()) && (pred.getFlowType().isJump() || pred.getFlowType().isFallthrough())) {
              preds.add(pred);
            }
          }
          var predCount = preds.size();
          var predsBuilder = bBuilder.initPredecessors(predCount);
          i = 0;
          for (var pred : preds) {
            var predId = (long)myId << 32L | (long)blockMap.get(pred.getSourceAddress());
            predsBuilder.get(i).setSource(predId);
            predsBuilder.get(i).setTarget(blockId);
            predsBuilder.get(i).setFunction(myId);
            ++i;
          }

          var succs = new ArrayList<CodeBlockReference>();
          var succsIter = block.getDestinations(monitor);
          while (succsIter.hasNext()) {
            var succ = succsIter.next();
            if (blockMap.containsKey(succ.getDestinationAddress()) && (succ.getFlowType().isJump() || succ.getFlowType().isFallthrough())) {
              succs.add(succ);
            }
          }
          var succCount = succs.size();
          var succsBuilder = bBuilder.initSuccessors(succCount);
          i = 0;
          for (var succ : succs) {
            var succId = (long)myId << 32L | (long)blockMap.get(succ.getDestinationAddress());
            succsBuilder.get(i).setSource(blockId);
            succsBuilder.get(i).setTarget(succId);
            succsBuilder.get(i).setFunction(myId);
            ++i;
          }
        }
      }
    }

    public void exportTo(String outputFileName) throws CancelledException, IOException {
      projectBuilder.getExportInfo().setStartTime(startTime);
      projectBuilder.getExportInfo().setExportTime(System.currentTimeMillis() * 1000000L);
      makeArchitecture(null);

      var meta = currentProgram.getMetadata();
      projectBuilder.setEndian(meta.get("Endian").equals("Big"));

      makeExportInfo();
      makeFormat();
      makeSegments();
      makeFunctions();
      makeArchitectures();
      projectBuilder.getExportInfo().setFinishTime(System.currentTimeMillis() * 1000000L);


      org.capnproto.SerializePacked.writeToUnbuffered(
          (new java.io.FileOutputStream(outputFileName)).getChannel(),
          message);
    }
}
