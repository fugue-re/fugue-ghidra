package fugue.serialise;

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
import com.google.flatbuffers.FlatBufferBuilder;

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

import fugue.schema.*;
import fugue.serialise.ArchBuilder;

public class DatabaseBuilder {
    private FlatBufferBuilder message;

    private LinkedHashMap<ArchBuilder, Integer> arches;
    private HashMap<Long, Integer> functionMap;

    private Program currentProgram;
    private TaskMonitor monitor;

    public DatabaseBuilder(Program currentProgram, TaskMonitor monitor) {
      this.currentProgram = currentProgram;
      this.monitor = monitor;

      message = new FlatBufferBuilder();

      arches = new LinkedHashMap<>();
      functionMap = new HashMap<>();
    }

    private int makeMetadata() {
      var meta = currentProgram.getMetadata();

      int inputMd5 = 0;
      int inputSha256 = 0;

      try {
        byte[] sha256bytes = Hex.decodeHex(meta.get("Executable SHA256").toCharArray());
        inputSha256 = Metadata.createInputSha256Vector(message, sha256bytes);
      } catch (DecoderException ex) {
        ex.printStackTrace();
      }

      try {
        byte[] md5bytes = Hex.decodeHex(meta.get("Executable MD5").toCharArray());
        inputMd5 = Metadata.createInputMd5Vector(message, md5bytes);
      } catch (DecoderException ex) {
        ex.printStackTrace();
      }

      var inputPath = message.createString(meta.get("Executable Location"));
      var inputFormat = message.createString(makeFormat());
      var inputSize = Long.parseUnsignedLong(meta.get("# of Bytes"));
      var exporter = message.createString("Ghidra v" + meta.get("Created With Ghidra Version"));
      Metadata.startMetadata(message);

      Metadata.addInputFormat(message, inputFormat);
      Metadata.addInputPath(message, inputPath);
      Metadata.addInputSize(message, inputSize);
      Metadata.addInputMd5(message, inputMd5);
      Metadata.addInputSha256(message, inputSha256);
      Metadata.addExporter(message, exporter);

      return Metadata.endMetadata(message);
    }

    private int makeArchitectures() {
      var architectures = new int[arches.size()];
      arches.forEach((arch, i) -> {
        var processor = message.createString(arch.processor);
        var variant = message.createString(arch.variant);

        Architecture.startArchitecture(message);
        Architecture.addProcessor(message, processor);
        Architecture.addEndian(message, arch.endian);
        Architecture.addBits(message, arch.bits);
        Architecture.addVariant(message, variant);

        architectures[i] = Architecture.endArchitecture(message);
      });
      return Project.createArchitecturesVector(message, architectures);
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

    private int makeSegments() throws IOException {
      var segments = currentProgram.getMemory().getBlocks();
      var loaded = Arrays.stream(segments).filter(s -> s.isLoaded()).toArray();

      var segmentVector = new int[loaded.length];
      var ldef = currentProgram.getLanguage().getLanguageDescription();

      for (var i = 0; i < loaded.length; ++i) {
        var segment = (MemoryBlock)loaded[i];
        var space = segment.getStart().getAddressSpace();

        var segmentName = message.createString(segment.getName());
        var segmentData = segment.getData();
        var segmentBytes = Segment.createBytesVector(
            message,
            (segmentData != null) ? segmentData.readAllBytes() : new byte[0]
        );

        Segment.startSegment(message);

        Segment.addName(message, segmentName);
        Segment.addAddress(message, segment.getStart().getUnsignedOffset());
        Segment.addSize(message, segment.getSize());
        Segment.addAddressSize(message, space.getPointerSize() * 8);
        Segment.addAlignment(message, space.getAddressableUnitSize());
        Segment.addBits(message, space.getPointerSize() * 8);
        Segment.addEndian(message, (segment.isExecute() ? ldef.getInstructionEndian() : ldef.getEndian()).isBigEndian());
        Segment.addCode(message, segment.isExecute());
        Segment.addData(message, !segment.isExecute());
        Segment.addExternal(message, segment.getName().equals(MemoryBlock.EXTERNAL_BLOCK_NAME));
        Segment.addReadable(message, segment.isRead());
        Segment.addWritable(message, segment.isWrite());
        Segment.addExecutable(message, segment.isExecute());
        Segment.addBytes(message, segmentBytes);

        segmentVector[i] = Segment.endSegment(message);
      }

      return Project.createSegmentsVector(message, segmentVector);
    }

    private String makeFormat() {
      var meta = currentProgram.getMetadata();
      var formatFull = meta.get("Executable Format");

      switch (formatFull) {
        case "Executable and Linking Format (ELF)":
          return "ELF";
        case "Portable Executable (PE)":
          return "PE";
        case "Mac OS X Mach-O":
          return "Mach-O";
        case "Terse Executable (TE)":
          return "TE";
        default:
          return "Raw";
      }
    }

    private int makeFunctions() throws CancelledException {
      var blockModel = new BasicBlockModel(currentProgram, true);
      var functionManager = currentProgram.getFunctionManager();
      var referenceManager = currentProgram.getReferenceManager();

      var i = 0;
      for (var function : functionManager.getFunctions(true)) {
        functionMap.put(function.getID(), i++);
      }

      var functions = new int[i];
      for (var function : functionManager.getFunctions(true)) {
        var myId = functionMap.get(function.getID());

        var incoming = Iterables.toArray(
            Iterables.filter(
              referenceManager.getReferencesTo(function.getEntryPoint()),
              ref -> ref.getReferenceType().isCall() && functionManager.getFunctionContaining(ref.getFromAddress()) != null
            ),
            Reference.class);

        var referencesVector = new int[incoming.length];

        i = 0;
        for (var caller : incoming) {
          var callingFunction = functionManager.getFunctionContaining(caller.getFromAddress());
          var id = functionMap.get(callingFunction.getID());

          InterRef.startInterRef(message);

          InterRef.addAddress(message, caller.getFromAddress().getUnsignedOffset());
          InterRef.addSource(message, id);
          InterRef.addTarget(message, myId);
          InterRef.addCall(message, true);

          referencesVector[i] = InterRef.endInterRef(message);

          ++i;
        }

        var blocks = new ArrayList<CodeBlock>();
        var blockIter = blockModel.getCodeBlocksContaining(function.getBody(), monitor);
        while (blockIter.hasNext()) {
          blocks.add(blockIter.next());
        }

        var blockCount = blocks.size();
        var blockMap = new HashMap<Address, Integer>();
        i = 0;
        for (var block : blocks) {
          var start = block.getMinAddress();
          blockMap.put(start, i++);
        }

        var blocksVector = new int[blockCount];
        var entry = 0L;

        for (var block : blocks) {
          i = blockMap.get(block.getMinAddress());

          var currBlockId = i;
          var blockId = ((long)myId << 32L) | (long)i;

          var start = block.getMinAddress();
          if (start.equals(function.getEntryPoint())) {
            entry = (long)myId << 32L | (long)i;
          }

          var end = block.getMaxAddress();
          var arch = makeArchitecture(start);

          var preds = new ArrayList<CodeBlockReference>();
          var predsIter = block.getSources(monitor);
          while (predsIter.hasNext()) {
            var pred = predsIter.next();
            if (blockMap.containsKey(pred.getSourceAddress()) && (pred.getFlowType().isJump() || pred.getFlowType().isFallthrough())) {
              preds.add(pred);
            }
          }
          var predCount = preds.size();
          var predsVector = new int[predCount];
          i = 0;
          for (var pred : preds) {
            var predId = (long)myId << 32L | (long)blockMap.get(pred.getSourceAddress());

            IntraRef.startIntraRef(message);

            IntraRef.addSource(message, predId);
            IntraRef.addTarget(message, blockId);
            IntraRef.addFunction(message, myId);

            predsVector[i] = IntraRef.endIntraRef(message);

            ++i;
          }

          var predsV = BasicBlock.createPredecessorsVector(message, predsVector);

          var succs = new ArrayList<CodeBlockReference>();
          var succsIter = block.getDestinations(monitor);
          while (succsIter.hasNext()) {
            var succ = succsIter.next();
            if (blockMap.containsKey(succ.getDestinationAddress()) && (succ.getFlowType().isJump() || succ.getFlowType().isFallthrough())) {
              succs.add(succ);
            }
          }
          var succCount = succs.size();
          var succsVector = new int[succCount];
          i = 0;
          for (var succ : succs) {
            var succId = (long)myId << 32L | (long)blockMap.get(succ.getDestinationAddress());
            IntraRef.startIntraRef(message);

            IntraRef.addSource(message, blockId);
            IntraRef.addTarget(message, succId);
            IntraRef.addFunction(message, myId);

            succsVector[i] = IntraRef.endIntraRef(message);

            ++i;
          }

          var succsV = BasicBlock.createSuccessorsVector(message, succsVector);

          BasicBlock.startBasicBlock(message);

          BasicBlock.addAddress(message, start.getUnsignedOffset());
          BasicBlock.addSize(message, end.subtract(start) + 1);
          BasicBlock.addPredecessors(message, predsV);
          BasicBlock.addSuccessors(message, succsV);
          BasicBlock.addArchitecture(message, arch);

          blocksVector[currBlockId] = BasicBlock.endBasicBlock(message);
        }

        var blocksV = fugue.schema.Function.createBlocksVector(message, blocksVector);
        var referencesV = fugue.schema.Function.createReferencesVector(message, referencesVector);
        var symbol = message.createString(function.getName());

        fugue.schema.Function.startFunction(message);

        fugue.schema.Function.addSymbol(message, symbol);
        fugue.schema.Function.addAddress(message, function.getEntryPoint().getUnsignedOffset());
        fugue.schema.Function.addEntry(message, entry);
        fugue.schema.Function.addBlocks(message, blocksV);
        fugue.schema.Function.addReferences(message, referencesV);

        functions[myId] = fugue.schema.Function.endFunction(message);
      }
      return Project.createFunctionsVector(message, functions);
    }

    public void exportTo(String outputFileName) throws CancelledException, IOException {
      makeArchitecture(null);

      var metadata = makeMetadata();
      var segments = makeSegments();
      var functions = makeFunctions();
      var architectures = makeArchitectures();

      Project.startProject(message);
      Project.addArchitectures(message, architectures);
      Project.addSegments(message, segments);
      Project.addFunctions(message, functions);
      Project.addMetadata(message, metadata);

      var project = Project.endProject(message);

      Project.finishProjectBuffer(message, project);

      var output = new java.io.FileOutputStream(outputFileName);
      var channel = output.getChannel();

      channel.write(message.dataBuffer());

      channel.close();
      output.close();
    }
}
