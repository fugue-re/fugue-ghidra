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
      var auxiliary = Metadata.createAuxiliaryVector(message, new byte[0]);

      return Metadata.createMetadata(
          message,
          inputFormat,
          inputPath,
          inputMd5,
          inputSha256,
          inputSize,
          exporter,
          auxiliary
      );
    }

    private int makeArchitectures() {
      var architectures = new int[arches.size()];
      arches.forEach((arch, i) -> {
        var processor = message.createString(arch.processor);
        var variant = message.createString(arch.variant);
        var auxiliary = Architecture.createAuxiliaryVector(message, new byte[0]);

        architectures[i] = Architecture.createArchitecture(
            message,
            processor,
            arch.endian,
            arch.bits,
            variant,
            auxiliary
        );
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
        var auxiliary = Segment.createAuxiliaryVector(message, new byte[0]);

        segmentVector[i] = Segment.createSegment(
            message,
            segmentName,
            segment.getStart().getUnsignedOffset(),
            segment.getSize(),
            space.getPointerSize(),
            space.getAddressableUnitSize(),
            space.getPointerSize() * 8, // should be the same as bits?
            (segment.isExecute() ? ldef.getInstructionEndian() : ldef.getEndian()).isBigEndian(),
            segment.isExecute(),
            !segment.isExecute(),
            segment.getName().equals(MemoryBlock.EXTERNAL_BLOCK_NAME),
            segment.isRead(),
            segment.isWrite(),
            segment.isExecute(),
            segmentBytes,
            auxiliary
        );
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

          var auxiliary = InterRef.createAuxiliaryVector(message, new byte[0]);

          referencesVector[i] = InterRef.createInterRef(
              message,
              caller.getFromAddress().getUnsignedOffset(),
              id,
              myId,
              true,
              auxiliary
          );

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
            var auxiliary = IntraRef.createAuxiliaryVector(message, new byte[0]);

            predsVector[i] = IntraRef.createIntraRef(
                message,
                predId,
                blockId,
                myId,
                auxiliary
            );

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
          var succsVector = new int[succCount];
          i = 0;
          for (var succ : succs) {
            var succId = (long)myId << 32L | (long)blockMap.get(succ.getDestinationAddress());
            var auxiliary = IntraRef.createAuxiliaryVector(message, new byte[0]);

            succsVector[i] = IntraRef.createIntraRef(
                message,
                blockId,
                succId,
                myId,
                auxiliary
            );

            ++i;
          }

          var predsV = BasicBlock.createPredecessorsVector(message, predsVector);
          var succsV = BasicBlock.createSuccessorsVector(message, succsVector);

          var auxiliary = BasicBlock.createAuxiliaryVector(message, new byte[0]);

          blocksVector[i] = BasicBlock.createBasicBlock(
              message,
              start.getUnsignedOffset(),
              end.subtract(start) + 1,
              arch,
              predsV,
              succsV,
              auxiliary
          );
        }

        var symbol = message.createString(function.getName());
        var blocksV = fugue.schema.Function.createBlocksVector(message, blocksVector);
        var references = fugue.schema.Function.createReferencesVector(message, referencesVector);
        var auxiliary = fugue.schema.Function.createAuxiliaryVector(message, new byte[0]);

        functions[myId] = fugue.schema.Function.createFunction(
            message,
            symbol,
            function.getEntryPoint().getUnsignedOffset(),
            entry,
            blocksV,
            references,
            auxiliary
        );
      }
      return Project.createFunctionsVector(message, functions);
    }

    public void exportTo(String outputFileName) throws CancelledException, IOException {
      makeArchitecture(null);

      var metadata = makeMetadata();
      var segments = makeSegments();
      var functions = makeFunctions();
      var architectures = makeArchitectures();
      var auxiliary = Project.createAuxiliaryVector(message, new byte[0]);

      var project = Project.createProject(
          message,
          architectures,
          segments,
          functions,
          metadata,
          auxiliary
      );

      Project.finishProjectBuffer(message, project);

      var output = new java.io.FileOutputStream(outputFileName);
      var channel = output.getChannel();

      channel.write(message.dataBuffer());

      channel.close();
      output.close();
    }
}
