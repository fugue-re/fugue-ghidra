//Niobe NDB GTIRB exporter
//@author Sam L. Thomas
//@category External

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.framework.Application;
import niobe.flirt.Flirt;
import niobe.serialise.ArchBuilder;
import niobe.serialise.DatabaseBuilder;

import java.io.File;
import java.util.Optional;

public class NiobeNDBExport extends GhidraScript {
  private static final String NIOBE_OPT_OUTPUT = "NiobeOutput:";
  private static final String NIOBE_OPT_REBASE = "NiobeRebase:";
  private static final String NIOBE_OPT_OVERWRITE = "NiobeForceOverwrite:";
  private static final String NIOBE_OPT_APPLYSIGS = "NiobeApplySigs:";

  public void run() throws Exception {
    var args = getScriptArgs();

    String fileName = null;
    boolean inHeadless = args.length > 0;

    boolean overwriteNDB = false;
    Optional<Address> rebase = Optional.empty();

    if (inHeadless) {
      for (var arg : args) {
        if (arg.startsWith(NIOBE_OPT_OUTPUT)) {
          fileName = arg.split(NIOBE_OPT_OUTPUT)[1];
        } else if (arg.startsWith(NIOBE_OPT_OVERWRITE)) {
          overwriteNDB = Boolean.parseBoolean(arg.split(NIOBE_OPT_OVERWRITE)[1].toLowerCase());
        } else if (arg.startsWith(NIOBE_OPT_REBASE)) {
          var rebaseStr = arg.split(NIOBE_OPT_REBASE)[1];
          try {
            if (rebaseStr.startsWith("+")) {
              currentProgram.setImageBase(toAddr(0), false); // Normalise
              var value = Long.parseUnsignedLong(rebaseStr.split("\\+0x")[1], 16);
              rebase = Optional.of(currentProgram.getImageBase().add(value));
            } else if (rebaseStr.startsWith("-")) {
              currentProgram.setImageBase(toAddr(0), false); // Normalise
              var value = Long.parseUnsignedLong(rebaseStr.split("-0x")[1], 16);
              rebase = Optional.of(currentProgram.getImageBase().subtract(value));
            } else {
              currentProgram.setImageBase(toAddr(0), false); // Normalise
              var value = Long.parseUnsignedLong(rebaseStr.split("0x")[1], 16);
              rebase = Optional.of(toAddr(value));
            }
          } catch (Exception _ex) {
            _ex.printStackTrace();
            System.exit(104); // rebase failure
          }
        } else if (arg.startsWith(NIOBE_OPT_APPLYSIGS)) {
          var sigFiles = arg.split(NIOBE_OPT_APPLYSIGS)[1].split(":");
          var extBasePath = Application.getApplicationLayout().getApplicationInstallationDir().getAbsolutePath();
          var extSigDir = extBasePath + File.separator + "Ghidra" + File.separator + "Extensions" + File.separator
              + "niobe-ndb-ghidra" + File.separator + "extra" + File.separator + "sigs";

          var arch = new ArchBuilder(currentProgram);
          var flirt = new Flirt(extSigDir, arch, currentProgram);
          var endianSuffix = arch.endian ? "eb" : "el";
          for (var sig : sigFiles) {
            try {
              flirt.loadAndApplySignature(sig, this);
            } catch (Exception _ex) {
              try {
                flirt.loadAndApplySignature(sig + endianSuffix, this);
              } catch (Exception _ex2) {
              }
            }
          }
        }
      }

      if (rebase.isPresent()) {
        currentProgram.setImageBase(rebase.get(), false);
      }

      if (fileName == null) {
        System.exit(102); // import error
      }

      if (!overwriteNDB && (new File(fileName)).exists()) {
        System.exit(100); // already exists
      }
    } else {
      fileName = askFile("Output file", "Save").toString();
    }

    var builder = new DatabaseBuilder(currentProgram, monitor);

    try {
      builder.exportTo(fileName);
    } catch (Exception _ex) {
      if (inHeadless) {
        System.exit(101); // input/output
      } else {
        popup("Failed to export NDB database -- consult the console for a stack-trace.");
        printerr(_ex.toString());
      }
    }
    if (inHeadless)
      System.exit(100); // OK
  }
}
