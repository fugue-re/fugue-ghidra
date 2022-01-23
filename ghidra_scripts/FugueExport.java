//Fugue exporter
//@author Sam L. Thomas
//@category External

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.framework.Application;
import fugue.serialise.ArchBuilder;
import fugue.serialise.DatabaseBuilder;

import java.io.File;
import java.util.Optional;

public class FugueExport extends GhidraScript {
  private static final String FUGUE_OPT_OUTPUT = "FugueOutput:";
  private static final String FUGUE_OPT_OVERWRITE = "FugueForceOverwrite:";

  public void run() throws Exception {
    var args = getScriptArgs();

    String fileName = null;
    boolean inHeadless = args.length > 0;

    boolean overwrite = false;
    Optional<Address> rebase = Optional.empty();

    if (inHeadless) {
      for (var arg : args) {
        if (arg.startsWith(FUGUE_OPT_OUTPUT)) {
          fileName = arg.split(FUGUE_OPT_OUTPUT)[1];
        } else if (arg.startsWith(FUGUE_OPT_OVERWRITE)) {
          overwrite = Boolean.parseBoolean(arg.split(FUGUE_OPT_OVERWRITE)[1].toLowerCase());
        }
      }

      if (fileName == null) {
        System.exit(102); // import error
      }

      if (!overwrite && (new File(fileName)).exists()) {
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
        popup("Failed to export database.");
        printerr(_ex.toString());
      }
    }
    if (inHeadless)
      System.exit(100); // OK
  }
}
