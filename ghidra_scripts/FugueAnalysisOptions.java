import ghidra.app.script.GhidraScript;
import java.util.Map;
import fugue.serialise.DatabaseBuilder;

public class FugueAnalysisOptions extends GhidraScript {
    private static final String EMBEDDED_MEDIA = "Embedded Media";
    private static final String CREATE_ADDRESS_TABLES = "Create Address Tables";

    @Override
    protected void run() throws Exception {
        Map<String, String> options = getCurrentAnalysisOptionsAndValues(currentProgram);
        if (options.containsKey(EMBEDDED_MEDIA)) {
            setAnalysisOption(currentProgram, EMBEDDED_MEDIA, "false");
        }
        if (options.containsKey(CREATE_ADDRESS_TABLES)) {
            setAnalysisOption(currentProgram, CREATE_ADDRESS_TABLES, "false");
        }
    }
}
