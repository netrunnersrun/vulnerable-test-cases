import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

public class CommandInjectionVulnerable {

    // Matches: java-runtime-exec
    public void vulnerableRuntimeExec(String userInput) throws Exception {
        Runtime.getRuntime().exec(userInput);
    }

    // Matches: java-processbuilder-command
    public void vulnerableProcessBuilder(String cmd) throws Exception {
        new ProcessBuilder("sh", "-c", cmd).start();
    }

    // Matches: java-script-engine-eval
    public Object vulnerableScriptEngine(String userInput) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        return engine.eval(userInput);
    }

    // Safe: allowlisted commands
    public void safeCommand(String filename) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("ls", "-la", filename);
        pb.start();
    }
}
