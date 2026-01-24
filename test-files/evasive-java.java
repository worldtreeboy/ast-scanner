package com.example.evasive;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import java.util.Base64;

/**
 * Test file for Java ScriptEngine evasion detection
 * These patterns should be detected as code injection via ScriptEngine
 */
public class ScriptEngineEvasion {

    // Pattern 1: Base64 decoded user input executed via ScriptEngine
    public void executeBase64Script(String userInput) throws Exception {
        // User provides Base64-encoded malicious JavaScript
        byte[] decoded = Base64.getDecoder().decode(userInput);  // DETECT: Base64 decode flows to ScriptEngine
        String script = new String(decoded);

        ScriptEngine engine = new ScriptEngineManager().getEngineByName("javascript");
        engine.eval(script);  // DETECT: ScriptEngine.eval with Base64-decoded payload
    }

    // Pattern 2: Direct tainted input to ScriptEngine
    public void directExecution(String userScript) throws Exception {
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("js");

        // DETECT: ScriptEngine.eval with tainted data
        engine.eval(userScript);
    }

    // Pattern 3: Inline chain pattern
    public void inlineChain(String code) throws Exception {
        // DETECT: Inline ScriptEngine chain with tainted data
        new ScriptEngineManager().getEngineByName("javascript").eval(code);
    }

    // Pattern 4: Base64 decode with separate string conversion
    public void separateConversion(String encodedScript) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(encodedScript);
        String decodedScript = new String(bytes);  // Tracking propagation

        ScriptEngine engine = new ScriptEngineManager().getEngineByName("nashorn");
        // DETECT: ScriptEngine.eval with decoded variable
        engine.eval(decodedScript);
    }

    // Pattern 5: Groovy script engine (also dangerous)
    public void groovyExecution(String userCode) throws Exception {
        ScriptEngine groovy = new ScriptEngineManager().getEngineByName("groovy");
        // DETECT: ScriptEngine.eval with tainted data
        groovy.eval(userCode);
    }

    // Pattern 6: Python/Jython script engine
    public void pythonExecution(String pythonCode) throws Exception {
        ScriptEngine python = new ScriptEngineManager().getEngineByName("python");
        // DETECT: ScriptEngine.eval with tainted data
        python.eval(pythonCode);
    }

    // Pattern 7: Obfuscated via intermediate variable
    public void obfuscatedExecution(String input) throws Exception {
        String script = input;  // Taint propagation
        ScriptEngineManager sem = new ScriptEngineManager();
        ScriptEngine se = sem.getEngineByName("js");
        // DETECT: ScriptEngine.eval with tainted data
        Object result = se.eval(script);
    }

    // Safe pattern - hardcoded script (should flag with lower severity)
    public void safeExecution() throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("javascript");
        // Lower severity - hardcoded script
        engine.eval("var x = 1 + 2;");
    }
}
