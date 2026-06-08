// Decompile core RLC text decode functions.
//@category EldoradoGate

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class ghidra_decompile_textcore extends GhidraScript {
    @Override
    public void run() throws Exception {
        long[] funcs = {
            0x8c0bf87cL, 0x8c0bf884L, 0x8c0bf88cL, 0x8c0bf8b0L,
            0x8c01907cL, 0x8c0190f6L, 0x8c0191beL,
            0x8c019000L, 0x8c01902cL, 0x8c018f48L, 0x8c018fcaL
        };

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        File out = new File("/Users/acr/Develop/el-dorado-gate/output/ghidra_textcore.txt");
        out.getParentFile().mkdirs();
        PrintWriter pw = new PrintWriter(new FileWriter(out));

        for (long entry : funcs) {
            Function fn = funcMgr.getFunctionAt(toAddr(entry));
            if (fn == null) {
                createFunction(toAddr(entry), "FUN_" + Long.toHexString(entry));
                fn = funcMgr.getFunctionAt(toAddr(entry));
            }
            if (fn == null) {
                pw.println("=== missing " + Long.toHexString(entry) + " ===\n");
                continue;
            }
            pw.println("=== " + fn.getName() + " @ " + fn.getEntryPoint() + " ===");
            DecompileResults res = decomp.decompileFunction(fn, 240, monitor);
            if (res.decompileCompleted()) {
                pw.println(res.getDecompiledFunction().getC());
            } else {
                pw.println("FAILED: " + res.getErrorMessage());
            }
            pw.println();
        }
        pw.close();
        decomp.dispose();
        println("Wrote " + out.getAbsolutePath());
    }
}
