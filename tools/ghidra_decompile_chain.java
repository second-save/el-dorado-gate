// Decompile candidate text decode chain.
//@category EldoradoGate

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class ghidra_decompile_chain extends GhidraScript {
    @Override
    public void run() throws Exception {
        long[] funcs = {
            0x8c018f48L, 0x8c018fcaL, 0x8c019000L, 0x8c01902cL, 0x8c01927aL,
            0x8c0191c0L, 0x8c019200L, 0x8c019300L, 0x8c019400L, 0x8c019500L,
            0x8c01a0c4L, 0x8c011548L
        };

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        File out = new File("/Users/acr/Develop/el-dorado-gate/output/ghidra_text_chain.txt");
        out.getParentFile().mkdirs();
        PrintWriter pw = new PrintWriter(new FileWriter(out));

        for (long entry : funcs) {
            Function fn = funcMgr.getFunctionAt(toAddr(entry));
            if (fn == null) continue;
            pw.println("=== " + fn.getName() + " @ " + fn.getEntryPoint() + " ===");
            DecompileResults res = decomp.decompileFunction(fn, 180, monitor);
            if (res.decompileCompleted()) {
                pw.println(res.getDecompiledFunction().getC());
            } else {
                pw.println("FAILED");
            }
            pw.println();
        }
        pw.close();
        decomp.dispose();
        println("Wrote " + out.getAbsolutePath());
    }
}
