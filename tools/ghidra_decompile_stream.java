// Decompile file/stream layer used by RLC loader.
//@category EldoradoGate

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class ghidra_decompile_stream extends GhidraScript {
    @Override
    public void run() throws Exception {
        long[] funcs = {
            0x8c011710L, 0x8c011714L, 0x8c011718L, 0x8c011d28L, 0x8c011d8cL, 0x8c011dacL,
            0x8c011548L, 0x8c011d00L, 0x8c011c00L, 0x8c011b00L, 0x8c011a00L,
            0x8c012000L, 0x8c012100L, 0x8c012200L, 0x8c012300L
        };

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        File out = new File("/Users/acr/Develop/el-dorado-gate/output/ghidra_stream.txt");
        out.getParentFile().mkdirs();
        PrintWriter pw = new PrintWriter(new FileWriter(out));

        for (long entry : funcs) {
            Function fn = funcMgr.getFunctionAt(toAddr(entry));
            if (fn == null) continue;
            pw.println("=== " + fn.getName() + " @ " + fn.getEntryPoint() + " ===");
            DecompileResults res = decomp.decompileFunction(fn, 300, monitor);
            if (res.decompileCompleted()) pw.println(res.getDecompiledFunction().getC());
            pw.println();
        }
        pw.close();
        decomp.dispose();
        println("Wrote " + out.getAbsolutePath());
    }
}
