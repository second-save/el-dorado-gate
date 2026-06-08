// Decompile filesystem/read chain (FUN_8c011650 subtree).
//@category EldoradoGate

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class ghidra_decompile_fs extends GhidraScript {
    private long readPtr(long addr) throws Exception {
        return getInt(toAddr(addr)) & 0xffffffffL;
    }

    @Override
    public void run() throws Exception {
        long[] seeds = {
            readPtr(0x8c011710L), readPtr(0x8c011714L), readPtr(0x8c011718L),
            readPtr(0x8c0115dcL), readPtr(0x8c0115e0L), readPtr(0x8c0115e4L),
            0x8c012c10L
        };

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        File out = new File("/Users/acr/Develop/el-dorado-gate/output/ghidra_fs.txt");
        PrintWriter pw = new PrintWriter(new FileWriter(out));

        for (long entry : seeds) {
            Function fn = funcMgr.getFunctionAt(toAddr(entry));
            if (fn == null) continue;
            pw.println("=== " + fn.getName() + " @ " + fn.getEntryPoint() + " ===");
            DecompileResults res = decomp.decompileFunction(fn, 360, monitor);
            if (res.decompileCompleted()) pw.println(res.getDecompiledFunction().getC());
            pw.println();
            for (Function callee : fn.getCalledFunctions(monitor)) {
                if (callee.getBody().getNumAddresses() > 2500) continue;
                pw.println("--- callee " + callee.getName() + " @ " + callee.getEntryPoint() + " ---");
                DecompileResults r2 = decomp.decompileFunction(callee, 240, monitor);
                if (r2.decompileCompleted()) pw.println(r2.getDecompiledFunction().getC());
                pw.println();
            }
        }
        pw.close();
        decomp.dispose();
        println("Wrote " + out.getAbsolutePath());
    }
}
