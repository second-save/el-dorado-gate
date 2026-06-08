// Decompile text dispatcher vtable and file loaders.
//@category EldoradoGate

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.io.*;

public class ghidra_decompile_vtable extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address table = toAddr(0x8c019078L);
        File out = new File("/Users/acr/Develop/el-dorado-gate/output/ghidra_vtable.txt");
        out.getParentFile().mkdirs();
        PrintWriter pw = new PrintWriter(new FileWriter(out));
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        FunctionManager funcMgr = currentProgram.getFunctionManager();

        pw.println("=== Vtable @ 8c019078 ===");
        for (int i = 0; i < 8; i++) {
            int ptr = getInt(table.add(i * 4));
            Address fnAddr = toAddr(ptr & 0xffffffffL);
            Function fn = funcMgr.getFunctionAt(fnAddr);
            pw.println("[" + i + "] " + fnAddr + " " + (fn != null ? fn.getName() : "no_fn"));
            if (fn != null) {
                DecompileResults res = decomp.decompileFunction(fn, 180, monitor);
                if (res.decompileCompleted()) {
                    pw.println(res.getDecompiledFunction().getC());
                }
                pw.println();
            }
        }

        long[] extras = {
            0x8c01a1c0L, 0x8c01a1ccL, 0x8c01a1bcL, 0x8c01a1dcL,
            0x8c0193beL, 0x8c019420L, 0x8c019500L, 0x8c019600L,
            0x8c019700L, 0x8c019800L, 0x8c019900L, 0x8c019a00L
        };
        for (long entry : extras) {
            Function fn = funcMgr.getFunctionAt(toAddr(entry));
            if (fn == null) continue;
            pw.println("=== " + fn.getName() + " @ " + fn.getEntryPoint() + " ===");
            DecompileResults res = decomp.decompileFunction(fn, 180, monitor);
            if (res.decompileCompleted()) pw.println(res.getDecompiledFunction().getC());
            pw.println();
        }

        pw.close();
        decomp.dispose();
        println("Wrote " + out.getAbsolutePath());
    }
}
