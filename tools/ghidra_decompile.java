// Decompile Eldorado Gate functions of interest.
//@category EldoradoGate

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.io.*;
import java.util.*;

public class ghidra_decompile extends GhidraScript {
    private void decompileFunction(DecompInterface decomp, FunctionManager funcMgr, PrintWriter pw, long entry) throws Exception {
        Address addr = toAddr(entry);
        Function fn = funcMgr.getFunctionAt(addr);
        if (fn == null) {
            pw.println("=== Missing function at " + addr + " ===\n");
            return;
        }
        pw.println("=== " + fn.getName() + " @ " + fn.getEntryPoint() + " ===");
        DecompileResults res = decomp.decompileFunction(fn, 120, monitor);
        if (res.decompileCompleted()) {
            pw.println(res.getDecompiledFunction().getC());
        } else {
            pw.println("FAILED: " + res.getErrorMessage());
        }
        pw.println();
    }

    @Override
    public void run() throws Exception {
        long[] funcs = {
            0x8c01a0c4L,
            0x8c01a122L,
            0x8c01a0c4L
        };

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        FunctionManager funcMgr = currentProgram.getFunctionManager();

        File out = new File("/Users/acr/Develop/el-dorado-gate/output/ghidra_decompile.txt");
        out.getParentFile().mkdirs();
        PrintWriter pw = new PrintWriter(new FileWriter(out));

        Set<Long> seen = new HashSet<>();
        for (long entry : funcs) {
            if (!seen.add(entry)) continue;
            decompileFunction(decomp, funcMgr, pw, entry);
        }

        // Decompile first-level callees from FUN_8c01a0c4
        Function root = funcMgr.getFunctionAt(toAddr(0x8c01a0c4L));
        if (root != null) {
            Set<Function> callees = root.getCalledFunctions(monitor);
            for (Function callee : callees) {
                long entry = callee.getEntryPoint().getOffset();
                if (!seen.add(entry)) continue;
                pw.println("=== CALLEE " + callee.getName() + " @ " + callee.getEntryPoint() + " ===");
                DecompileResults res = decomp.decompileFunction(callee, 120, monitor);
                if (res.decompileCompleted()) {
                    pw.println(res.getDecompiledFunction().getC());
                }
                pw.println();
            }
        }

        pw.close();
        decomp.dispose();
        println("Wrote " + out.getAbsolutePath());
    }
}
