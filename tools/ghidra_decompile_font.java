// Decompile functions near pl00.rlc pointer table and font-related calls.
//@category EldoradoGate

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;

public class ghidra_decompile_font extends GhidraScript {
    @Override
    public void run() throws Exception {
        long[] funcs = {
            0x8c0af900L, 0x8c0af800L, 0x8c0afa00L,
            0x8c019420L, 0x8c0193e4L, 0x8c019500L,
            0x8c014e6eL, 0x8c015000L, 0x8c016000L
        };

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        File out = new File("/Users/acr/Develop/el-dorado-gate/output/ghidra_font.txt");
        PrintWriter pw = new PrintWriter(new FileWriter(out));

        // xrefs to pl00.rlc @ 8c0ac450
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        pw.println("=== XREF 8c0ac450 ===");
        for (Reference ref : refMgr.getReferencesTo(toAddr(0x8c0ac450L))) {
            Function fn = funcMgr.getFunctionContaining(ref.getFromAddress());
            pw.println(ref.getFromAddress() + " " + (fn != null ? fn.getEntryPoint() + " " + fn.getName() : ""));
            if (fn != null) funcs = append(funcs, fn.getEntryPoint().getOffset());
        }

        for (long entry : funcs) {
            Function fn = funcMgr.getFunctionAt(toAddr(entry));
            if (fn == null) fn = funcMgr.getFunctionContaining(toAddr(entry));
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

    private long[] append(long[] arr, long v) {
        for (long x : arr) if (x == v) return arr;
        long[] n = new long[arr.length + 1];
        System.arraycopy(arr, 0, n, 0, arr.length);
        n[arr.length] = v;
        return n;
    }
}
