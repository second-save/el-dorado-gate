// Decompile RLC loader/decompressor helpers.
//@category EldoradoGate

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class ghidra_decompile_loader extends GhidraScript {
    private long readPtr(long addr) throws Exception {
        return getInt(toAddr(addr)) & 0xffffffffL;
    }

    @Override
    public void run() throws Exception {
        long[] ptrSlots = {
            0x8c0192c8L, 0x8c0192ccL, 0x8c0192d0L, 0x8c0192dcL,
            0x8c0192e4L, 0x8c0192e8L, 0x8c0192c0L, 0x8c0193e4L, 0x8c0193beL
        };

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        File out = new File("/Users/acr/Develop/el-dorado-gate/output/ghidra_loader.txt");
        out.getParentFile().mkdirs();
        PrintWriter pw = new PrintWriter(new FileWriter(out));

        for (long slot : ptrSlots) {
            long target = readPtr(slot);
            pw.println("PTR @" + Long.toHexString(slot) + " -> " + Long.toHexString(target));
            Function fn = funcMgr.getFunctionAt(toAddr(target));
            if (fn == null) {
                createFunction(toAddr(target), "FUN_" + Long.toHexString(target));
                fn = funcMgr.getFunctionAt(toAddr(target));
            }
            if (fn == null) {
                pw.println("  (no function)\n");
                continue;
            }
            pw.println("=== " + fn.getName() + " @ " + fn.getEntryPoint() + " ===");
            DecompileResults res = decomp.decompileFunction(fn, 300, monitor);
            if (res.decompileCompleted()) pw.println(res.getDecompiledFunction().getC());
            else pw.println("FAILED");
            pw.println();
        }

        // one level of callees from decompress candidate
        long dec = readPtr(0x8c0192ccL);
        Function root = funcMgr.getFunctionAt(toAddr(dec));
        if (root != null) {
            for (Function callee : root.getCalledFunctions(monitor)) {
                pw.println("=== CALLEE " + callee.getName() + " @ " + callee.getEntryPoint() + " ===");
                DecompileResults res = decomp.decompileFunction(callee, 300, monitor);
                if (res.decompileCompleted()) pw.println(res.getDecompiledFunction().getC());
                pw.println();
            }
        }

        pw.close();
        decomp.dispose();
        println("Wrote " + out.getAbsolutePath());
    }
}
