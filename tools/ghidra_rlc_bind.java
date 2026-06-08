// RLC load hook and segment table patching.
//@category EldoradoGate

import java.io.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;

public class ghidra_rlc_bind extends GhidraScript {
    public void run() throws Exception {
        var out = new PrintWriter(new FileWriter("/Users/acr/Develop/el-dorado-gate/output/ghidra_rlc_bind.txt"));
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        long[] t = {
            0x8c014b10L, 0x8c011c3aL, 0x8c0119ecL, 0x8c011978L,
            0x8c069180L, 0x8c069240L, 0x8c07e850L, 0x8c07ea50L,
            0x8c06b1c6L, 0x8c06b388L,
        };
        for (long a : t) {
            Function fn = getFunctionContaining(toAddr(a));
            if (fn == null) fn = getFunctionAt(toAddr(a));
            out.println("=== " + (fn != null ? fn.getName() : "?") + " @" + Long.toHexString(a) + " ===");
            if (fn != null) {
                var r = d.decompileFunction(fn, 300, monitor);
                if (r.decompileCompleted()) out.println(r.getDecompiledFunction().getC());
            }
            out.println();
        }
        out.close();
        d.dispose();
    }
}
