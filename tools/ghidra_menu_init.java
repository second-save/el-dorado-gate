// Decompile menu init / object load chain.
//@category EldoradoGate

import java.io.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;

public class ghidra_menu_init extends GhidraScript {
    public void run() throws Exception {
        var out = new PrintWriter(new FileWriter("/Users/acr/Develop/el-dorado-gate/output/ghidra_menu_init.txt"));
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        Memory mem = currentProgram.getMemory();

        long[] targets = {
            0x8c04e6c0L, 0x8c04e700L, 0x8c04e740L, 0x8c04e780L, 0x8c04e7c0L, 0x8c04e800L,
            0x8c06b3deL, 0x8c06b414L, 0x8c06b478L, 0x8c06b4aeL, 0x8c06b608L,
            0x8c011220L, 0x8c014b10L, 0x8c011650L,
        };
        for (long a : targets) {
            Function fn = getFunctionContaining(toAddr(a));
            if (fn == null) fn = getFunctionAt(toAddr(a));
            out.println("=== " + (fn != null ? fn.getName() : "?") + " @" + Long.toHexString(a) + " ===");
            if (fn != null) {
                var r = d.decompileFunction(fn, 300, monitor);
                if (r.decompileCompleted()) out.println(r.getDecompiledFunction().getC());
            }
            out.println();
        }

        // Who references file table 0x8c0b0828
        out.println("=== XREFS file table 8c0b0828 ===");
        var refs = currentProgram.getReferenceManager().getReferencesTo(toAddr(0x8c0b0828L));
        int n = 0;
        while (refs.hasNext() && n < 60) {
            var r = refs.next();
            Function fn = getFunctionContaining(r.getFromAddress());
            out.println("  from " + r.getFromAddress() + " fn=" + (fn != null ? fn.getName() : "?"));
            n++;
        }
        out.println();

        // Dump menu-related static structs
        out.println("=== STATIC STRUCTS ===");
        for (long base : new long[]{0x8c181960L, 0x8c1969ecL, 0x8c0af4e0L, 0x8c0abf20L}) {
            out.printf("bytes @%x: ", base);
            for (int i = 0; i < 32; i++) {
                try { out.printf("%02x", mem.getByte(toAddr(base + i)) & 0xff); }
                catch (Exception e) { out.print("??"); break; }
            }
            out.println();
        }

        // Resolve PTR_8c01484c / table confusion
        out.println("=== SEGMENT DISPATCH TABLE (LE) ===");
        for (int i = 0; i < 8; i++) {
            int v = mem.getInt(toAddr(0x8c014848L + i * 4));
            Function fn = getFunctionAt(toAddr(v & 0xffffffffL));
            out.printf("  seg_cmd[%d] 0x%08x -> %s%n", i, v, fn != null ? fn.getName() : "data");
        }

        out.close();
        d.dispose();
    }
}
