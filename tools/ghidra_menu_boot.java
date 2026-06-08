// Menu boot setup and object file binding.
//@category EldoradoGate

import java.io.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class ghidra_menu_boot extends GhidraScript {
    public void run() throws Exception {
        var out = new PrintWriter(new FileWriter("/Users/acr/Develop/el-dorado-gate/output/ghidra_menu_boot.txt"));
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);

        long[] targets = {
            0x8c026c68L, 0x8c025c94L, 0x8c04e86cL, 0x8c04e870L,
            0x8c06b200L, 0x8c06b300L, 0x8c06b478L, 0x8c06b4aeL,
            0x8c06b500L, 0x8c06b548L, 0x8c06b5c0L,
            0x8c011098L, 0x8c01177cL,
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

        long[] ptrs = {0x8c06b610L,0x8c06b614L,0x8c06b618L,0x8c06b674L,0x8c06b678L};
        out.println("=== MENU PTR SLOTS ===");
        for (long p : ptrs) {
            int v = getInt(toAddr(p));
            Function fn = getFunctionAt(toAddr(v & 0xffffffffL));
            out.printf("  %x -> %08x %s%n", p, v, fn != null ? fn.getName() : "?");
        }
        out.println();

        out.println("=== XREFS FUN_8c06af5c ===");
        var refs = currentProgram.getReferenceManager().getReferencesTo(toAddr(0x8c06af5cL));
        while (refs.hasNext()) {
            var r = refs.next();
            Function fn = getFunctionContaining(r.getFromAddress());
            out.println("  from " + r.getFromAddress() + " " + (fn != null ? fn.getName() : "?"));
        }
        out.println();

        out.println("=== XREFS FUN_8c04e680 ===");
        refs = currentProgram.getReferenceManager().getReferencesTo(toAddr(0x8c04e680L));
        while (refs.hasNext()) {
            var r = refs.next();
            Function fn = getFunctionContaining(r.getFromAddress());
            out.println("  from " + r.getFromAddress() + " " + (fn != null ? fn.getName() : "?"));
        }

        out.close();
        d.dispose();
    }
}
