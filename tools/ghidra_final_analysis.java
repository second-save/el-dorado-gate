// Final menu textbox analysis — loaders, hooks, file table.
//@category EldoradoGate

import java.io.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;

public class ghidra_final_analysis extends GhidraScript {
    @Override
    public void run() throws Exception {
        var out = new PrintWriter(new FileWriter(
            "/Users/acr/Develop/el-dorado-gate/output/ghidra_final_analysis.txt"));
        DecompInterface d = new DecompInterface();
        d.openProgram(currentProgram);
        Memory mem = currentProgram.getMemory();

        out.println("ELDORADO GATE — MENU TEXT BOX (final static analysis)");
        out.println("Load base: 0x8C010000 (1ST_READ.BIN)");
        out.println();

        out.println("=== CALL CHAIN (description text) ===");
        out.println("vtable[0] @0x8c0692ac -> FUN_8c06af5c  (per-frame, cursor slot 0)");
        out.println("  FUN_8c06b3a4 -> routing ushort grid @ *(*DAT_8c06b608+0x2c)");
        out.println("  PTR_8c06b058 -> FUN_8c014708(slot, segment_index)");
        out.println("    table@0x8c014848[seg] -> segment ptr; handler@0x8c01484c -> FUN_8c011650");
        out.println("    FUN_8c011098 alloc; FUN_8c01177c text VM; FUN_8c014854 bind");
        out.println("  PTR_8c06b06c -> FUN_8c014f0c (text box position / glyph blit loop)");
        out.println("  PTR_8c06b064 -> FUN_8c014cd0 (alternate open, flags @ DAT_8c06b060)");
        out.println();
        out.println("Initial RLC load: object vtable method @0x8c04e724");
        out.println("  -> FUN_8c014a2e(slot, path=*(obj+4), ...)");
        out.println("  PTR_8c014b1c -> FUN_8c011650 (fread)");
        out.println("  PTR_8c014b10 -> FUN_8c01177c (VM setup)");
        out.println();

        out.println("=== FILE TABLE @0x8c0b0828 (RLC/TPL paths) ===");
        Address tab = toAddr(0x8c0b0828L);
        for (int i = 0; i < 8; i++) {
            int pathPtr = mem.getInt(tab.add(i * 8));
            int meta = mem.getInt(tab.add(i * 8 + 4));
            StringBuilder sb = new StringBuilder();
            try {
                Address ps = toAddr(pathPtr & 0xffffffffL);
                for (int j = 0; j < 48; j++) {
                    byte b = mem.getByte(ps.add(j));
                    if (b == 0) break;
                    sb.append((char) (b & 0xff));
                }
            } catch (Exception e) {
                sb.append("?");
            }
            out.printf("  [%d] \"%s\" meta=%#x%n", i, sb, meta);
        }
        out.println();

        out.println("=== SEGMENT DISPATCH TABLE @0x8c014848 (runtime-filled) ===");
        for (int i = 0; i < 8; i++) {
            int v = mem.getInt(toAddr(0x8c014848L + i * 4));
            Function fn = getFunctionAt(toAddr(v & 0xffffffffL));
            out.printf("  [%d] %#x %s%n", i, v, fn != null ? fn.getName() : "(segment ptr after load)");
        }
        out.println();

        long[] extra = {0x8c04e724L, 0x8c01177cL, 0x8c0119a2L, 0x8c0119b6L, 0x8c01902cL};
        for (long a : extra) {
            Function fn = getFunctionAt(toAddr(a));
            if (fn == null) fn = getFunctionContaining(toAddr(a));
            out.println("=== " + (fn != null ? fn.getName() : "?") + " @" + Long.toHexString(a) + " ===");
            if (fn != null) {
                var r = d.decompileFunction(fn, 280, monitor);
                if (r.decompileCompleted()) out.println(r.getDecompiledFunction().getC());
            }
            out.println();
        }

        out.println("=== TRACE HOOK SITES (for 1ST_READ patch) ===");
        out.println("  FUN_8c011650 @0x8c011650  tag=0x0001650  fread path in r4");
        out.println("  FUN_8c014a2e @0x8c014a2e  tag=0x0014a2e  RLC load path in r5");
        out.println("  FUN_8c06af5c @0x8c06af5c  tag=0x000af5c  menu handler slot0");
        out.println("  FUN_8c014708 @0x8c014708  tag=0x0014708  segment attach r5=seg");
        out.println("  ring buffer RAM @0x8c2fe000 (not in ROM)");
        out.println("  code cave ROM @0x8c13d800");

        d.dispose();
        out.close();
    }
}
