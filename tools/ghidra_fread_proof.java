// Static proof: selobj.rlc path -> fread callers (no emulator needed).
//@category EldoradoGate

import java.io.*;
import java.util.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;

public class ghidra_fread_proof extends GhidraScript {
    @Override
    public void run() throws Exception {
        File outFile = new File("/Users/acr/Develop/el-dorado-gate/output/ghidra_fread_proof.txt");
        PrintWriter out = new PrintWriter(new FileWriter(outFile));
        Memory mem = currentProgram.getMemory();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        out.println("FREAD / SELOBJ STATIC PROOF (Ghidra, no emulator)");
        out.println("Target: FUN_8c011650 @0x8c011650 (segment fread)");
        out.println();

        Address fread = toAddr(0x8c011650L);
        Function freadFn = funcMgr.getFunctionAt(fread);
        out.println("fread function: " + (freadFn != null ? freadFn.getName() : "MISSING"));
        out.println();

        out.println("=== STRINGS -> XREFS (file paths) ===");
        String[] needles = {"selobj.rlc", "SELOBJ", "en_obj00", "COMN"};
        Set<Long> stringAddrs = new TreeSet<>();
        for (String needle : needles) {
            Address found = findBytes(currentProgram.getMinAddress(), needle.getBytes(), null);
            while (found != null) {
                long va = found.getOffset();
                stringAddrs.add(va);
                out.printf("  \"%s\" @%#x%n", needle, va);
                found = findBytes(found.add(1), needle.getBytes(), null);
            }
        }
        out.println();

        out.println("=== CALLERS OF fread (direct xrefs to entry) ===");
        List<String> callerLines = new ArrayList<>();
        for (Reference ref : refMgr.getReferencesTo(fread)) {
            if (!ref.getReferenceType().isCall()) continue;
            Function caller = funcMgr.getFunctionContaining(ref.getFromAddress());
            if (caller != null) {
                callerLines.add(String.format("  %s @%s", caller.getName(), caller.getEntryPoint()));
            }
        }
        Collections.sort(callerLines);
        for (String line : callerLines) out.println(line);
        out.println();

        long[] keyFuncs = {
            0x8c014a2eL, 0x8c014708L, 0x8c014b28L, 0x8c04e724L,
            0x8c011220L, 0x8c011d28L, 0x8c06b608L, 0x8c06af5cL
        };
        out.println("=== KEY LOADERS (decompile) ===");
        for (long entry : keyFuncs) {
            Function fn = funcMgr.getFunctionAt(toAddr(entry));
            if (fn == null) fn = funcMgr.getFunctionContaining(toAddr(entry));
            out.println("--- " + (fn != null ? fn.getName() : "?") + " @" + Long.toHexString(entry) + " ---");
            if (fn != null) {
                DecompileResults r = decomp.decompileFunction(fn, 240, monitor);
                if (r.decompileCompleted()) {
                    String c = r.getDecompiledFunction().getC();
                    if (c.contains("8c011650") || c.contains("PTR_FUN_8c014b1c") || c.contains("selobj")) {
                        out.println("[CONTAINS fread/selobj reference]");
                    }
                    out.println(c);
                }
            }
            out.println();
        }

        out.println("=== FILE TABLE @0x8c0b0828 ===");
        Address tab = toAddr(0x8c0b0828L);
        for (int i = 0; i < 4; i++) {
            int pathPtr = mem.getInt(tab.add(i * 8));
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
            out.printf("  [%d] \"%s\" ptr=%#x%n", i, sb, pathPtr);
        }
        out.println();

        out.println("=== PTR_8c014b1c (fread ptr used by RLC loader) ===");
        int freadPtr = mem.getInt(toAddr(0x8c014b1cL));
        out.printf("  value = %#x (expect 0x8c011650)%n", freadPtr);
        out.println();

        out.println("=== CONCLUSION (static) ===");
        out.println("  - Table[0] points to \\\\COMN\\\\selobj.rlc in ROM.");
        out.println("  - FUN_8c014a2e / FUN_8c014708 chain uses PTR_8c014b1c -> fread.");
        out.println("  - Menu description uses segment attach (FUN_8c014708), not raw disk string.");
        out.println("  - Nuclear GDI (SELOBJ=0xFF) is the runtime disk test; trace hooks confirm RAM path.");
        out.println("  - Without debugger: use Flycast Save State (F5) + tools/flycast_state_scan.py");

        decomp.dispose();
        out.close();
        println("Wrote " + outFile);
    }
}
