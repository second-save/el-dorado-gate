// Trace menu text box: callers, pointer tables, RLC paths.
//@category EldoradoGate

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

public class ghidra_trace_textbox extends GhidraScript {

    private PrintWriter out;
    private DecompInterface decomp;

    private void decompileFn(long addr, String label) throws Exception {
        Address a = toAddr(addr);
        Function fn = getFunctionAt(a);
        if (fn == null) fn = getFunctionContaining(a);
        out.println("=== " + label + " @" + a + " ===");
        if (fn == null) {
            out.println("NO FUNCTION");
            out.println();
            return;
        }
        DecompileResults res = decomp.decompileFunction(fn, 240, monitor);
        out.println("NAME: " + fn.getName());
        if (res.decompileCompleted()) {
            out.println(res.getDecompiledFunction().getC());
        } else {
            out.println("FAILED: " + res.getErrorMessage());
        }
        out.println();
    }

    private void dumpPtrTable(long baseAddr, int count, String label) throws Exception {
        Memory mem = currentProgram.getMemory();
        Address base = toAddr(baseAddr);
        out.println("=== PTR TABLE " + label + " @" + base + " (count=" + count + ") ===");
        for (int i = 0; i < count; i++) {
            Address slot = base.add(i * 4);
            int ptr;
            try {
                ptr = mem.getInt(slot);
            } catch (Exception e) {
                out.printf("  [%2d] unreadable slot%n", i);
                continue;
            }
            Address target = toAddr(ptr & 0xffffffffL);
            String note = "";
            try {
                byte b0 = mem.getByte(target);
                byte b1 = mem.getByte(target.add(1));
                byte b2 = mem.getByte(target.add(2));
                byte b3 = mem.getByte(target.add(3));
                note = String.format(" head=%02x%02x%02x%02x", b0 & 0xff, b1 & 0xff, b2 & 0xff, b3 & 0xff);
            } catch (Exception e) {
                note = " unreadable";
            }
            out.printf("  [%2d] -> 0x%08x%s%n", i, ptr, note);
        }
        out.println();
    }

    private void dumpString(long addr) throws Exception {
        Address a = toAddr(addr);
        StringBuilder sb = new StringBuilder();
        Memory mem = currentProgram.getMemory();
        for (int i = 0; i < 64; i++) {
            byte b = mem.getByte(a.add(i));
            if (b == 0) break;
            sb.append((char)(b & 0xff));
        }
        out.println("  string@" + a + " = \"" + sb + "\"");
    }

    private void xrefsTo(long addr, String label, int max) throws Exception {
        out.println("=== XREFS " + label + " @" + Long.toHexString(addr) + " ===");
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(toAddr(addr));
        int n = 0;
        while (refs.hasNext() && n < max) {
            Reference r = refs.next();
            Function from = getFunctionContaining(r.getFromAddress());
            String fn = from != null ? from.getName() + " @ " + from.getEntryPoint() : "no_func";
            out.println("  from " + r.getFromAddress() + " type=" + r.getReferenceType() + " fn=" + fn);
            n++;
        }
        out.println();
    }

    private void dumpDataPtr(long addr, String label) throws Exception {
        Memory mem = currentProgram.getMemory();
        try {
            int val = mem.getInt(toAddr(addr));
            out.printf("  %s (DAT_%x) = 0x%08x%n", label, addr, val);
        } catch (Exception e) {
            out.printf("  %s (DAT_%x) = <uninitialized>%n", label, addr);
        }
    }

    @Override
    public void run() throws Exception {
        File target = new File("/Users/acr/Develop/el-dorado-gate/output/ghidra_textbox_trace.txt");
        out = new PrintWriter(new FileWriter(target));
        decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        out.println("MENU TEXT BOX TRACE");
        out.println();

        // Core render / attach chain
        long[] core = {
            0x8c01484cL, // segment prep (called from 8c014708)
            0x8c011650L, // fread
            0x8c0146a2L,
            0x8c014708L,
            0x8c014cd0L,
            0x8c014a2eL,
            0x8c014b28L,
            0x8c06af5cL,
            0x8c06b092L,
            0x8c06b3a4L,
            0x8c06b608L, // menu object loader?
            0x8c06b63cL,
            0x8c04e544L,
            0x8c04eac4L,
            0x8c04ebf6L,
            0x8c015120L, // per-frame slot dispatcher
            0x8c014fe0L, // text VM step?
            0x8c014f0cL,
            0x8c0190f6L,
        };
        for (long a : core) {
            decompileFn(a, "fn");
        }

        // Pointer tables for segment bytecode (slot 0 path in FUN_8c014708)
        dumpPtrTable(0x8c014848L, 24, "PTR_PTR_8c014848");
        dumpPtrTable(0x8c014c44L, 24, "PTR_PTR_8c014c44");
        dumpPtrTable(0x8c014d64L, 16, "PTR_PTR_8c014d64");

        // Menu vtable / function pointers
        out.println("=== MENU FUNCTION POINTERS ===");
        long[] menuPtrs = {
            0x8c06b050L, 0x8c06b058L, 0x8c06b05cL, 0x8c06b064L,
            0x8c06b06cL, 0x8c06b148L, 0x8c06b154L, 0x8c06b15cL, 0x8c06b164L,
        };
        Memory mem = currentProgram.getMemory();
        for (long p : menuPtrs) {
            int val = mem.getInt(toAddr(p));
            Function fn = getFunctionAt(toAddr(val & 0xffffffffL));
            String name = fn != null ? fn.getName() : "?";
            out.printf("  PTR_%x -> 0x%08x (%s)%n", p, val, name);
        }
        out.println();

        // DAT pointers for menu state
        out.println("=== MENU STATE DAT ===");
        dumpDataPtr(0x8c06b048L, "DAT_8c06b048");
        dumpDataPtr(0x8c06b04cL, "DAT_8c06b04c");
        dumpDataPtr(0x8c06b060L, "DAT_8c06b060");
        dumpDataPtr(0x8c06b608L, "DAT_8c06b608");
        try {
            int objPtr = mem.getInt(toAddr(0x8c06b608L));
            out.printf("  *DAT_8c06b608 (runtime, may be BSS) = 0x%08x%n", objPtr);
            if (objPtr != 0) {
                int segTable = mem.getInt(toAddr(objPtr + 0x2c));
                out.printf("  *DAT_8c06b608+0x2c (routing table) = 0x%08x%n", segTable);
            }
        } catch (Exception e) {
            out.println("  DAT_8c06b608 runtime dereference unavailable in static image");
        }
        out.println();

        // RLC path strings
        out.println("=== RLC PATH STRINGS ===");
        dumpString(0x8c0ac6b0L);
        dumpString(0x8c0ac6c4L);
        out.println();

        // Xrefs
        xrefsTo(0x8c014a2eL, "FUN_8c014a2e", 40);
        xrefsTo(0x8c014708L, "FUN_8c014708", 40);
        xrefsTo(0x8c014cd0L, "FUN_8c014cd0", 40);
        xrefsTo(0x8c0ac6b0L, "selobj.rlc", 40);
        xrefsTo(0x8c0ac6c4L, "en_obj00.rlc", 40);
        xrefsTo(0x8c06b608L, "DAT_8c06b608", 40);
        xrefsTo(0x8c014848L, "PTR_PTR_8c014848", 40);

        // File table at 8c0b0828
        out.println("=== FILE TABLE @ 8c0b0828 (first 20 entries) ===");
        Address tab = toAddr(0x8c0b0828L);
        for (int i = 0; i < 20; i++) {
            int pathPtr = mem.getInt(tab.add(i * 8));
            int meta = mem.getInt(tab.add(i * 8 + 4));
            StringBuilder sb = new StringBuilder();
            try {
                Address ps = toAddr(pathPtr & 0xffffffffL);
                for (int j = 0; j < 48; j++) {
                    byte b = mem.getByte(ps.add(j));
                    if (b == 0) break;
                    sb.append((char)(b & 0xff));
                }
            } catch (Exception e) {
                sb.append("?");
            }
            out.printf("  [%2d] path=0x%08x \"%s\" meta=0x%08x%n", i, pathPtr, sb, meta);
        }
        out.println();

        decomp.dispose();
        out.close();
        println("Wrote " + target.getAbsolutePath());
    }
}
