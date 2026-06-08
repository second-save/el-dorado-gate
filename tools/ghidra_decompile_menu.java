// Decompile menu / object RLC VM functions — writes output/ghidra_menu.txt
//@category EldoradoGate

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;

public class ghidra_decompile_menu extends GhidraScript {

    private PrintWriter out;

    private void decompileAt(long addr) throws Exception {
        Address a = toAddr(addr);
        Function fn = getFunctionAt(a);
        if (fn == null) {
            fn = getFunctionContaining(a);
        }
        out.println("=== @" + a + " ===");
        if (fn == null) {
            out.println("NO FUNCTION");
            out.println();
            return;
        }
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        DecompileResults res = decomp.decompileFunction(fn, 180, monitor);
        out.println("NAME: " + fn.getName());
        if (res.decompileCompleted()) {
            out.println(res.getDecompiledFunction().getC());
        } else {
            out.println("DECOMPILE FAILED: " + res.getErrorMessage());
        }
        out.println();
        decomp.dispose();
    }

    @Override
    public void run() throws Exception {
        File target = new File("/Users/acr/Develop/el-dorado-gate/output/ghidra_menu.txt");
        out = new PrintWriter(new FileWriter(target));

        long[] targets = {
            0x8c014468L, 0x8c014532L, 0x8c014608L, 0x8c014670L,
            0x8c0146a2L, 0x8c0146d6L, 0x8c014708L, 0x8c014818L,
            0x8c014a2eL, 0x8c014b28L, 0x8c014c1aL, 0x8c014c60L,
            0x8c014cd0L, 0x8c014e10L, 0x8c014e34L, 0x8c014e6eL,
            0x8c014eacL, 0x8c014f0cL, 0x8c014fe0L, 0x8c0150d0L,
            0x8c015120L, 0x8c0193e4L, 0x8c0193beL,
            0x8c0af800L, 0x8c0af900L, 0x8c0afa00L, 0x8c0afb00L,
            0x8c0afc00L, 0x8c0afd00L, 0x8c0afe00L, 0x8c0aff00L,
            0x8c0b0000L, 0x8c0b0100L, 0x8c0b0200L, 0x8c0b0300L,
        };

        out.println("MENU / OBJECT VM");
        for (long addr : targets) {
            decompileAt(addr);
        }

        out.println("=== XREFS selobj.rlc @ 8c0ac6b0 ===");
        Address selobj = toAddr(0x8c0ac6b0L);
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(selobj);
        while (refs.hasNext()) {
            Reference r = refs.next();
            Function from = getFunctionContaining(r.getFromAddress());
            String fn = from != null ? from.getName() + " @ " + from.getEntryPoint() : "no_func";
            out.println("  from " + r.getFromAddress() + " type=" + r.getReferenceType() + " fn=" + fn);
        }

        out.println("=== XREFS DAT_8c0150b8 ===");
        Address slotBase = toAddr(0x8c0150b8L);
        refs = currentProgram.getReferenceManager().getReferencesTo(slotBase);
        int n = 0;
        while (refs.hasNext() && n < 50) {
            Reference r = refs.next();
            Function from = getFunctionContaining(r.getFromAddress());
            String fn = from != null ? from.getName() + " @ " + from.getEntryPoint() : "no_func";
            out.println("  from " + r.getFromAddress() + " fn=" + fn);
            n++;
        }

        out.println("=== XREFS 8c0b0828 (file table) ===");
        Address filetab = toAddr(0x8c0b0828L);
        refs = currentProgram.getReferenceManager().getReferencesTo(filetab);
        while (refs.hasNext()) {
            Reference r = refs.next();
            Function from = getFunctionContaining(r.getFromAddress());
            String fn = from != null ? from.getName() + " @ " + from.getEntryPoint() : "no_func";
            out.println("  from " + r.getFromAddress() + " fn=" + fn);
        }

        out.println("=== XREFS FUN_8c011650 ===");
        Address fread = toAddr(0x8c011650L);
        refs = currentProgram.getReferenceManager().getReferencesTo(fread);
        n = 0;
        while (refs.hasNext() && n < 40) {
            Reference r = refs.next();
            Function from = getFunctionContaining(r.getFromAddress());
            String fn = from != null ? from.getName() + " @ " + from.getEntryPoint() : "no_func";
            out.println("  from " + r.getFromAddress() + " fn=" + fn);
            n++;
        }

        out.println("=== FUNCTIONS 0x8c0af000-0x8c0b1000 ===");
        Address start = toAddr(0x8c0af000L);
        Address end = toAddr(0x8c0b1000L);
        FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(start, true);
        while (fit.hasNext()) {
            Function f = fit.next();
            if (f.getEntryPoint().compareTo(end) > 0) break;
            out.println(f.getName() + " @ " + f.getEntryPoint());
        }

        out.close();
        println("Wrote " + target.getAbsolutePath());
    }
}
