// Xrefs and decompile callers/callees of FUN_8c018f48.
//@category EldoradoGate

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class ghidra_xref_f48 extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address target = toAddr(0x8c018f48L);
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        File out = new File("/Users/acr/Develop/el-dorado-gate/output/ghidra_f48_xrefs.txt");
        PrintWriter pw = new PrintWriter(new FileWriter(out));

        pw.println("=== XREF to FUN_8c018f48 ===");
        Set<Function> related = new TreeSet<>((a,b)->a.getEntryPoint().compareTo(b.getEntryPoint()));
        Function root = funcMgr.getFunctionAt(target);
        related.add(root);
        ReferenceIterator it = refMgr.getReferencesTo(target);
        while (it.hasNext()) {
            Function fn = funcMgr.getFunctionContaining(it.next().getFromAddress());
            if (fn != null) related.add(fn);
        }
        for (Function callee : root.getCalledFunctions(monitor)) related.add(callee);
        for (Function fn : related) {
            pw.println(fn.getEntryPoint() + " " + fn.getName());
        }

        pw.println("\n=== Decompile ===");
        for (Function fn : related) {
            pw.println("--- " + fn.getName() + " @ " + fn.getEntryPoint() + " ---");
            DecompileResults res = decomp.decompileFunction(fn, 240, monitor);
            if (res.decompileCompleted()) pw.println(res.getDecompiledFunction().getC());
            pw.println();
        }
        pw.close();
        decomp.dispose();
        println("Wrote " + out.getAbsolutePath());
    }
}
