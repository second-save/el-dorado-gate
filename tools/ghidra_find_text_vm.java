// Find functions referencing the text VM context and 0x80.
//@category EldoradoGate

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class ghidra_find_text_vm extends GhidraScript {
    @Override
    public void run() throws Exception {
        long[] watch = { 0x8c019074L, 0x8c0192c4L, 0x8c019450L };
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        File out = new File("/Users/acr/Develop/el-dorado-gate/output/ghidra_text_vm.txt");
        out.getParentFile().mkdirs();
        PrintWriter pw = new PrintWriter(new FileWriter(out));
        Set<Function> targets = new TreeSet<>((a,b) -> a.getEntryPoint().compareTo(b.getEntryPoint()));

        for (long addr : watch) {
            Address a = toAddr(addr);
            pw.println("=== refs to " + a + " ===");
            ReferenceIterator it = refMgr.getReferencesTo(a);
            while (it.hasNext()) {
                Reference ref = it.next();
                Function fn = funcMgr.getFunctionContaining(ref.getFromAddress());
                pw.println("  " + ref.getFromAddress() + " " + (fn != null ? fn.getEntryPoint() + " " + fn.getName() : "no_fn"));
                if (fn != null) targets.add(fn);
            }
        }

        pw.println("\n=== Decompile unique functions (" + targets.size() + ") ===");
        for (Function fn : targets) {
            if (fn.getBody().getNumAddresses() > 4000) continue;
            pw.println("--- " + fn.getName() + " @ " + fn.getEntryPoint() + " ---");
            DecompileResults res = decomp.decompileFunction(fn, 180, monitor);
            if (res.decompileCompleted()) {
                String c = res.getDecompiledFunction().getC();
                if (c.contains("0x80") || c.contains("128") || c.contains("param_1 + 0x10") || c.contains("+ 2)")) {
                    pw.println(c);
                } else {
                    pw.println("(skipped - no keyword)");
                }
            }
            pw.println();
        }

        pw.close();
        decomp.dispose();
        println("Wrote " + out.getAbsolutePath());
    }
}
