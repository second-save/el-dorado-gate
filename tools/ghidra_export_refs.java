// Ghidra headless script: export functions referencing RLC path tables.
//@category EldoradoGate

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;

public class ghidra_export_refs extends GhidraScript {
    @Override
    public void run() throws Exception {
        long[] targets = {
            0x8c0ad10cL, // f00_00.rlc table
            0x8c0ac450L, // pl00.rlc
            0x8c0ac6b0L, // selobj.rlc
            0x8c0b0828L  // filename pointer table
        };

        File out = new File("/Users/acr/Develop/el-dorado-gate/output/ghidra_rlc_refs.txt");
        out.getParentFile().mkdirs();
        PrintWriter pw = new PrintWriter(new FileWriter(out));
        ReferenceManager refMgr = currentProgram.getReferenceManager();
        FunctionManager funcMgr = currentProgram.getFunctionManager();
        AddressFactory af = currentProgram.getAddressFactory();
        AddressSpace space = af.getDefaultAddressSpace();

        for (long t : targets) {
            Address addr = space.getAddress(t);
            pw.println("=== XREF target " + addr + " ===");
            ReferenceIterator it = refMgr.getReferencesTo(addr);
            while (it.hasNext()) {
                Reference ref = it.next();
                Address from = ref.getFromAddress();
                Function fn = funcMgr.getFunctionContaining(from);
                String fnName = fn != null ? fn.getName() + " @ " + fn.getEntryPoint() : "no_func";
                pw.println("  from " + from + " type=" + ref.getReferenceType() + " fn=" + fnName);
            }
        }

        // Also dump functions whose names contain likely keywords from decompiler scan
        pw.println("=== Functions with many 0x80 immediate uses (heuristic) ===");
        for (Function fn : funcMgr.getFunctions(true)) {
            String body = fn.getBody().toString();
            if (body.length() > 2000) {
                pw.println(fn.getName() + " @ " + fn.getEntryPoint() + " size=" + body.length());
            }
        }
        pw.close();
        println("Wrote " + out.getAbsolutePath());
    }
}
