
// @category EldoradoGate
import java.io.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
public class ghidra_menu_caller extends GhidraScript {
  public void run() throws Exception {
    var out = new PrintWriter(new FileWriter("/Users/acr/Develop/el-dorado-gate/output/ghidra_menu_caller.txt"));
    DecompInterface d = new DecompInterface(); d.openProgram(currentProgram);
    long[] t = {0x8c04e700L,0x8c04e780L,0x8c04e800L,0x8c04e600L,0x8c04e900L,0x8c04ea00L,0x8c04eb00L,0x8c04ec00L};
    for (long a : t) {
      var fn = getFunctionContaining(toAddr(a));
      if (fn==null) continue;
      out.println("=== "+fn.getName()+" @ "+fn.getEntryPoint()+" ===");
      var r=d.decompileFunction(fn,180,monitor);
      if (r.decompileCompleted()) out.println(r.getDecompiledFunction().getC());
      out.println();
    }
    // also decompile whatever calls FUN_8c014cd0
    var refs=currentProgram.getReferenceManager().getReferencesTo(toAddr(0x8c014cd0L));
    out.println("XREFS FUN_8c014cd0:");
    while(refs.hasNext()){
      var r=refs.next();
      var fn=getFunctionContaining(r.getFromAddress());
      out.println(" from "+r.getFromAddress()+" "+(fn==null?"?":fn.getName()+" @ "+fn.getEntryPoint()));
    }
    out.close();
  }
}
