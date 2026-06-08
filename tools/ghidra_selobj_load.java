
// @category EldoradoGate
import java.io.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
public class ghidra_selobj_load extends GhidraScript {
  public void run() throws Exception {
    var out = new PrintWriter(new FileWriter("/Users/acr/Develop/el-dorado-gate/output/ghidra_selobj_load.txt"));
    DecompInterface d = new DecompInterface(); d.openProgram(currentProgram);
    long[] t = {0x8c014a2eL, 0x8c014b10L, 0x8c011220L};
    for (long a : t) {
      var fn=getFunctionAt(toAddr(a));
      var r=d.decompileFunction(fn,180,monitor);
      out.println("=== "+fn.getName()+" ===");
      out.println(r.getDecompiledFunction().getC());
      out.println();
    }
    var refs=currentProgram.getReferenceManager().getReferencesTo(toAddr(0x8c014a2eL));
    out.println("XREFS FUN_8c014a2e:");
    while(refs.hasNext()){
      var r=refs.next();
      var fn=getFunctionContaining(r.getFromAddress());
      out.println(" "+r.getFromAddress()+" "+(fn==null?"?":fn.getName()+" @ "+fn.getEntryPoint()));
    }
    out.close();
  }
}
