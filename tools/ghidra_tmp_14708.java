
// @category EldoradoGate
import java.io.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
public class ghidra_tmp_14708 extends GhidraScript {
  public void run() throws Exception {
    var out = new PrintWriter(new FileWriter("/Users/acr/Develop/el-dorado-gate/output/ghidra_14708.txt"));
    long[] t = {0x8c0146a2L,0x8c014670L,0x8c0146d6L,0x8c014708L,0x8c014760L,0x8c014cd0L};
    DecompInterface d = new DecompInterface(); d.openProgram(currentProgram);
    for (long a : t) {
      var fn = getFunctionAt(toAddr(a));
      if (fn==null) fn=getFunctionContaining(toAddr(a));
      out.println("=== "+a+" "+(fn==null?"?":fn.getName())+" ===");
      if (fn!=null) {
        var r=d.decompileFunction(fn,180,monitor);
        if (r.decompileCompleted()) out.println(r.getDecompiledFunction().getC());
      }
      out.println();
    }
    // xrefs to selobj string and b0828
    var refs=currentProgram.getReferenceManager().getReferencesTo(toAddr(0x8c0ac6b0L));
    out.println("XREFS selobj:");
    while(refs.hasNext()){var r=refs.next();out.println(" "+r.getFromAddress());}
    refs=currentProgram.getReferenceManager().getReferencesTo(toAddr(0x8c0b0828L));
    out.println("XREFS filetab:");
    while(refs.hasNext()){var r=refs.next();out.println(" "+r.getFromAddress());}
    out.close();
  }
}
