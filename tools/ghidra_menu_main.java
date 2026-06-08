
// @category EldoradoGate
import java.io.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
public class ghidra_menu_main extends GhidraScript {
  public void run() throws Exception {
    var out = new PrintWriter(new FileWriter("/Users/acr/Develop/el-dorado-gate/output/ghidra_menu_main.txt"));
    DecompInterface d = new DecompInterface(); d.openProgram(currentProgram);
    long[] t = {0x8c06af5cL,0x8c06b092L,0x8c06b658L,0x8c082722L,0x8c04e544L,0x8c04e5d0L};
    for (long a : t) {
      var fn = getFunctionAt(toAddr(a));
      if (fn==null) fn=getFunctionContaining(toAddr(a));
      if (fn==null) continue;
      out.println("=== "+fn.getName()+" @ "+fn.getEntryPoint()+" ===");
      var r=d.decompileFunction(fn,240,monitor);
      if (r.decompileCompleted()) out.println(r.getDecompiledFunction().getC());
      out.println();
    }
    out.close();
  }
}
