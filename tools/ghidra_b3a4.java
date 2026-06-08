
// @category EldoradoGate
import java.io.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
public class ghidra_b3a4 extends GhidraScript {
  public void run() throws Exception {
    var out = new PrintWriter(new FileWriter("/Users/acr/Develop/el-dorado-gate/output/ghidra_b3a4.txt"));
    DecompInterface d = new DecompInterface(); d.openProgram(currentProgram);
    for (long a : new long[]{0x8c06b3a4L,0x8c014a2eL}) {
      var fn=getFunctionAt(toAddr(a));
      var r=d.decompileFunction(fn,240,monitor);
      out.println(r.getDecompiledFunction().getC());
    }
    out.close();
  }
}
