package r4ghidra;

import docking.widgets.EventTrigger;
import ghidra.app.util.viewer.listingpanel.ProgramLocationListener;
import ghidra.program.util.ProgramLocation;
import r4ghidra.repl.R2Context;

public class R4ProgramLocationListener implements ProgramLocationListener {
  R2Context context;

  public R4ProgramLocationListener(R2Context context) {
    this.context = context;
  }

  @Override
  public void programLocationChanged(ProgramLocation programLocation, EventTrigger eventTrigger) {
    context.setCurrentAddress(programLocation.getAddress());
  }
}
