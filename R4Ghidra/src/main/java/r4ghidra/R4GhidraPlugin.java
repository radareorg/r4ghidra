/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package r4ghidra;

import java.io.IOException;

import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import docking.widgets.OkDialog;
import docking.widgets.OptionDialog;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;

/**
 * Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = CorePluginPackage.NAME, // https://github.com/NationalSecurityAgency/ghidra/discussions/5175
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "R4Ghidra - Radare2/Ghidra Integration",
	description = "R4Ghidra provides integration between Ghidra and Radare2."
)
//@formatter:on
public class R4GhidraPlugin extends ProgramPlugin {

	MyProvider provider;
	

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public R4GhidraPlugin(PluginTool tool) {
		super(tool);

		// Customize provider (or remove if a provider is not desired)
		String pluginName = getName();
		provider = new MyProvider(this, pluginName);

		// Customize help (or remove if help is not desired)
		String topicName = this.getClass().getPackage().getName();
		String anchorName = "HelpAnchor";
		provider.setHelpLocation(new HelpLocation(topicName, anchorName));
	}

	@Override
	public void init() {
		super.init();
		// Acquire services if necessary
	}
	
	@Override
	protected void programOpened(Program program) {
		R4GhidraState.api = new FlatProgramAPI(program);
		R4GhidraState.r2Seek = R4GhidraState.api.toAddr(0);
	}

	// If provider is desired, it is recommended to move it to its own file
	private static class MyProvider extends ComponentProvider {

		private JPanel panel;
		private DockingAction startAction;
		private DockingAction stopAction;

		public MyProvider(Plugin plugin, String owner) {
			super(plugin.getTool(), owner, owner);
			createActions();
		}

		// Customize actions
		private void createActions() {
			startAction = new DockingAction("R4Ghidra Start Action", getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					try {
						String strPort=OptionDialog.showInputSingleLineDialog(null, "R4Ghidra", "Server port:", "9191");
						Integer intPort=Integer.parseInt(strPort);
						R4GhidraServer.start(intPort.intValue());
						OkDialog.showInfo("R4Ghidra", "R4Ghidra server started on port "+strPort+".\n\nGet the best of both worlds!");
					}catch(IOException ioe) {
						OkDialog.showError("R4Ghidra Error", ioe.getMessage());
					}
					
				}
			};
			
			startAction.setMenuBarData(new MenuData(
		            new String[] {                      // Menu Path
		                ToolConstants.MENU_TOOLS,
		                "R4Ghidra",
		                "Start R4Ghidra server..."
		            },
		            null,                               // Icon
		            "r4ghidra",                      // Menu Group
		            MenuData.NO_MNEMONIC,               // Mnemonic
		            "1"                                 // Menu Subgroup
		        ));
			
			stopAction = new DockingAction("R4Ghidra Stop Action", getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					R4GhidraServer.stop();
					OkDialog.showInfo("R4Ghidra", "R4Ghidra server stopped.");
					
				}
			};
			
			stopAction.setMenuBarData(new MenuData(
		            new String[] {                      // Menu Path
		                ToolConstants.MENU_TOOLS,
		                "R4Ghidra",
		                "Stop R4Ghidra server"
		            },
		            null,                               // Icon
		            "r4ghidra",                      // Menu Group
		            MenuData.NO_MNEMONIC,               // Mnemonic
		            "1"                                 // Menu Subgroup
		        ));
			//action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
			startAction.setEnabled(true);
			startAction.markHelpUnnecessary();
			stopAction.setEnabled(true);
			stopAction.markHelpUnnecessary();
			dockingTool.addAction(startAction);
			dockingTool.addAction(stopAction);
		}

		@Override
		public JComponent getComponent() {
			return panel;
		}
	}
}
