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
import java.util.ArrayList;
import java.util.List;

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
import r4ghidra.repl.R2CommandHandler;
import r4ghidra.repl.handlers.*;
import r4ghidra.repl.R2REPLImpl;

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
	R4CommandShellProvider shellProvider;
	private List<R2CommandHandler> commandHandlers;
	private boolean shellProviderAdded = false;
	

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
		
		// Initialize command handlers list
		commandHandlers = new ArrayList<>();
	}

	@Override
	public void init() {
		super.init();
		
		// Initialize command handlers
		initCommandHandlers();
	}
	
	/**
	 * Initialize all command handlers for R4Ghidra
	 */
	private void initCommandHandlers() {
		// Register all command handlers
		commandHandlers.add(new R2SeekCommandHandler());
		commandHandlers.add(new R2PrintCommandHandler());
		commandHandlers.add(new R2BlocksizeCommandHandler());
		commandHandlers.add(new R2DecompileCommandHandler());
		commandHandlers.add(new R2EnvCommandHandler());
		commandHandlers.add(new R2EvalCommandHandler());
		commandHandlers.add(new R2ShellCommandHandler());
		
		// Note: R2HelpCommandHandler will be created in the CommandShellProvider
		// because it needs a reference to the command registry
		
		// Add more handlers as needed
	}
	
	/**
	 * Get the registered command handlers
	 * 
	 * @return List of command handlers
	 */
	public List<R2CommandHandler> getCommandHandlers() {
		return commandHandlers;
	}
	
	@Override
	protected void programOpened(Program program) {
		R4GhidraState.api = new FlatProgramAPI(program);
		R4GhidraState.r2Seek = R4GhidraState.api.toAddr(0);
		
		// Create the command shell when a program is opened
		if (shellProvider == null) {
			shellProvider = new R4CommandShellProvider(this, "R4Ghidra Command Shell");
		}
	}
	
	@Override
	protected void programClosed(Program program) {
		// Dispose the command shell when program is closed
		if (shellProvider != null) {
			shellProvider.close();
			shellProvider = null;
		}
	}

	// If provider is desired, it is recommended to move it to its own file
	private static class MyProvider extends ComponentProvider {

		private JPanel panel;
		private DockingAction startAction;
		private DockingAction stopAction;
		private DockingAction commandShellAction;

		public MyProvider(Plugin plugin, String owner) {
			super(plugin.getTool(), owner, owner);
			createActions();
		}
		
		/**
		 * Shows the R4Ghidra command shell
		 */
		private void showCommandShell() {
			// Get the plugin directly from the dockingTool
			PluginTool pluginTool = (PluginTool)dockingTool;
			R4GhidraPlugin plugin = pluginTool.getService(R4GhidraPlugin.class);
			
			if (plugin != null) {
				// Create the shell provider if it doesn't exist
				if (plugin.shellProvider == null) {
					plugin.shellProvider = new R4CommandShellProvider(plugin, "R4Ghidra Command Shell");
				}
				
				// Add the component to the tool if not already added
				if (!plugin.shellProviderAdded) {
					pluginTool.addComponentProvider(plugin.shellProvider, true);
					plugin.shellProviderAdded = true;
				}
				
				pluginTool.showComponentProvider(plugin.shellProvider, true);
			}
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
			// Create the command shell action
			commandShellAction = new DockingAction("R4Ghidra Command Shell Action", getName()) {
				@Override
				public void actionPerformed(ActionContext context) {
					showCommandShell();
				}
			};
			
			commandShellAction.setMenuBarData(new MenuData(
		            new String[] {                      // Menu Path
		                ToolConstants.MENU_TOOLS,
		                "R4Ghidra",
		                "Open Command Shell"
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
			commandShellAction.setEnabled(true);
			commandShellAction.markHelpUnnecessary();
			dockingTool.addAction(startAction);
			dockingTool.addAction(stopAction);
			dockingTool.addAction(commandShellAction);
		}

		@Override
		public JComponent getComponent() {
			return panel;
		}
	}
}
