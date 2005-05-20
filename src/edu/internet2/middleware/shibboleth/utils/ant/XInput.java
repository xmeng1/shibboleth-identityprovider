/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.utils.ant;

import java.util.Vector;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Task;
import org.apache.tools.ant.input.InputRequest;
import org.apache.tools.ant.taskdefs.condition.Condition;

/**
 * Extended version of <code>org.apache.tools.ant.taskdefs.Input</code>
 * 
 * @author Will Norris (wnorris@memphis.edu)
 */
public class XInput extends Task implements Condition {

	private Boolean caseSensitive = new Boolean(true);
	private String validArgs = null;
	private String message = "";
	private String addproperty = null;
	private String defaultValue = null;
	private String type = "standard";
	private Vector options = new Vector();
	private String value = null;

	public void setCaseSensitive(Boolean b) {

		this.caseSensitive = b;
	}

	public Boolean getCaseSensitive() {

		return this.caseSensitive;
	}

	/**
	 * Defines valid input parameters as comma separated strings. If set, input task will reject any input not defined
	 * as accepted and requires the user to reenter it. Validargs are case sensitive. If you want 'a' and 'A' to be
	 * accepted you need to define both values as accepted arguments.
	 * 
	 * @param validargs
	 *            A comma separated String defining valid input args.
	 */
	public void setValidargs(String validArgs) {

		this.validArgs = validArgs;
	}

	/**
	 * Defines the name of a property to be created from input. Behaviour is according to property task which means that
	 * existing properties cannot be overridden.
	 * 
	 * @param addproperty
	 *            Name for the property to be created from input
	 */
	public void setAddproperty(String addproperty) {

		this.addproperty = addproperty;
	}

	/**
	 * Sets the Message which gets displayed to the user during the build run.
	 * 
	 * @param message
	 *            The message to be displayed.
	 */
	public void setMessage(String message) {

		this.message = message;
	}

	/**
	 * Defines the default value of the property to be created from input. Property value will be set to default if not
	 * input is received.
	 * 
	 * @param defaultvalue
	 *            Default value for the property if no input is received
	 */
	public void setDefaultvalue(String defaultValue) {

		this.defaultValue = defaultValue;
	}

	public void setType(String type) {

		this.type = type;
	}

	public void addConfiguredXoption(XInputOption option) {

		if (option.getCaseSensitive() == null) {
			option.setCaseSensitive(getCaseSensitive());
		}
		if (defaultValue != null && option.acceptsInput(defaultValue)) {
			option.setIsDefault(true);
		}

		options.add(option);
	}

	/**
	 * Set a multiline message.
	 * 
	 * @param msg
	 *            The message to be displayed.
	 */
	public void addText(String msg) {

		message += getProject().replaceProperties(msg);
	}

	/**
	 * No arg constructor.
	 */
	public XInput() {

	}

	/**
	 * Actual method executed by ant.
	 * 
	 * @throws BuildException
	 */
	public void execute() throws BuildException {

		if (addproperty != null && getProject().getProperty(addproperty) != null) {
			log("skipping " + getTaskName() + " as property " + addproperty + " has already been set.");
			return;
		}

		InputRequest request = null;

		if (type.equals("menu")) {
			getProject().setInputHandler(new XMenuInputHandler());
			request = new XMultipleChoiceInputRequest(message.trim(), options);
		} else if (type.equals("confirm")) {
			setCaseSensitive(new Boolean(false));
			addConfiguredXoption(new XInputOption("y", "y,yes,t,true", "y"));
			addConfiguredXoption(new XInputOption("n", "n,no,f,false", "n"));

			getProject().setInputHandler(new XInputHandler());
			request = new XMultipleChoiceInputRequest(message.trim(), options);
		} else {
			getProject().setInputHandler(new XInputHandler());
			request = new XMultipleChoiceInputRequest(message.trim(), options);
		}

		getProject().getInputHandler().handleInput(request);

		value = request.getInput();
		if ((value == null || value.trim().length() == 0) && defaultValue != null) {
			value = defaultValue;
		}
		if (addproperty != null && value != null) {
			getProject().setNewProperty(addproperty, value);
		}
	}

	public boolean eval() {

		if (!type.equals("confirm")) { throw new BuildException(); }

		execute();
		return value.equals("y");
	}

}
