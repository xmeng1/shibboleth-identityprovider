/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials
 * provided with the distribution, if any, must include the following acknowledgment: "This product includes software
 * developed by the University Corporation for Advanced Internet Development <http://www.ucaid.edu>Internet2 Project.
 * Alternately, this acknowledegement may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear. Neither the name of Shibboleth nor the names of its contributors, nor Internet2, nor
 * the University Corporation for Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote
 * products derived from this software without specific prior written permission. For written permission, please contact
 * shibboleth@shibboleth.org Products derived from this software may not be called Shibboleth, Internet2, UCAID, or the
 * University Corporation for Advanced Internet Development, nor may Shibboleth appear in their name, without prior
 * written permission of the University Corporation for Advanced Internet Development. THIS SOFTWARE IS PROVIDED BY THE
 * COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE
 * DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. IN NO
 * EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC.
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
