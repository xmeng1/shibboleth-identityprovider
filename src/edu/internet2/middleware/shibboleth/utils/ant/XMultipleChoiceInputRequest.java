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

import java.util.Iterator;
import java.util.Vector;

import org.apache.tools.ant.input.InputRequest;

/**
 * @author Will Norris (wnorris@memphis.edu)
 */
public class XMultipleChoiceInputRequest extends InputRequest {

	private Vector options = null;

	public XMultipleChoiceInputRequest(String prompt, Vector options) {

		super(prompt);
		if (options == null) { throw new IllegalArgumentException("choices must not be null"); }
		this.options = options;
	}

	public Vector getOptions() {

		return options;
	}

	/**
	 * @return The possible values.
	 */
	public Vector getChoices() {

		Vector choices = new Vector();

		Iterator i = options.iterator();
		while (i.hasNext()) {
			XInputOption o = (XInputOption) i.next();
			choices.add(o.displayName());
		}

		return choices;
	}

	/**
	 * @return true if the input is one of the allowed values.
	 */
	public boolean isInputValid() {

		// first check if any XInputOptions will accept the input
		Iterator i = options.iterator();
		while (i.hasNext()) {
			XInputOption o = (XInputOption) i.next();
			if (o.acceptsInput(getInput())) {
				setInput(o.getValue());
				return true;
			}
		}

		// next check if they tried to input a menu item number
		try {
			Integer input = new Integer(getInput());
			if (input.intValue() > 0 && input.intValue() <= options.size()) {
				XInputOption o = (XInputOption) options.get(input.intValue() - 1);
				setInput(o.getValue());
				return true;
			}
		} catch (NumberFormatException nfe) {
			// input was not a number
		}

		return false;
	}

}
