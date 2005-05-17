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
