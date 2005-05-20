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

import org.apache.tools.ant.input.DefaultInputHandler;
import org.apache.tools.ant.input.InputRequest;

/**
 * Input handler to display of a multiple choice menu
 * 
 * @author Will Norris (wnorris@memphis.edu)
 */
public class XMenuInputHandler extends DefaultInputHandler {

	/**
	 * 
	 */
	public XMenuInputHandler() {

		super();
	}

	protected String getPrompt(InputRequest request) {

		String prompt = request.getPrompt();
		if (request instanceof XMultipleChoiceInputRequest) {
			StringBuffer sb = new StringBuffer("\n" + prompt);
			sb.append("\n\n");
			Iterator i = ((XMultipleChoiceInputRequest) request).getOptions().iterator();
			boolean first = true;
			int count = 0;
			while (i.hasNext()) {
				if (!first) {
					sb.append("\n");
				}
				count++;
				XInputOption o = (XInputOption) i.next();
				sb.append("    " + count + ") " + o.displayName());
				if (o.isDefault()) {
					sb.append(" (default)");
				}
				first = false;
			}
			prompt = sb.toString();
		}
		return prompt;
	}

}
