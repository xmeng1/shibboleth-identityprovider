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

/*
 * Contributed by SungGard SCT.
 */

package edu.internet2.middleware.shibboleth.aa.attrresolv;

import java.io.FileReader;
import java.io.IOException;
import java.io.LineNumberReader;
import java.util.HashMap;
import java.util.Map;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;

import org.apache.log4j.Logger;
import org.opensaml.SAMLException;

import edu.internet2.middleware.shibboleth.aa.AAAttribute;

/**
 * The AttributesFile reads attributes specified in a file as name-value pairs separated by an 'equals' sign (=)
 * Multiple values of an attribute may be specified using multiple pairs with the same attribute name. Multi-valued
 * attributes can be read as ordered or unordered.
 * 
 * @author <a href="mailto:vgoenka@sungardsct.com">Vishal Goenka </a>
 */

public class AttributesFile {

	private static Logger log = Logger.getLogger(AttributesFile.class.getName());
	private String datafile;
	private FileReader freader = null;
	private LineNumberReader linereader = null;

	public AttributesFile(String datafile) {

		this.datafile = datafile;
	}

	private void open() throws IOException {

		freader = new FileReader(datafile);
		linereader = new LineNumberReader(freader);
	}

	private void close() {

		try {
			if (freader != null) freader.close();
		} catch (Exception e) {
			log.warn("Unexpected error when closing file: " + datafile + " -- " + e.getMessage());
		}
	}

	private AVPair readAV() throws IOException {

		AVPair av = null;
		do {
			String line = linereader.readLine();
			if (line == null) break;

			line = line.trim();
			// Ignore comments and empty lines
			if ((line.length() == 0) || (line.charAt(0) == '#')) continue;

			int index = line.indexOf("=");
			if (index == -1)
				throw new IOException("'=' not specified in " + datafile + ":" + linereader.getLineNumber());
			String attrib = line.substring(0, index).trim();
			String value = line.substring(index + 1).trim();
			if ((attrib == null) || (attrib.length() == 0))
				throw new IOException("Empty attribute name in " + datafile + ":" + linereader.getLineNumber());

			if (value == null) value = "";

			av = new AVPair(attrib, value);
		} while (av == null);
		return av;
	}

	public synchronized Attributes readAttributes(boolean ordered) throws IOException {

		open();
		try {
			BasicAttributes attributes = new BasicAttributes();
			AVPair av = readAV();
			while (av != null) {
				BasicAttribute ba = (BasicAttribute) attributes.get(av.name);
				if (ba == null) {
					ba = new BasicAttribute(av.name, ordered);
					attributes.put(ba);
				}
				ba.add(av.value);
				av = readAV();
			}
			return attributes;
		} finally {
			close();
		}
	}

	public synchronized Map<String, AAAttribute> getResolverAttributes(boolean returnValues) throws IOException,
			SAMLException {

		open();
		try {
			Map<String, AAAttribute> attributes = new HashMap<String, AAAttribute>();
			AVPair av = readAV();
			while (av != null) {
				AAAttribute attr = (AAAttribute) attributes.get(av.name);
				if (attr == null) {
					// The intern() is to work-around the bug in AAAttribute.equals() where the name of the
					// attribute is compared
					// using "==" rather than "equals" ...
					attr = new AAAttribute(av.name.intern());
					attributes.put(attr.getName(), attr);
				}
				if (returnValues) {
					attr.addValue(av.value);
				}
				av = readAV();
			}
			return attributes;
		} finally {
			close();
		}
	}

	private class AVPair {

		String name;
		String value;

		public AVPair(String a, String v) {

			name = a;
			value = v;
		}
	}

}