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

/*
 * Contributed by SungGard SCT.
 */

package edu.internet2.middleware.shibboleth.aa.attrresolv;

import java.io.FileReader;
import java.io.IOException;
import java.io.LineNumberReader;

import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;

import org.apache.log4j.Logger;
import org.opensaml.SAMLException;

import edu.internet2.middleware.shibboleth.aa.AAAttribute;
import edu.internet2.middleware.shibboleth.aa.AAAttributeSet;

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

	public synchronized ResolverAttributeSet getResolverAttributes(boolean returnValues) throws IOException,
			SAMLException {

		open();
		try {
			AAAttributeSet attributes = new AAAttributeSet();
			AVPair av = readAV();
			while (av != null) {
				AAAttribute attr = (AAAttribute) attributes.getByName(av.name);
				if (attr == null) {
					// The intern() is to work-around the bug in AAAttribute.equals() where the name of the
					// attribute is compared
					// using "==" rather than "equals" ...
					attr = new AAAttribute(av.name.intern());
					attributes.add(attr);
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