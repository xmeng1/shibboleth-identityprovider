package edu.internet2.middleware.shibboleth.aa.arp.provider;

import java.util.Arrays;
import java.util.HashSet;

import edu.internet2.middleware.shibboleth.aa.arp.ArpAttribute;

/**
 *  Shibboleth implementation of an attribute to which ARPs may be applied.
 *
 * @author Walter Hoehn (wassa@columbia.edu)
 */
public class ShibArpAttribute implements ArpAttribute {

	private String name;
	private Object[] values;

	public ShibArpAttribute(String name, Object[] values) {
		this.name = name;
		this.values = values;
	}

	public ShibArpAttribute(String name) {
		this.name = name;
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.arp.ArpAttribute#getName()
	 */
	public String getName() {
		return name;
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.arp.ArpAttribute#getValues()
	 */
	public Object[] getValues() {
		if (values != null) {
			return values;
		} else {
			return new Object[0];
		}
	}

	/**
	 * @see edu.internet2.middleware.shibboleth.aa.arp.ArpAttribute#setValues(Object[])
	 */
	public void setValues(Object[] values) {
		this.values = values;
	}

	/**
	 * @see java.lang.Object#equals(Object)
	 */
	public boolean equals(Object object) {
		if (!(object instanceof ShibArpAttribute)) {
			return false;
		}
		return (new HashSet(Arrays.asList(values))).equals(
			new HashSet(Arrays.asList(((ShibArpAttribute) object).getValues())));
	}

	/**
	* @see java.lang.Object#hashCode()
	*/
	public int hashCode() {
		int code = 0;
		for (int i = 0; i < values.length; i++) {
			code += values[i].hashCode();
		}
		return name.hashCode() + code;
	}

}
