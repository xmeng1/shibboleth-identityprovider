package edu.internet2.middleware.shibboleth.wayf;

/**
 * Runtime configuration bundle that is passed to a <code>WayfCacheFactory</code>.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */
public class WayfCacheOptions {
	
	private int expiration;
	private String domain;

	/**
	 * Returns the domain.
	 * @return String
	 */
	public String getDomain() {
		return domain;
	}


	/**
	 * Returns the expiration.
	 * @return int
	 */
	public int getExpiration() {
		return expiration;
	}


	/**
	 * Sets the domain.
	 * @param domain The domain to set
	 */
	public void setDomain(String domain) {
		this.domain = domain;
	}


	/**
	 * Sets the expiration.
	 * @param expiration The expiration to set
	 */
	public void setExpiration(int expiration) {
		this.expiration = expiration;
	}


}

