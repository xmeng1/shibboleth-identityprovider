package edu.internet2.middleware.shibboleth.wayf;

import org.apache.log4j.Logger;

/**
 * Factory for creating instances of <code>WayfCache</code> based on 
 * the state of the <code>WayfConfig</code>.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */
public class WayfCacheFactory {

	private static Logger log =
		Logger.getLogger(WayfCacheFactory.class.getName());

	public static WayfCache getInstance(String cacheType, WayfCacheOptions options) {

		if (cacheType.equals("NONE")) {
			return new NullWayfCache();
		} else if (cacheType.equals("SESSION")) {
			return new SessionWayfCache(options.getExpiration());
		} else if (cacheType.equals("COOKIES")) {
			return new CookieWayfCache(options.getExpiration(), options.getDomain());
		} else {
			log.warn(
				"Invalid Cache type specified: running with cache type NONE.");
			return new NullWayfCache();
		}
	}
	
	public static WayfCache getInstance(String cacheType) {
		
		return getInstance(cacheType, new WayfCacheOptions());
		}

}