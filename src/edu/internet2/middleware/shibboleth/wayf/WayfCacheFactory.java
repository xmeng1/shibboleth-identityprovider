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

	public static WayfCache getInstance() {

		if (WayfConfig.getCache().equals("NONE")) {
			return new NullWayfCache();
		} else if (WayfConfig.getCache().equals("SESSION")) {
			return new SessionWayfCache();
		} else if (WayfConfig.getCache().equals("COOKIES")) {
			return new CookieWayfCache();
		} else {
			log.warn(
				"Invalid Cache type specified: running with cache type NONE.");
			return new NullWayfCache();
		}
	}

}