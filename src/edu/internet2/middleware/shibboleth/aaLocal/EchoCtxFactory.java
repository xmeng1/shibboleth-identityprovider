import java.util.Hashtable;
import javax.naming.*;
import javax.naming.spi.*;


public class EchoCtxFactory implements InitialContextFactory{

    public Context getInitialContext(Hashtable env)
	throws NamingException{
	return new EchoDirContext(env);
    }

}
