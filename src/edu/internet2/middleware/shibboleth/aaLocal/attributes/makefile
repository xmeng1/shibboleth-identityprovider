RTLIB=/afs/andrew/acs/asg/shibboleth/runtime/java/v2/lib/
CMULIB=/afs/andrew/acs/asg/shibboleth/cmu/beta/lib/

CP=.:${RTLIB}/xercesImpl.jar:${RTLIB}/xmlParserAPIs.jar:${RTLIB}/shibboleth.jar:${RTLIB}/opensaml.jar:~blk/src/shib/mm.mysql-2.0.8-bin.jar:/usr/www/tomcat/lib/servlet.jar:${CMULIB}/aa.jar:${CMULIB}/jndi.jar:${CMULIB}/ldap.jar

DESTDIR=/afs/andrew/acs/asg/shibboleth/cmu/beta/lib

all:	*.java
	javac -classpath ${CP} *.java
	jar cvf attributes.jar *.class
	cp attributes.jar ${DESTDIR}

