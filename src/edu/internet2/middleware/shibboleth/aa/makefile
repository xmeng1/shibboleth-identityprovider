CP=.:/afs/andrew/acs/asg/shibboleth/runtime/java/v2/lib/xercesImpl.jar:/afs/andrew/acs/asg/shibboleth/runtime/java/v2/lib/xmlParserAPIs.jar:/afs/andrew/acs/asg/shibboleth/runtime/java/v2/lib/shibboleth.jar:/afs/andrew/acs/asg/shibboleth/runtime/java/v2/lib/opensaml.jar:/usr/www/tomcat/lib/servlet.jar:/usr/java/jre/lib/rt.jar:../../lib/jndi.jar

INSTDIR=/afs/andrew/acs/asg/shibboleth/cmu/beta/lib

all:
	javac -g -classpath ${CP} *.java

docs:
	javadoc -classpath ${CP} -d /usr/www/tree/aa *java

jar:	all
	mkdir aa;
	cp *.class aa;
	jar -cvf aa.jar aa;
	rm -fr aa

install:  jar
	cp aa.jar ${INSTDIR}

