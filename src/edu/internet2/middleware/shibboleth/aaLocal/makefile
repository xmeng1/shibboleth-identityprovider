RTLIB=/afs/andrew/acs/asg/shibboleth/runtime/java/v2/lib/
CMULIB=/afs/andrew/acs/asg/shibboleth/cmu/beta/lib/

CP=.:${RTLIB}/xercesImpl.jar:${RTLIB}/xmlParserAPIs.jar:${RTLIB}/shibboleth.jar:${RTLIB}/opensaml.jar:~blk/src/shib/mm.mysql-2.0.8-bin.jar:/usr/www/tomcat/lib/servlet.jar:${CMULIB}/aa.jar:${CMULIB}/jndi.jar:${CMULIB}/ldap.jar


INSTDIR=/afs/andrew/acs/asg/shibboleth/cmu/beta/lib


all: aaLocal.jar attributes

aaLocal.jar: *.class
	jar -cvf aaLocal.jar *class
	

attributes: attributes/*.java
	cd attributes;make $*


*.class:  *.java
	javac -g -classpath ${CP} *.java

install:  all
	cp aaLocal.jar ${INSTDIR}
