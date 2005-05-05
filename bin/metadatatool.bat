@echo off
setlocal

REM We need a JVM
if not defined JAVA_HOME  (
  echo Error: JAVA_HOME is not defined.
  exit /b
)

if not defined JAVACMD (
  set JAVACMD="%JAVA_HOME%\bin\java.exe"
)

if not exist %JAVACMD% (
  echo Error: JAVA_HOME is not defined correctly.
  echo Cannot execute %JAVACMD%
  exit /b
)

REM The root of the Shibboleth package tree, relative to the run directory
if not defined SHIB_HOME (
  set SHIB_HOME=.
)

set ENDORSED=%SHIB_HOME%\endorsed

if not exist %SHIB_HOME%\lib\shib-util.jar (
  echo Error: Cannot find shib-util.jar
  echo 		If you downloaded the shibboleth source, you need to run "ant build-util"
  exit /b
)

REM Grab all the dependencies
if defined CLASSPATH (
  set LOCALCLASSPATH=%CLASSPATH%
)

REM add in the dependency .jar files
for %%i in (%SHIB_HOME%\lib\*.jar) do (
	call %SHIB_HOME%\cpappend.bat %%i
)

REM Here we go
%JAVACMD% -Djava.endorsed.dirs="%ENDORSED%" -cp "%LOCALCLASSPATH%" edu.internet2.middleware.shibboleth.utils.MetadataTool %*

