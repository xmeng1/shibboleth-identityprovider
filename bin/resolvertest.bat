@echo off
setlocal

REM We need a JVM
if not defined JAVA_HOME  (
  echo Error: JAVA_HOME is not defined.
  exit /b
)

if not defined JAVACMD (
  set JAVACMD=%JAVA_HOME\bin\java.exe
)

if not exist %JAVACMD (
  echo Error: JAVA_HOME is not defined correctly.
  echo Cannot execute %JAVACMD
  exit /b
)


REM Find the shibboleth components
if not defined SHIB_HOME (
  echo Error: SHIB_HOME is not defined.
  exit /b
)

if not exist %SHIB_HOME/lib/shib-util.jar (
  echo Error: Cannot find the shibboleth jar (shib-util.jar).
  echo      If you downloaded the shibboleth source, you need to run "ant build-util"
  exit /b
)

set ENDORSED=%SHIB_HOME\endorsed

REM Grab all the dependencies
if defined CLASSPATH (
  set SHIB_UTIL_CLASSPATH=%CLASSPATH
)

set DIRLIBS=%SHIB_HOME\lib\*.jar
for %%i in (%DIRLIBS) do (
  if defined SHIB_UTIL_CLASSPATH (
    set SHIB_UTIL_CLASSPATH="%i";%SHIB_UTIL_CLASSPATH
  ) else (
    set SHIB_UTIL_CLASSPATH=%i
  )
)


REM Here we go
%JAVACMD -Djava.endorsed.dirs="%ENDORSED" -classpath "%SHIB_UTIL_CLASSPATH" edu.internet2.middleware.shibboleth.utils.ResolverTest %*
