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

REM The root of the Shibboleth package tree, relative to the run directory
if not exist %SHIB_HOME (
  set SHIB_HOME=.
)

REM Grab all the dependencies
if defined CLASSPATH (
  set SHIB_UTIL_CLASSPATH=%CLASSPATH
)
set SHIB_UTIL_CLASSPATH="%SHIB_HOME\webApplication\WEB-INF\classes";%SHIB_UTIL_CLASSPATH

set DIRLIBS=%SHIB_HOME\lib\*.jar
for %%i in (%DIRLIBS) do (
  if defined SHIB_UTIL_CLASSPATH (
    set SHIB_UTIL_CLASSPATH="%i";%SHIB_UTIL_CLASSPATH
  ) else (
    set SHIB_UTIL_CLASSPATH=%i
  )
)

set DIRLIBS=%SHIB_HOME\webApplication\WEB-INF\lib\*.jar
for %%i in (%DIRLIBS) do (
  if defined SHIB_UTIL_CLASSPATH (
    set SHIB_UTIL_CLASSPATH="%i";%SHIB_UTIL_CLASSPATH
  ) else (
    set SHIB_UTIL_CLASSPATH=%i
  )
)

REM Here we go
%JAVACMD -cp "%SHIB_UTIL_CLASSPATH" edu.internet2.middleware.shibboleth.utils.ExtKeyTool %*
