:: Copyright 2010-2012 Canonical Ltd.
::
:: This program is free software: you can redistribute it and/or modify it
:: under the terms of the GNU General Public License version 3, as published
:: by the Free Software Foundation.
::
:: This program is distributed in the hope that it will be useful, but
:: WITHOUT ANY WARRANTY; without even the implied warranties of
:: MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
:: PURPOSE.  See the GNU General Public License for more details.
::
:: You should have received a copy of the GNU General Public License along
:: with this program.  If not, see <http://www.gnu.org/licenses/>.
::
:: In addition, as a special exception, the copyright holders give
:: permission to link the code of portions of this program with the
:: OpenSSL library under certain conditions as described in each
:: individual source file, and distribute linked combinations
:: including the two.
:: You must obey the GNU General Public License in all respects
:: for all of the code used other than OpenSSL.  If you modify
:: file(s) with this exception, you may extend this exception to your
:: version of the file(s), but you are not obligated to do so.  If you
:: do not wish to do so, delete this exception statement from your
:: version.  If you delete this exception statement from all source
:: files in the program, then also delete it here.

@ECHO off

SET PYTHONEXEPATH=""

set PYTHONPATH=%PYTHONPATH%;..\ubuntu-sso-client;.

ECHO Checking for Python on the path
:: Look for Python from buildout
FOR %%A in (python.exe) do (SET PYTHONEXEPATH=%%~$PATH:A)
FOR %%B in (u1trial.exe) do (SET TRIALPATH=%%~$PATH:B)
FOR %%C in (u1lint.exe) do (SET LINTPATH=%%~$PATH:C)
FOR %%D in (pep8.exe) do (SET PEP8PATH=%%~$PATH:D)

IF NOT "%PYTHONEXEPATH%" == "" GOTO :PYTHONPRESENT

ECHO Please ensure you have python installed
GOTO :END

:PYTHONPRESENT

:: throw the first parameter away if is /skip-lint,
:: the way we do this is to ensure that /skip-lint
:: is the first parameter and copy all the rest in a loop
:: the main reason for that is that %* is not affected
:: by SHIFT, that is, it allways have all passed parameters

SET PARAMS=%*
SET SKIPLINT=0
IF "%1" == "/skip-lint" (
    SET SKIPLINT=1
    GOTO :CLEANPARAMS
)ELSE (
    GOTO :CONTINUEBATCH) 
:CLEANPARAMS

SHIFT
SET PARAMS=%1
:GETREST
SHIFT
if [%1]==[] (
    GOTO CONTINUEBATCH)
SET PARAMS=%PARAMS% %1
GOTO GETREST
:CONTINUEBATCH

ECHO Python found at %PYTHONEXEPATH%, building auto-generated modules...
:: call setup.py build so that necessary generated files are built
::START "Build code" /D%CD% /WAIT "%PYTHONEXEPATH%\python.exe" setup.py build
"%PYTHONEXEPATH%" setup.py build
ECHO Running tests
:: execute the tests with a number of ignored linux and mac os only modules
"%TRIALPATH%" --reactor=twisted -c -p tests\platform\linux -i "test_linux.py,test_darwin.py,test_fsevents_daemon.py" %PARAMS% tests
:: Clean the build from the setupt.py
ECHO Cleaning the generated code before running the style checks...
"%PYTHONEXEPATH%" setup.py clean

IF %SKIPLINT% == 1 (
    ECHO Skipping style checks
    GOTO :CLEAN)
ECHO Performing style checks...
"%LINTPATH%"

"%PYTHONEXEPATH%" contrib\check-reactor-import

:: if pep8 is not present, move to the end
IF EXIST "%PEP8PATH%" (
    "%PEP8PATH%" --repeat ubuntuone
)ELSE (
    ECHO Style checks were not done)
:CLEAN

:: The dot must be escaped or the directory won't be found.
IF EXIST \.coverage RMDIR /s /q \.coverage

:: Delete the temp folders
IF "%TRIAL_TEMP_DIR%" == "" GOTO :TRIALTEMPEXISTS
IF EXIST _trial_temp RMDIR /s /q _trial_temp
: TRIALTEMPEXISTS
IF EXIST "%TRIAL_TEMP_DIR%" RMDIR /s /q "%TRIAL_TEMP_DIR%"

:END
