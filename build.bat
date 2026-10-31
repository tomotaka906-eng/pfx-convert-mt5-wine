@echo off
rem Build PfxConvert.exe with the C# compiler that ships with Windows (.NET Framework 4.x).
rem Keep this file ASCII-only.
setlocal
set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
  echo csc.exe not found. .NET Framework 4.x is required.
  exit /b 1
)
"%CSC%" /nologo /target:winexe /optimize+ /codepage:65001 /out:"%~dp0PfxConvert.exe" /win32icon:"%~dp0app.ico" /resource:"%~dp0app.ico",PfxConvert.app.ico /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll "%~dp0PfxConvert.cs"
if errorlevel 1 exit /b 1
echo Built: %~dp0PfxConvert.exe
