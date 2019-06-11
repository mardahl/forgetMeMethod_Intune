#requires -RunAsAdministrator 
<#
.SYNOPSIS
Execute Powershell code with Intune Management Extension, and have it run everytime IME reloads (about every hour)
.DESCRIPTION
Normally a script executed successfully through IME will never be run again.
The code in this script will erase the registry entry that tells IME that it has already run the script.
This version will also execute some code as the currently logged on user
.REQUIREMENTS
This script must be run as with SYSTEM priviledges.
Executed in 64bit PowerShell.
.EXAMPLE
Assign the script to a test user or device in Intune, then restart the IME service on your test computer.
The script will run and generate output files in c:\windows\temp\ and the users TEMP for your perusal...
.COPYRIGHT
MIT License, feel free to distribute and use as you like, please leave author information.
.AUTHOR
Michael Mardahl - @michael_mardahl on twitter - BLOG: https://www.iphase.dk
.DISCLAIMER
This script is provided AS-IS, with no warranty - Use at own risk!
Proof of Concept version! Could use alot of cleanup :)
#>

Start-Transcript -Path "$($env:windir)\temp\forgetMeScript_log.txt"

### Do something that you want IME to repeat everytime it runs configuration scripts (every hour or so).
# put your code in the TRY block after the Function - The FINALLY block will make sure that even if your code fails, Intune will still run your script again.

function executeAsLoggedOnUser ($Command,$Hidden=$true) {
    # custom API for token manipulation, allowing the system account to execute a command as the currently logged-on user.
    # C# borrowed from the awesome Justin Myrray (https://github.com/murrayju/CreateProcessAsUser)

$csharpCode = @"
    using System;  
    using System.Runtime.InteropServices;

    namespace murrayju.ProcessExtensions  
    {
        public static class ProcessExtensions
        {
            #region Win32 Constants

            private const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;
            private const int CREATE_NO_WINDOW = 0x08000000;

            private const int CREATE_NEW_CONSOLE = 0x00000010;

            private const uint INVALID_SESSION_ID = 0xFFFFFFFF;
            private static readonly IntPtr WTS_CURRENT_SERVER_HANDLE = IntPtr.Zero;

            #endregion

            #region DllImports

            [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
            private static extern bool CreateProcessAsUser(
                IntPtr hToken,
                String lpApplicationName,
                String lpCommandLine,
                IntPtr lpProcessAttributes,
                IntPtr lpThreadAttributes,
                bool bInheritHandle,
                uint dwCreationFlags,
                IntPtr lpEnvironment,
                String lpCurrentDirectory,
                ref STARTUPINFO lpStartupInfo,
                out PROCESS_INFORMATION lpProcessInformation);

            [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
            private static extern bool DuplicateTokenEx(
                IntPtr ExistingTokenHandle,
                uint dwDesiredAccess,
                IntPtr lpThreadAttributes,
                int TokenType,
                int ImpersonationLevel,
                ref IntPtr DuplicateTokenHandle);

            [DllImport("userenv.dll", SetLastError = true)]
            private static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

            [DllImport("userenv.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern bool CloseHandle(IntPtr hSnapshot);

            [DllImport("kernel32.dll")]
            private static extern uint WTSGetActiveConsoleSessionId();

            [DllImport("Wtsapi32.dll")]
            private static extern uint WTSQueryUserToken(uint SessionId, ref IntPtr phToken);

            [DllImport("wtsapi32.dll", SetLastError = true)]
            private static extern int WTSEnumerateSessions(
                IntPtr hServer,
                int Reserved,
                int Version,
                ref IntPtr ppSessionInfo,
                ref int pCount);

            #endregion

            #region Win32 Structs

            private enum SW
            {
                SW_HIDE = 0,
                SW_SHOWNORMAL = 1,
                SW_NORMAL = 1,
                SW_SHOWMINIMIZED = 2,
                SW_SHOWMAXIMIZED = 3,
                SW_MAXIMIZE = 3,
                SW_SHOWNOACTIVATE = 4,
                SW_SHOW = 5,
                SW_MINIMIZE = 6,
                SW_SHOWMINNOACTIVE = 7,
                SW_SHOWNA = 8,
                SW_RESTORE = 9,
                SW_SHOWDEFAULT = 10,
                SW_MAX = 10
            }

            private enum WTS_CONNECTSTATE_CLASS
            {
                WTSActive,
                WTSConnected,
                WTSConnectQuery,
                WTSShadow,
                WTSDisconnected,
                WTSIdle,
                WTSListen,
                WTSReset,
                WTSDown,
                WTSInit
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct PROCESS_INFORMATION
            {
                public IntPtr hProcess;
                public IntPtr hThread;
                public uint dwProcessId;
                public uint dwThreadId;
            }

            private enum SECURITY_IMPERSONATION_LEVEL
            {
                SecurityAnonymous = 0,
                SecurityIdentification = 1,
                SecurityImpersonation = 2,
                SecurityDelegation = 3,
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct STARTUPINFO
            {
                public int cb;
                public String lpReserved;
                public String lpDesktop;
                public String lpTitle;
                public uint dwX;
                public uint dwY;
                public uint dwXSize;
                public uint dwYSize;
                public uint dwXCountChars;
                public uint dwYCountChars;
                public uint dwFillAttribute;
                public uint dwFlags;
                public short wShowWindow;
                public short cbReserved2;
                public IntPtr lpReserved2;
                public IntPtr hStdInput;
                public IntPtr hStdOutput;
                public IntPtr hStdError;
            }

            private enum TOKEN_TYPE
            {
                TokenPrimary = 1,
                TokenImpersonation = 2
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct WTS_SESSION_INFO
            {
                public readonly UInt32 SessionID;

                [MarshalAs(UnmanagedType.LPStr)]
                public readonly String pWinStationName;

                public readonly WTS_CONNECTSTATE_CLASS State;
            }

            #endregion

            // Gets the user token from the currently active session
            private static bool GetSessionUserToken(ref IntPtr phUserToken)
            {
                var bResult = false;
                var hImpersonationToken = IntPtr.Zero;
                var activeSessionId = INVALID_SESSION_ID;
                var pSessionInfo = IntPtr.Zero;
                var sessionCount = 0;

                // Get a handle to the user access token for the current active session.
                if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, ref pSessionInfo, ref sessionCount) != 0)
                {
                    var arrayElementSize = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                    var current = pSessionInfo;

                    for (var i = 0; i < sessionCount; i++)
                    {
                        var si = (WTS_SESSION_INFO)Marshal.PtrToStructure((IntPtr)current, typeof(WTS_SESSION_INFO));
                        current += arrayElementSize;

                        if (si.State == WTS_CONNECTSTATE_CLASS.WTSActive)
                        {
                            activeSessionId = si.SessionID;
                        }
                    }
                }

                // If enumerating did not work, fall back to the old method
                if (activeSessionId == INVALID_SESSION_ID)
                {
                    activeSessionId = WTSGetActiveConsoleSessionId();
                }

                if (WTSQueryUserToken(activeSessionId, ref hImpersonationToken) != 0)
                {
                    // Convert the impersonation token to a primary token
                    bResult = DuplicateTokenEx(hImpersonationToken, 0, IntPtr.Zero,
                        (int)SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, (int)TOKEN_TYPE.TokenPrimary,
                        ref phUserToken);

                    CloseHandle(hImpersonationToken);
                }

                return bResult;
            }

            public static bool StartProcessAsCurrentUser(string cmdLine, bool visible, string appPath = null, string workDir = null)
            {
                var hUserToken = IntPtr.Zero;
                var startInfo = new STARTUPINFO();
                var procInfo = new PROCESS_INFORMATION();
                var pEnv = IntPtr.Zero;
                int iResultOfCreateProcessAsUser;

                startInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));

                try
                {
                    if (!GetSessionUserToken(ref hUserToken))
                    {
                        throw new Exception("StartProcessAsCurrentUser: GetSessionUserToken failed.");
                    }

                    uint dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | (uint)(visible ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW);
                    startInfo.wShowWindow = (short)(visible ? SW.SW_SHOW : SW.SW_HIDE);
                    startInfo.lpDesktop = "winsta0\\default";

                    if (!CreateEnvironmentBlock(ref pEnv, hUserToken, false))
                    {
                        throw new Exception("StartProcessAsCurrentUser: CreateEnvironmentBlock failed.");
                    }

                    if (!CreateProcessAsUser(hUserToken,
                        appPath, // Application Name
                        cmdLine, // Command Line
                        IntPtr.Zero,
                        IntPtr.Zero,
                        false,
                        dwCreationFlags,
                        pEnv,
                        workDir, // Working directory
                        ref startInfo,
                        out procInfo))
                    {
                        throw new Exception("StartProcessAsCurrentUser: CreateProcessAsUser failed.\n");
                    }

                    iResultOfCreateProcessAsUser = Marshal.GetLastWin32Error();
                }
                finally
                {
                    CloseHandle(hUserToken);
                    if (pEnv != IntPtr.Zero)
                    {
                        DestroyEnvironmentBlock(pEnv);
                    }
                    CloseHandle(procInfo.hThread);
                    CloseHandle(procInfo.hProcess);
                }
                return true;
            }
        }
    }
"@
    # Importing the source code as csharp
    $compilerParams = [System.CodeDom.Compiler.CompilerParameters]::new()
    $compilerParams.ReferencedAssemblies.AddRange(('System.Runtime.InteropServices.dll', 'System.dll'))
    $compilerParams.CompilerOptions = '/unsafe'
    $compilerParams.GenerateInMemory = $True
    Add-Type -TypeDefinition $csharpCode -Language CSharp -CompilerParameters $compilerParams
    # Execute a process as the currently logged on user. 
    # Absolute paths required if running as SYSTEM!
    if($Hidden) {
        $runCommand = [murrayju.ProcessExtensions.ProcessExtensions]::StartProcessAsCurrentUser($Command,$false)
    }else{
        $runCommand = [murrayju.ProcessExtensions.ProcessExtensions]::StartProcessAsCurrentUser($Command,$true)
    }

    if ($runCommand) {
        return "Executed `"$Command`" as loggedon user"
    } else {
        throw "Something went wrong when executing process as currently logged-on user"
    }
}

# Execute section

try {

    # lets output a test to the currently logged in users temp folder, outputting the users name.
    # You can go have a look in there to see that this works as expected

$scriptFile = @'
whoami >> "$($env:TEMP)\forgetMeScript_whoami.txt"
'@

    $scriptFile | Out-File "c:\windows\temp\forgetMeScript_whoami.ps1" -Force
    
    $userCommand = '{0}\System32\WindowsPowerShell\v1.0\powershell.exe -executionPolicy bypass -file c:\windows\temp\forgetMe_whoami.ps1' -f $($env:windir)
    # running command as logged-on user, and escaping backslashes so they get interpreted literaly
    executeAsLoggedOnUser -Command $userCommand.Replace("\","\\")
    Write-Output "Ran the forgetMeMethod on $((get-date).DateTime)" >> "$($env:windir)\temp\forgetMeScript_log_proof.txt"

} finally {
    ### These aren't the droids you're looking for...

    # starting the process that will remove this scripts policy from IME after it has run... (can't really do it while it's running!)
    # getting the name of the script file as it is run by IME
    # NOTICE! this will ONLY work when run by IME, so testing is not really easy.
    $scriptName = $MyInvocation.MyCommand.Name.Split(".")[0]
    $userGUID = $scriptName.Split("_")[0]
    $policyGUID = $scriptName.Split("_")[1]

    # generating the reg key path that we need to remove in order to have IME forget it ever ran this script.
    $regKey = "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Policies\$userGUID\$policyGUID"

    # where to log the delete process
    $removalOutput = "$($env:windir)\temp\forgetMeScript_job_log.txt"

    # the delete registry key script
$deleteScript = @'
start-transcript "{0}";
Start-Sleep -Seconds 30;
Remove-Item -path "{1}" -Force -confirm:$false;
Write-Output "Next line should say false if all whent well...";
Test-Path -path "{1}";
Stop-Transcript;
'@ -f $removalOutput,$regKey

    $deleteScriptName = "c:\windows\temp\delete_$policyGUID.ps1"
    $deleteScript | Out-File $deleteScriptName -Force

    # starting a seperate powershell process that will wait 30 seconds before deleting the IME Policy registry key.
    $deleteProcess = New-Object System.Diagnostics.ProcessStartInfo "Powershell";
    $deleteProcess.Arguments = "-File " + $deleteScriptName
    $deleteProcess.Verb = "runas";
    [System.Diagnostics.Process]::Start($deleteProcess);

    Stop-Transcript
    exit
}


