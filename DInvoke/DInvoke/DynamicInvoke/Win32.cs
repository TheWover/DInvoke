// Author: Ryan Cobb (@cobbr_io), The Wover (@TheRealWover)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace DInvoke.DynamicInvoke
{
    /// <summary>
    /// Contains function prototypes and wrapper functions for dynamically invoking Win32 API Calls.
    /// </summary>
    public static class Win32
    {
        /// <summary>
        /// Uses DynamicInvocation to call the OpenProcess Win32 API. https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
        /// </summary>
        /// <author>The Wover (@TheRealWover)</author>
        /// <param name="dwDesiredAccess"></param>
        /// <param name="bInheritHandle"></param>
        /// <param name="dwProcessId"></param>
        /// <returns></returns>
        public static IntPtr OpenProcess(Data.Win32.Kernel32.ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, UInt32 dwProcessId)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                dwDesiredAccess, bInheritHandle, dwProcessId
            };

            return (IntPtr)Generic.DynamicAPIInvoke(@"kernel32.dll", @"OpenProcess",
                typeof(Delegates.OpenProcess), ref funcargs);
        }

        public static IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            ref IntPtr lpThreadId)
        {
            // Craft an array for the arguments
            object[] funcargs =
            {
                hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId
            };

            IntPtr retValue = (IntPtr)Generic.DynamicAPIInvoke(@"kernel32.dll", @"CreateRemoteThread",
                typeof(Delegates.CreateRemoteThread), ref funcargs);

            // Update the modified variables
            lpThreadId = (IntPtr)funcargs[6];

            return retValue;
        }

        /// <summary>
        /// Uses DynamicInvocation to call the IsWow64Process Win32 API. https://docs.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process
        /// </summary>
        /// <returns>Returns true if process is WOW64, and false if not (64-bit, or 32-bit on a 32-bit machine).</returns>
        public static bool IsWow64Process(IntPtr hProcess, ref bool lpSystemInfo)
        {

            // Build the set of parameters to pass in to IsWow64Process
            object[] funcargs =
            {
                hProcess, lpSystemInfo
            };

            bool retVal = (bool)Generic.DynamicAPIInvoke(@"kernel32.dll", @"IsWow64Process", typeof(Delegates.IsWow64Process), ref funcargs);

            lpSystemInfo = (bool) funcargs[1];

            // Dynamically load and invoke the API call with out parameters
            return retVal;
        }

        /// <summary>
        /// Uses DynamicInvocation to call the CloseHandle Win32 API. https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
        /// </summary>
        /// <returns></returns>
        public static bool CloseHandle(IntPtr handle)
        {

            // Build the set of parameters to pass in to CloseHandle
            object[] funcargs =
            {
                handle
            };

            bool retVal = (bool)Generic.DynamicAPIInvoke(@"kernel32.dll", @"CloseHandle", typeof(Delegates.CloseHandle), ref funcargs);

            // Dynamically load and invoke the API call with out parameters
            return retVal;
        }

        public static class Delegates
        {
            // Kernel32.dll

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr CreateRemoteThread(IntPtr hProcess,
                IntPtr lpThreadAttributes,
                uint dwStackSize,
                IntPtr lpStartAddress,
                IntPtr lpParameter,
                uint dwCreationFlags,
                out IntPtr lpThreadId);

            [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
            public delegate IntPtr OpenProcess(
                Data.Win32.Kernel32.ProcessAccessFlags dwDesiredAccess,
                bool bInheritHandle,
                UInt32 dwProcessId
            );

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool IsWow64Process(
                IntPtr hProcess, ref bool lpSystemInfo
            );

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Boolean CloseHandle(IntPtr hProcess);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr GetCurrentThread();

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 SearchPath(String lpPath, String lpFileName, String lpExtension, UInt32 nBufferLength, StringBuilder lpBuffer, ref IntPtr lpFilePart);

            //Advapi32.dll

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Boolean OpenProcessToken(IntPtr hProcess, UInt32 dwDesiredAccess, out IntPtr hToken);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Boolean SetThreadToken(IntPtr ThreadHandle, IntPtr TokenHandle);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Boolean DuplicateTokenEx(IntPtr hExistingToken, UInt32 dwDesiredAccess, IntPtr lpTokenAttributes, _SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, _TOKEN_TYPE TokenType, out IntPtr phNewToken);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Boolean ImpersonateLoggedOnUser(IntPtr hToken);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Boolean OpenThreadToken(IntPtr ThreadHandle, UInt32 DesiredAccess, Boolean OpenAsSelf, ref IntPtr TokenHandle);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Boolean ImpersonateSelf(_SECURITY_IMPERSONATION_LEVEL ImpersonationLevel);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Boolean LookupPrivilegeValueA(String lpSystemName, String lpName, ref _LUID luid);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Boolean AdjustTokenPrivileges(IntPtr TokenHandle, Boolean DisableAllPrivileges, ref _TOKEN_PRIVILEGES NewState, UInt32 BufferLengthInBytes, ref _TOKEN_PRIVILEGES PreviousState, out UInt32 ReturnLengthInBytes);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Boolean LookupPrivilegeName(String lpSystemName, IntPtr lpLuid, StringBuilder lpName, ref Int32 cchName);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Boolean GetTokenInformation(IntPtr TokenHandle, _TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, UInt32 TokenInformationLength, out UInt32 ReturnLength);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Boolean PrivilegeCheck(IntPtr ClientToken, _PRIVILEGE_SET RequiredPrivileges, IntPtr pfResult);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool LookupAccountSidA(String lpSystemName, IntPtr Sid, StringBuilder lpName, ref UInt32 cchName, StringBuilder ReferencedDomainName, ref UInt32 cchReferencedDomainName, out _SID_NAME_USE peUse);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool ConvertSidToStringSidA(IntPtr Sid, ref IntPtr StringSid);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Boolean LookupPrivilegeNameA(String lpSystemName, IntPtr lpLuid, StringBuilder lpName, ref Int32 cchName);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool CreateProcessWithTokenW(IntPtr hToken, LogonFlags dwLogonFlags, Byte[] lpApplicationName, Byte[] lpCommandLine, CreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref _STARTUPINFO lpStartupInfo, out _PROCESS_INFORMATION lpProcessInformation);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Boolean CreateProcessWithLogonW(String lpUsername,String lpDomain,String lpPassword, LogonFlags dwLogonFlags,Byte[] lpApplicationName,Byte[] lpCommandLine,CREATION_FLAGS dwCreationFlags,IntPtr lpEnvironment,String lpCurrentDirectory,ref _STARTUPINFO lpStartupInfo,out _PROCESS_INFORMATION lpProcessInformation);
            
            // Secur32.dll || sspicli.dll

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate UInt32 LsaGetLogonSessionData(IntPtr LogonId, out IntPtr ppLogonSessionData);
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _LUID
        {
            public System.UInt32 LowPart;
            public System.UInt32 HighPart;
        }

        //https://msdn.microsoft.com/en-us/library/windows/desktop/ms684873(v=vs.85).aspx
        [StructLayout(LayoutKind.Sequential)]
        public struct _PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public UInt32 dwProcessId;
            public UInt32 dwThreadId;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct _STARTUPINFO
        {
            public UInt32 cb;
            public String lpReserved;
            public String lpDesktop;
            public String lpTitle;
            public UInt32 dwX;
            public UInt32 dwY;
            public UInt32 dwXSize;
            public UInt32 dwYSize;
            public UInt32 dwXCountChars;
            public UInt32 dwYCountChars;
            public UInt32 dwFillAttribute;
            public UInt32 dwFlags;
            public UInt16 wShowWindow;
            public UInt16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        };

        [Flags]
        public enum _TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }
        public enum LogonFlags
        {
            WithProfile = 1,
            NetCredentialsOnly = 0
        }
        public enum CreationFlags
        {
            DefaultErrorMode = 0x04000000,
            NewConsole = 0x00000010,
            CREATE_NO_WINDOW = 0x08000000,
            NewProcessGroup = 0x00000200,
            SeparateWOWVDM = 0x00000800,
            Suspended = 0x00000004,
            UnicodeEnvironment = 0x00000400,
            ExtendedStartupInfoPresent = 0x00080000
        }

        [Flags]
        public enum _SECURITY_IMPERSONATION_LEVEL : int
        {
            SecurityAnonymous = 0,
            SecurityIdentification = 1,
            SecurityImpersonation = 2,
            SecurityDelegation = 3
        };

        [Flags]
        public enum CREATION_FLAGS : uint
        {
            NONE = 0x0,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_SUSPENDED = 0x00000004,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000
        }

        [Flags]
        public enum _SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer,
            SidTypeLabel
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _TOKEN_PRIVILEGES
        {
            public UInt32 PrivilegeCount;
            public _LUID_AND_ATTRIBUTES Privileges;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _LUID_AND_ATTRIBUTES
        {
            public _LUID Luid;
            public System.UInt32 Attributes;
        }

        internal const Int32 ANYSIZE_ARRAY = 1;

        [StructLayout(LayoutKind.Sequential)]
        public struct _PRIVILEGE_SET
        {
            public System.UInt32 PrivilegeCount;
            public System.UInt32 Control;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = (Int32)ANYSIZE_ARRAY)]
            public _LUID_AND_ATTRIBUTES[] Privilege;
        }

        [Flags]
        public enum _TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUIAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            TokenIsAppContainer,
            TokenCapabilities,
            TokenAppContainerSid,
            TokenAppContainerNumber,
            TokenUserClaimAttributes,
            TokenDeviceClaimAttributes,
            TokenRestrictedUserClaimAttributes,
            TokenRestrictedDeviceClaimAttributes,
            TokenDeviceGroups,
            TokenRestrictedDeviceGroups,
            TokenSecurityAttributes,
            TokenIsRestricted,
            MaxTokenInfoClass
        }
    }
}
