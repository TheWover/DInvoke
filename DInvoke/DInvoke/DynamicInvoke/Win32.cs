// Author: Ryan Cobb (@cobbr_io), The Wover (@TheRealWover)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

using System;
using System.Runtime.InteropServices;

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
        /// Uses DynamicInvocation to call the WTSOpenServerA Win32 API. https://docs.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsopenservera
        /// </summary>
        /// <returns>Returns a pointer to the local or remote session.</returns>
        public static IntPtr WTSOpenServerA(string pServerName)
        {

            // Build the set of parameters to pass in to WTSOpenServerA
            object[] funcargs =
            {
                pServerName
            };

            Generic.GetLibraryAddress(@"C:\Windows\System32\wtsapi32.dll", "WTSOpenServerA", true, true);
            IntPtr hServer = (IntPtr)Generic.DynamicAPIInvoke(@"wtsapi32.dll", @"WTSOpenServerA", typeof(Delegates.WTSOpenServerA), ref funcargs);

            return hServer;
        }

        /// <summary>
        /// Uses DynamicInvocation to call the WTSEnumerateSessionsA Win32 API. https://docs.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsenumeratesessionsa
        /// </summary>
        /// <returns>Returns true or false after enumerating the sessions.</returns>
        public static bool WTSEnumerateSessionsA(
            IntPtr hServer,
            int Reserved,
            int Version,
            ref IntPtr ppSessionInfo,
            ref int pCount)
        {

            // Build the set of parameters to pass in to WTSEnumerateSessionsA
            object[] funcargs =
            {
                IntPtr.Zero,0,1,ppSessionInfo,pCount
            };

            Generic.GetLibraryAddress(@"C:\Windows\System32\wtsapi32.dll", "WTSEnumerateSessionsA", true, true);
            bool res = (bool)Generic.DynamicAPIInvoke(@"wtsapi32.dll", @"WTSEnumerateSessionsA", typeof(Delegates.WTSEnumerateSessionsA), ref funcargs);

            ppSessionInfo = (IntPtr)funcargs[3];
            pCount = (int)funcargs[4];

            return res;
        }

        /// <summary>
        /// Uses DynamicInvocation to call the WTSDisconnectSession Win32 API. https://docs.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-WTSDisconnectSession
        /// </summary>
        /// <returns>Returns true or false after disconnecting the target session.</returns>
        public static bool WTSDisconnectSession(
            IntPtr hServer, 
            int SessionId, 
            bool Wait)
        {

            // Build the set of parameters to pass in to WTSDisconnectSession
            object[] funcargs =
            {
                hServer,SessionId,Wait
            };

            Generic.GetLibraryAddress(@"C:\Windows\System32\wtsapi32.dll", "WTSDisconnectSession", true, true);
            bool res = (bool)Generic.DynamicAPIInvoke(@"wtsapi32.dll", @"WTSDisconnectSession", typeof(Delegates.WTSDisconnectSession), ref funcargs);

            return res;
        }

        /// <summary>
        /// Uses DynamicInvocation to call the WTSConnectSessionA Win32 API. https://docs.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-WTSConnectSessiona
        /// </summary>
        /// <returns>Returns true or false after opening the target session.</returns>
        public static bool WTSConnectSession(
            int TargetSessionId,
            int SourceSessionId,
            string Password,
            bool Wait)
        {

            // Build the set of parameters to pass in to WTSConnectSessionA
            object[] funcargs =
            {
                TargetSessionId,SourceSessionId,Password,Wait
            };

            Generic.GetLibraryAddress(@"C:\Windows\System32\wtsapi32.dll", "WTSConnectSessionA", true, true);
            bool res = (bool)Generic.DynamicAPIInvoke(@"wtsapi32.dll", @"WTSConnectSessionA", typeof(Delegates.WTSConnectSession), ref funcargs);

            return res;
        }

        public static class Delegates
        {
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool WTSConnectSession(
                    int targetSessionId,
                    int sourceSessionId,
                    string password,
                    bool wait);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool WTSDisconnectSession(
                IntPtr hServer,
                int sessionId,
                bool bWait);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr WTSOpenServerA(
                string pServerName);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool WTSEnumerateSessionsA(
                IntPtr hServer,
                int Reserved,
                int Version,
                ref IntPtr ppSessionInfo,
                ref int pCount);

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
        }
    }
}