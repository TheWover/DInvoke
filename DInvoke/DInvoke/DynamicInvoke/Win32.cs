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

        public static Boolean CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, Data.Win32.Advapi32.CREATION_FLAGS dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref Data.Win32.ProcessThreadsAPI.STARTF lpStartupInfo, out Data.Win32.ProcessThreadsAPI._PROCESS_INFORMATION lpProcessInformation)
        {
            lpProcessInformation = new Data.Win32.ProcessThreadsAPI._PROCESS_INFORMATION();
            object[] funcargs =
            {
                lpApplicationName,lpCommandLine,lpProcessAttributes,lpThreadAttributes,bInheritHandles,dwCreationFlags,
                lpEnvironment,lpCurrentDirectory,lpStartupInfo,lpProcessInformation
            };
            Boolean success = (Boolean)Generic.DynamicAPIInvoke(@"kernel32.dll", @"CreateProcessA", typeof(Delegates.CreateProcess), ref funcargs);
            lpProcessInformation = (Data.Win32.ProcessThreadsAPI._PROCESS_INFORMATION)funcargs[9];
            return success;
        }


        public static IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect)
        {
            object[] funcargs =
            {
                hProcess,lpAddress,dwSize,flAllocationType,flProtect
            };
            IntPtr retval = (IntPtr)Generic.DynamicAPIInvoke(@"kernel32.dll", @"VirtualAllocEx", typeof(Delegates.VirtualAllocEx), ref funcargs);
            return retval;
        }


        public static bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten)
        {
            lpNumberOfBytesWritten = UIntPtr.Zero;
            object[] funcargs =
            {
                hProcess,lpBaseAddress,lpBuffer,nSize,lpNumberOfBytesWritten
            };
            bool success = (bool)Generic.DynamicAPIInvoke(@"kernel32.dll", @"WriteProcessMemory", typeof(Delegates.WriteProcessMemory), ref funcargs);
            return success;
        }


        public static IntPtr OpenThread(Data.Win32.Kernel32.ThreadAccess dwDesiredAccess, bool bInheritHandle,
        int dwThreadId)
        {
            object[] funcargs =
            {
                dwDesiredAccess,bInheritHandle,dwThreadId
            };
            IntPtr retvalue = (IntPtr)Generic.DynamicAPIInvoke(@"kernel32.dll", @"OpenThread", typeof(Delegates.OpenThread), ref funcargs);
            return retvalue;
        }


        public static Boolean VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect)
        {
            lpflOldProtect = 0;
            object[] funcargs =
            {
                hProcess,lpAddress,dwSize,flNewProtect,lpflOldProtect
            };
            Boolean retval = (Boolean)Generic.DynamicAPIInvoke(@"kernel32.dll", @"VirtualProtectEx", typeof(Delegates.VirtualProtectEx), ref funcargs);
            return retval;
        }

        public static IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData)
        {
            object[] funcargs =
            {
                pfnAPC,hThread,dwData
            };
            IntPtr retval = (IntPtr)Generic.DynamicAPIInvoke(@"kernel32.dll", @"QueueUserAPC", typeof(Delegates.QueueUserAPC), ref funcargs);
            return retval;
        }

        public static uint ResumeThread(IntPtr hThread)
        {
            object[] funcargs =
            {
                hThread
            };
            uint retval = (uint)Generic.DynamicAPIInvoke(@"kernel32.dll", @"ResumeThread", typeof(Delegates.ResumeThread), ref funcargs);
            return retval;

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

            lpSystemInfo = (bool)funcargs[1];

            // Dynamically load and invoke the API call with out parameters
            return retVal;
        }

        public static class Delegates
        {
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
            public delegate Boolean CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, Data.Win32.Advapi32.CREATION_FLAGS dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref Data.Win32.ProcessThreadsAPI.STARTF lpStartupInfo, out Data.Win32.ProcessThreadsAPI._PROCESS_INFORMATION lpProcessInformation);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr OpenThread(Data.Win32.Kernel32.ThreadAccess dwDesiredAccess, bool bInheritHandle,
            int dwThreadId);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Boolean VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate uint ResumeThread(IntPtr hThhread);
        }
    }
}
