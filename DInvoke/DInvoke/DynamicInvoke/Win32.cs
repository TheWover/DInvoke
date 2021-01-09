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

        public static Data.Native.NTSTATUS SearchPathW(
                string lpPath,
                string lpFileName,
                string lpExtension,
                UInt32 nBufferLength,
                StringBuilder lpBuffer,
                out IntPtr filePartOut)
        {
            filePartOut = IntPtr.Zero;
            // Craft an array for the arguments
            object[] funcargs =
            {
                lpPath, lpFileName, lpExtension, nBufferLength, lpBuffer, filePartOut
            };

            Data.Native.NTSTATUS retValue = (Data.Native.NTSTATUS)Generic.DynamicAPIInvoke(@"kernel32.dll", @"SearchPathW", typeof(Delegates.SearchPathW), ref funcargs);

            // Update the modified variables
            filePartOut = (IntPtr)funcargs[5];

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
                hProcess,lpSystemInfo
            };

            bool retVal = (bool)Generic.DynamicAPIInvoke(@"kernel32.dll", @"IsWow64Process", typeof(Delegates.IsWow64Process), ref funcargs);

            lpSystemInfo = (bool) funcargs[1];

            // Dynamically load and invoke the API call with out parameters
            return retVal;
        }

        public static class Delegates
        {
            // https://github.com/Tarkiyah/ansible/blob/b0c8e7926f4ed31c37fabfad7803bd378f8aaba4/lib/ansible/module_utils/csharp/Ansible.Process.cs
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate Data.Native.NTSTATUS SearchPathW(
                [MarshalAs(UnmanagedType.LPWStr)] 
                string lpPath,
                [MarshalAs(UnmanagedType.LPWStr)] 
                string lpFileName,
                [MarshalAs(UnmanagedType.LPWStr)] 
                string lpExtension,
                UInt32 nBufferLength,
                [MarshalAs(UnmanagedType.LPTStr)]
                StringBuilder lpBuffer,
                ref IntPtr lpFilePart);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            public delegate IntPtr CreateRemoteThread(
                IntPtr hProcess,
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
