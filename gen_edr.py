import os

typedef = '''
typedef NTSTATUS(NTAPI* NtDelayExecution_t)(BOOL Alertable, PLARGE_INTEGER DelayInterval);
typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
typedef NTSTATUS(NTAPI* NtResumeThread_t)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI* NtCreateThreadEx_t)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);
typedef NTSTATUS(NTAPI* NtGetContextThread_t)(HANDLE ThreadHandle, PCONTEXT ThreadContext);
typedef NTSTATUS(NTAPI* NtSetContextThread_t)(HANDLE ThreadHandle, PCONTEXT ThreadContext);
typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesRead);
typedef NTSTATUS(NTAPI* NtQueueApcThread_t)(HANDLE ThreadHandle, PIO_APC_ROUTINE ApcRoutine, PVOID ApcRoutineContext, PIO_STATUS_BLOCK ApcStatusBlock, ULONG ApcReserved);
typedef NTSTATUS(NTAPI* NtAlertResumeThread_t)(HANDLE ThreadHandle, PULONG SuspendCount);
typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
'''

#A ajouter
'''


typedef NTSTATUS(NTAPI* NtClose_t)(HANDLE Handle);
typedef NTSTATUS(NTAPI* NtOpenProcess_t)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
typedef NTSTATUS(NTAPI* NtWaitForSingleObject_t)(HANDLE ObjectHandle, BOOLEAN Alertable, PLARGE_INTEGER TimeOut);
typedef NTSTATUS(NTAPI* NtOpenSection_t)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
'''

def parse_typedef():
    parse = typedef.replace("typedef NTSTATUS(NTAPI* ","").split("\n")[1:-1]
    for i in range(len(parse)):
        parse[i] = parse[i].split(")(")
        parse[i][0] = parse[i][0][:-2]
        parse[i][1] = parse[i][1][:-2].split(", ")
    return parse

parse = parse_typedef()


template = '''
#include <windows.h>
#include <iostream>
#include <vector>
#include <ntstatus.h>
#include <ntdef.h>
#include <winnt.h>
#include <winternl.h>

Replace_TYPEDEF

Replace_PTRDEF

Replace_BYTEBUFF

std::string GetExecutableNameFromPath(const std::string& fullPath) {
    size_t lastSlashPos = fullPath.find_last_of("\\\\/");
    if (lastSlashPos != std::string::npos) {
        return fullPath.substr(lastSlashPos + 1);
    }
    return fullPath;
}

void sendMessage(char* functionName){
    // Get the process name and PID
    char processName[MAX_PATH];
    DWORD processId = GetCurrentProcessId();
    GetModuleFileNameA(NULL, processName, MAX_PATH);
    std::string executableName = GetExecutableNameFromPath(processName);
    // Send the message through the named pipe to the injector process
    HANDLE pipe;
    LPCSTR pipeName = "\\\\\\\\.\\\\pipe\\\\my_named_pipe";
    pipe = CreateNamedPipeA(pipeName, PIPE_ACCESS_OUTBOUND, PIPE_TYPE_BYTE, 1, 0, 0, 0, NULL);
    // Connect to the named pipe
    ConnectNamedPipe(pipe, NULL);
    // Write data to the named pipe
    std::string message = executableName + " (PID: " + std::to_string(processId) + ") - " + functionName +" called!";
    DWORD bytesWritten;
    WriteFile(pipe, message.c_str(), static_cast<DWORD>(message.size()) + 1, &bytesWritten, NULL);
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
}


Replace_HookedFUNCTIONS

void HookNtFunctions() {

    HMODULE hNtdll = GetModuleHandle("ntdll.dll");
    if (hNtdll != NULL) {

        Replace_Hooking
    }
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        HookNtFunctions();
    }
    return TRUE;
}


'''




def parse_typedef():
    parse = typedef.replace("typedef NTSTATUS(NTAPI* ","").split("\n")[1:-1]
    for i in range(len(parse)):
        parse[i] = parse[i].split(")(")
        parse[i][0] = parse[i][0][:-2]
        parse[i][1] = parse[i][1][:-2].split(", ")
    return parse

parse = parse_typedef()

def replace_ptrdef():
    model = "FuncName_t OriginalFuncName = nullptr;\n" 
    tmp = ""
    for func in parse:
       tmp += model.replace("FuncName",func[0])
    return tmp

def replace_bytebuff():
    model = "BYTE ByteFuncName[5] = {0};\n" 
    tmp = ""
    for func in parse:
       tmp += model.replace("FuncName",func[0])
    return tmp

def replace_hooking():
    model = '''
    OriginalFuncName = reinterpret_cast<FuncName_t>(GetProcAddress(hNtdll, "FuncName"));
    if (OriginalFuncName != nullptr) {
        DWORD oldProtect;
        VirtualProtect(OriginalFuncName, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(ByteFuncName, reinterpret_cast<void*>(OriginalFuncName), 5);
        // Hooking the function
        memcpy(reinterpret_cast<void*>(OriginalFuncName), "\\xE9\\x00\\x00\\x00\\x00", 5);
        DWORD hookOffset = reinterpret_cast<DWORD>(HookedFuncName) - reinterpret_cast<DWORD>(OriginalFuncName) - 5;
        memcpy(reinterpret_cast<void*>(OriginalFuncName + 1), &hookOffset, sizeof(hookOffset));

    } 
    '''
    tmp = ""
    for func in parse:
       tmp += model.replace("FuncName",func[0])
    return tmp

def replace_hookedfunc():
    model = '''
NTSTATUS NTAPI HookedFuncName(ARG1) {
    // Send the message through the named pipe to the injector process
    sendMessage("FuncName");

    // Restore the original bytes
    memcpy(reinterpret_cast<void*>(OriginalFuncName), ByteFuncName, 5);
    // Call the original FuncName function
    NTSTATUS result = OriginalFuncName(ARG2);
    // Reapply the hook
    memcpy(reinterpret_cast<void*>(OriginalFuncName), "\\xE9\\x00\\x00\\x00\\x00", 5);
    DWORD hookOffset = reinterpret_cast<DWORD>(HookedFuncName) - reinterpret_cast<DWORD>(OriginalFuncName) - 5;
    memcpy(reinterpret_cast<void*>(OriginalFuncName + 1), &hookOffset, sizeof(hookOffset));
    return result;
}
    '''
    tmp = ""
    for func in parse:
       tmp += model.replace("FuncName",func[0])
       arg1 = ""
       arg2 = ""
       for arg in func[1]:
           arg1 += arg + ", "
           arg2 += arg.split(" ")[1] + ", "
       arg1 = arg1[:-2]
       arg2 = arg2[:-2]
       tmp = tmp.replace("ARG1",arg1)
       tmp = tmp.replace("ARG2",arg2)
    return tmp





template = template.replace("Replace_TYPEDEF",typedef)
template = template.replace("Replace_PTRDEF",replace_ptrdef())
template = template.replace("Replace_BYTEBUFF",replace_bytebuff())
template = template.replace("Replace_Hooking",replace_hooking())
template = template.replace("Replace_HookedFUNCTIONS",replace_hookedfunc())


open("edrv1.cpp",'w').write(template)
print("[+] Generated edrv1.cpp")
print("[+] Compiling to edr.dll")
os.system("x86_64-w64-mingw32-g++ edrv1.cpp -s -w -std=c++17 -masm=intel -fpermissive -static -lntdll -lpsapi -Wl,--subsystem,console -shared -o edr.dll")
