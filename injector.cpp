#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <psapi.h>
#include <set>



//const char* DLL_PATH = "edr.dll";
const char* DLL_PATH = "edr.dll";
const char* TARGET_PROCESS_NAME ;



void sendMessage(std::string message){
    HANDLE pipe;
    LPCSTR pipeName = "\\\\.\\pipe\\my_named_pipe";
    pipe = CreateNamedPipeA(pipeName, PIPE_ACCESS_OUTBOUND, PIPE_TYPE_BYTE, 1, 0, 0, 0, NULL);
    // Connect to the named pipe
    ConnectNamedPipe(pipe, NULL);
    // Write data to the named pipe
    DWORD bytesWritten;
    WriteFile(pipe, message.c_str(), static_cast<DWORD>(message.size()) + 1, &bytesWritten, NULL);
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
}






bool InjectDLL(DWORD processId, const char* dllPath) {
    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL) {
        std::cerr << "Failed to open the target process with PID: " << processId << std::endl;
        return false;
    }

    // Allocate memory in the target process for the DLL path
    LPVOID dllPathAddr = VirtualAllocEx(hProcess, nullptr, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (dllPathAddr == nullptr) {
        std::cerr << "Failed to allocate memory in the target process." << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Write the DLL path into the target process
    if (!WriteProcessMemory(hProcess, dllPathAddr, dllPath, strlen(dllPath) + 1, nullptr)) {
        std::cerr << "Failed to write the DLL path into the target process." << std::endl;
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Get the address of the LoadLibrary function
    LPVOID loadLibraryAddr = reinterpret_cast<LPVOID>(GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"));
    if (loadLibraryAddr == nullptr) {
        std::cerr << "Failed to retrieve the address of LoadLibrary." << std::endl;
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Create a remote thread in the target process to load the DLL
    HANDLE remoteThread = CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryAddr), dllPathAddr, 0, nullptr);
    if (remoteThread == nullptr) {
        std::cerr << "Failed to create a remote thread in the target process." << std::endl;
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Wait for the remote thread to complete
    WaitForSingleObject(remoteThread, INFINITE);

    // Clean up resources
    VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
    CloseHandle(remoteThread);
    CloseHandle(hProcess);

    return true;
}




int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <process name> [process name 2] [process name 3] ..." << std::endl;
        return 1;
    }


    //for colored texts
    HANDLE hstdout = GetStdHandle(STD_OUTPUT_HANDLE);
    //Legend


    HANDLE pipe;
    LPCSTR pipeName = "\\\\.\\pipe\\my_named_pipe";
    char buffer[256];

    //keep track of already injected process
    std::set<DWORD> injectedProcesses;


    while (true) {


        // Enumerate processes
        DWORD processIds[1024];
        DWORD bytesReturned;
        if (!EnumProcesses(processIds, sizeof(processIds), &bytesReturned)) {
            std::cerr << "Failed to enumerate processes." << std::endl;
            return 1;
        }

        // Calculate the number of processes
        DWORD numProcesses = bytesReturned / sizeof(DWORD);

        for (int i = 1; i < argc; i++) {
            const char* TARGET_PROCESS_NAME = argv[i];

            // Iterate over processes and inject the DLL into the target process
            for (DWORD i = 0; i < numProcesses; i++) {
                // Check if the process has already been injected
                if (injectedProcesses.find(processIds[i]) != injectedProcesses.end()) {
                    continue;
                }
                
                // Open the process
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processIds[i]);
                if (hProcess != NULL) {
                    char processName[MAX_PATH];
                    if (GetModuleFileNameExA(hProcess, nullptr, processName, MAX_PATH)) {
                        std::string name(processName);

                        // Check if the process name matches the target process name
                        if (name.find(TARGET_PROCESS_NAME) != std::string::npos) {
                            //Inject the DLL into the target process
                            if (InjectDLL(processIds[i], "syscall-detect.dll")) {
                                injectedProcesses.insert(processIds[i]);
                                SetConsoleTextAttribute(hstdout, 0xE5);
                                std::string message = "syscall detect DLL injected into process with PID: " + std::to_string(processIds[i]);
                                sendMessage(message);
                                std::cout << "syscall detect DLL injected into process with PID: " << processIds[i] << std::endl;
                                SetConsoleTextAttribute(hstdout, 0x5F);
                            } else {
                                std::cerr << "Failed to inject syscall detect DLL into process with PID: " << processIds[i] << std::endl;
                            }
                            if (InjectDLL(processIds[i], DLL_PATH)) {
                                injectedProcesses.insert(processIds[i]);
                                SetConsoleTextAttribute(hstdout, 0xE5);
                                std::string message = "DLL injected into process with PID: " + std::to_string(processIds[i]);
                                sendMessage(message);
                                std::cout << "DLL injected into process with PID: " << processIds[i] << std::endl;
                                SetConsoleTextAttribute(hstdout, 0x5F);
                            } else {
                                std::cerr << "Failed to inject DLL into process with PID: " << processIds[i] << std::endl;
                            }
                        }
                    }
                    // Close the process handle
                    CloseHandle(hProcess);
                }
            }
        }



        






        // Delay for some time before checking for new processes again
        //Sleep(500); 
    }

    return 0;
}
