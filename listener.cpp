#include <windows.h>
#include <stdio.h>
#include <iostream>

HANDLE pipe;
LPCSTR pipeName = "\\\\.\\pipe\\my_named_pipe";
char buffer[256];


int main()
{
    //for colored texts
    HANDLE hstdout = GetStdHandle(STD_OUTPUT_HANDLE);
    //Legend
    std::cout << "------------------------------------------------------------------" << std::endl;
    
    SetConsoleTextAttribute(hstdout, 0xEC);
    std::cout << "DLL injected into process successfully" << std::endl;
    SetConsoleTextAttribute(hstdout, 0x5A);
    std::cout << "memory manipulation functions in green" << std::endl;
    SetConsoleTextAttribute(hstdout, 0x5E);
    std::cout << "enum and delay functions for potential sandbox evasion in yellow" << std::endl;
    SetConsoleTextAttribute(hstdout, 0x5D);
    std::cout << "thread related functions in magenta " << std::endl;
    SetConsoleTextAttribute(hstdout, 0x5F);
    std::cout << "------------------------------------------------------------------" << std::endl;

    while (true){
        pipe = CreateFileA(pipeName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL );
        DWORD bytesRead;
        ReadFile(pipe, buffer, sizeof(buffer), &bytesRead, NULL);
        if (bytesRead>0){
            buffer[bytesRead] = '\0';  // Null-terminate the buffer
            std::string str;
            str.assign(buffer);

            //memory manipulation functions in green
            if (str.find("Memory") <str.length()){
                SetConsoleTextAttribute(hstdout, 0x5A);
                std::cout << buffer << std::endl;
                SetConsoleTextAttribute(hstdout, 0x5F);
            //enum and delay functions for potential sandbox evasion in yellow
            }else if (str.find("Query") <str.length() || str.find("Delay") <str.length()){
                SetConsoleTextAttribute(hstdout, 0x5E);
                std::cout << buffer << std::endl;
                SetConsoleTextAttribute(hstdout, 0x5F);
            //thread related functions in magenta
            }else if (str.find("Thread") <str.length()){
                SetConsoleTextAttribute(hstdout, 0x5D);
                std::cout << buffer << std::endl;
                SetConsoleTextAttribute(hstdout, 0x5F);
            //Suspicious kernel callback
            }else if (str.find("Kernel") <str.length()){
                SetConsoleTextAttribute(hstdout, 0x7C);
                std::cout << buffer << std::endl;
                SetConsoleTextAttribute(hstdout, 0x5F);
            //Injected dll
            }else if (str.find("injected") <str.length()){
                SetConsoleTextAttribute(hstdout, 0xEC);
                std::cout << buffer << std::endl;
                SetConsoleTextAttribute(hstdout, 0x5F);

            }else{
                std::cout << buffer << std::endl;
            }

        }
    }

   return 0;
}