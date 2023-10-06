#include <iostream>
#include <string>
#include <Windows.h>

int main()
{
    // Variables
    DWORD pID = 0;
    std::string dllPath;

    std::cout << "Enter DLL path: " << std::endl;
    std::getline(std::cin, dllPath);

    std::cout << "Enter target process ID: " << std::endl;
    std::cin >> pID;

    // 1. Get a handle to the target process with limited access rights
    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pID);
    if (!hProc) {
        std::cerr << "Failed to get process handle: " << GetLastError() << std::endl;
        return 1;
    }

    // 2. Allocate memory in the target process to store the DLL path
    LPVOID pAllocMemory = VirtualAllocEx(hProc, nullptr, dllPath.size() + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!pAllocMemory) {
        std::cerr << "Failed to allocate memory in remote process: " << GetLastError() << std::endl;
        CloseHandle(hProc);
        return 1;
    }

    // 3. Write the DLL path to the allocated memory in the target process
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProc, pAllocMemory, dllPath.c_str(), dllPath.size() + 1, &bytesWritten) || bytesWritten != dllPath.size() + 1) {
        std::cerr << "Failed to write DLL path to remote process memory: " << GetLastError() << std::endl;
        VirtualFreeEx(hProc, pAllocMemory, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    // 4. Call LoadLibraryA in the target process to load the DLL
    LPTHREAD_START_ROUTINE loadLibraryAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA");
    HANDLE hRemoteThread = CreateRemoteThread(hProc, nullptr, 0, loadLibraryAddr, pAllocMemory, 0, nullptr);
    if (!hRemoteThread) {
        std::cerr << "Failed to create remote thread: " << GetLastError() << std::endl;
        VirtualFreeEx(hProc, pAllocMemory, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return 1;
    }

    // Wait for the remote thread to complete
    WaitForSingleObject(hRemoteThread, INFINITE);

    std::cout << "Dll path allocated at: " << std::hex << pAllocMemory << std::endl;
    std::cin.get();

    // Cleanup
    CloseHandle(hRemoteThread);
    VirtualFreeEx(hProc, pAllocMemory, 0, MEM_RELEASE);
    CloseHandle(hProc);

    return 0;
}