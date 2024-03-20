//#include <afxwin.h>
#include <Windows.h>
#include <atlstr.h>
#include <iostream>
#include "rsa.h"

int main(int argc,char* argv[])
{
    setlocale(LC_ALL, "ru");
    if (argc < 3) { std::cout << "Недостаточно аргументов." << std::endl; return 0; }
    CString filepath = argv[1];
    CString fileout = argv[2];

    std::wcout << L"Выбран файл: " << filepath.GetString() << std::endl;
    std::wcout << L"Файл сохранен в: " << fileout.GetString() << std::endl;

    bool encrypt = true;
    RSA::Keys keys;
    if (argc != 4) {
        char answer = 0;
        std::cout << "Зашифровать/Расшифровать : y/n" << std::endl;
        std::cin >> answer; 
        switch (answer)
        {
        case 'y': encrypt = true; break;
        case 'Y': encrypt = true; break;

        case 'n': encrypt = false; break;
        case 'N': encrypt = false; break;
        default:
            std::cout << "Неопределенный ответ." << std::endl;
            return 0;
            break;
        }
    }
    if (encrypt == false)
    {
        std::cout << "Введите ключи e,d,n: " << std::endl;
        std::cin >> keys.publicKey.e >> keys.privateKey.d >> keys.publicKey.n;
        keys.privateKey.n = keys.publicKey.n;
    }

    HANDLE hFileIn = CreateFile(
        filepath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    HANDLE hFileOut = CreateFile(
        fileout,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    DWORD dwFileSize1 = GetFileSize(hFileIn, NULL);
    DWORD dwFileSize2 = (encrypt) ? 2 * dwFileSize1 : dwFileSize1 / 2;
    
    BYTE* fileBuffer1 = new BYTE[dwFileSize1];
    BYTE* fileBuffer2 = new BYTE[dwFileSize2];

    DWORD dwFileRead1;
    DWORD dwFileWritten2;

    ReadFile(hFileIn, fileBuffer1, dwFileSize1, &dwFileRead1, NULL);

    std::string inputText(dwFileSize1, '\0');
    std::string outputText;

    for (size_t i = 0; i < dwFileSize1; i++)
    {
        inputText[i] = ((char*)fileBuffer1)[i];
    }

    RSA rsa;
    
    switch (encrypt)
    {
    case true:  keys = rsa.GenerateKeys();  outputText = rsa.Encrypt(inputText, keys.publicKey); break;
    case false:                             outputText = rsa.Decrypt(inputText, keys.privateKey); break;
    }

    for (size_t i = 0; i < dwFileSize2; i++)
    {
        fileBuffer2[i] = outputText[i];
    }

    WriteFile(hFileOut, fileBuffer2, dwFileSize2, &dwFileWritten2, NULL);

    std::cout << "\tКлючи:" << std::endl;
    std::cout << "Открытые ключи: e = " << keys.publicKey.e << " n = " << keys.publicKey.n << std::endl;
    std::cout << "Закрытые ключи: d = " << keys.privateKey.d << " n = " << keys.privateKey.n << std::endl;



    CloseHandle(hFileIn);
    CloseHandle(hFileOut);

    delete[] fileBuffer1;
    delete[] fileBuffer2;

    return 0;
}
