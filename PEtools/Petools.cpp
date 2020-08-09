#include<windows.h>
#include"iostream"

#define DOS "-d"
#define PE "-p"

//虚拟地址转文件地址
DWORD Rva2Fva(DWORD dwRva, PIMAGE_NT_HEADERS pNT) {
	//由于解析方式是将PE文件加载到了内存， 而文件中的偏移是文件偏移
	//需要将RVA转为文件偏移，才能在文件PE中定位相关数据
	PIMAGE_SECTION_HEADER pSe = IMAGE_FIRST_SECTION(pNT);
	for (int i = 0; i < pNT->FileHeader.NumberOfSections; i++) {
		//判断是否在某个区段内
		if (dwRva >= pSe[i].VirtualAddress&&
			dwRva <= pSe[i].VirtualAddress + pSe[i].SizeOfRawData){
			return dwRva - pSe[i].VirtualAddress + pSe[i].PointerToRawData;
		}
	}
}
//读取PE文件到内存
PBYTE ReadPEFile(char* PE_path) {
	// 文件路径数据类型转换
	int num = MultiByteToWideChar(0, 0, PE_path, -1, NULL, 0);
	wchar_t *wide = new wchar_t[num];
	MultiByteToWideChar(0, 0, PE_path, -1, wide, num);
	//printf("%ls\n", wide);

	//打开PE文件
	HANDLE hfile = CreateFile(
		wide,
		GENERIC_READ,
		NULL,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hfile == INVALID_HANDLE_VALUE) {
		printf("打开文件失败：%d", GetLastError());
		return NULL;
	}
	DWORD  dwSize = GetFileSize(hfile, NULL);
	//printf("文件大小: %d\n", dwSize);

	//申请缓冲区， 并将PE文件读取到内存
	PBYTE peBuf = new BYTE[dwSize]{};
	if (!ReadFile(hfile, peBuf, dwSize, &dwSize, NULL)) {
		printf("读取PE文件到内存失败\n");
		return NULL;
	}
	return peBuf;
}
//获取PE文件DoS头部信息
BOOL get_dos_header(PBYTE pBuf) {
	 //获取PE DOS头部信息
	 PIMAGE_DOS_HEADER pdos = (PIMAGE_DOS_HEADER)pBuf;
	 if (pdos->e_magic != IMAGE_DOS_SIGNATURE) {
		 printf("无效的PE文件\n");
		 return FALSE;
	 }
	 printf("========== PE 文件 DOS头部信息===========\n");
	 printf("e_magic: 0x%2x\n", pdos->e_magic);
	 printf("e_cblp: 0x%02x\n", pdos->e_cblp);
	 printf("e_cp: 0x%02x\n", pdos->e_cp);
	 printf("e_crlc: 0x%02x\n", pdos->e_crlc);
	 printf("e_cparhdr: 0x%02x\n", pdos->e_cparhdr);
	 printf("e_minalloc: 0x%02x\n", pdos->e_minalloc);
	 printf("e_maxalloc: 0x%02x\n", pdos->e_maxalloc);
	 printf("e_ss: 0x%02x\n", pdos->e_ss);
	 printf("e_csum: 0x%02x\n", pdos->e_csum);
	 printf("e_ip: 0x%02x\n", pdos->e_ip);
	 printf("e_cs: 0x%02x\n", pdos->e_cs);
	 printf("e_lfarlc: 0x%02x\n", pdos->e_lfarlc);
	 printf("e_ovno: 0x%02x\n", pdos->e_ovno);
	 printf("e_res: 0x%04x\n", pdos->e_res);
	 printf("e_oemid: 0x%02x\n", pdos->e_oemid);
	 printf("e_oeminfo: 0x%02x\n", pdos->e_oeminfo);
	 printf("e_res2: 0x%02x\n", pdos->e_res2);
	 printf("e_lfanew: 0x%04x\n", pdos->e_lfanew);
	 return TRUE;
}
//获取PE头信息
BOOL get_pe_header(PBYTE pBuf) {
	//获取NT头首地址
	PIMAGE_DOS_HEADER pdos = (PIMAGE_DOS_HEADER)pBuf;
	PIMAGE_NT_HEADERS  pheader = (PIMAGE_NT_HEADERS)(pBuf + pdos->e_lfanew);
	printf("========== PE 文件 NT头部信息===========\n");

	// 获取NT头Signature字段
	DWORD p_header = pheader->Signature;
	if (p_header != IMAGE_NT_SIGNATURE) {
		printf("不是有效的PE文件\n");
		return FALSE;
	}
	printf("NT 头Signature： 0x%2x\n", pheader->Signature);
	printf("NT 头FileHeader： 0x%2x\n", pheader->FileHeader);
	printf("NT 头OptionalHeader： 0x%2x\n", pheader->OptionalHeader);


	//获取NT文件头
	PIMAGE_FILE_HEADER pFile = &pheader->FileHeader;
	printf("\n文件头信息：\n");
	printf("Machine： 0x%2x\n", pFile->Machine);
	printf("NumberOfSections： %d\n", pFile->NumberOfSections);
	printf("TimeDateStamp： 0x%2x\n", pFile->TimeDateStamp);
	printf("PointerToSymbolTable： 0x%2x\n", pFile->PointerToSymbolTable);
	printf("NumberOfSymbols： 0x%2x\n", pFile->NumberOfSymbols);
	printf("SizeOfOptionalHeader： 0x%2x\n", pFile->SizeOfOptionalHeader);
	printf("Characteristics： 0x%2x\n", pFile->Characteristics);
	

	//获取NT扩展头信息
	//32微程序PIMAGE_OPTIONAL_HEADER32
	//64位程序PIMAGE_OPTIONAL_HEADER64 两者在结构上存在些许差异
	PIMAGE_OPTIONAL_HEADER pOption = &pheader->OptionalHeader;
	printf("\n扩展头信息：\n");
	printf("Magic： 0x%2x\n", pOption->Magic );
	printf("MajorLinkerVersion： %d\n", pOption->MajorLinkerVersion);
	printf("MinorLinkerVersion： %d\n", pOption->MinorLinkerVersion);
	printf("SizeOfCode： 0x%2x\n", pOption->SizeOfCode);
	printf("SizeOfInitializedData： %d\n", pOption->SizeOfInitializedData);
	printf("SizeOfUninitializedData： %d\n", pOption->SizeOfUninitializedData);
	printf("AddressOfEntryPoint： 0x%2x\n", pOption->AddressOfEntryPoint);
	printf("BaseOfCode： 0x%2x\n", pOption->BaseOfCode);
	printf("BaseOfData： 0x%2x\n", pOption->BaseOfData);
	printf("ImageBase： 0x%2x\n", pOption->ImageBase);
	printf("SectionAlignment： 0x%2x\n", pOption->SectionAlignment);
	printf("FileAlignment： 0x%2x\n", pOption->FileAlignment);
	printf("MajorOperatingSystemVersion： %d\n", pOption->MajorOperatingSystemVersion);
	printf("MinorOperatingSystemVersion： %d\n", pOption->MinorOperatingSystemVersion);
	printf("MajorSubsystemVersion： %d\n", pOption->MajorSubsystemVersion);
	printf("MinorSubsystemVersion： %d\n", pOption->MinorSubsystemVersion);
	printf("Win32VersionValue： %d\n", pOption->Win32VersionValue);
	printf("SizeOfImage： 0x%2x\n", pOption->SizeOfImage);
	printf("SizeOfHeaders： 0x%2x\n", pOption->SizeOfHeaders);
	printf("CheckSum： 0x%2x\n", pOption->CheckSum);
	printf("Subsystem： 0x%2x\n", pOption->Subsystem);
	printf("DllCharacteristics： 0x%2x\n", pOption->DllCharacteristics);
	printf("SizeOfStackReserve： 0x%2x\n", pOption->SizeOfStackCommit);
	printf("SizeOfStackCommit： 0x%2x\n", pOption->SizeOfStackCommit);
	printf("SizeOfHeapReserve： 0x%2x\n", pOption->SizeOfStackReserve);
	printf("SizeOfHeapCommit： 0x%2x\n", pOption->SizeOfHeapCommit);
	printf("LoaderFlags： 0x%2x\n", pOption->LoaderFlags);
	printf("NumberOfRvaAndSizes： 0x%2x\n", pOption->NumberOfRvaAndSizes);

	//数据目录表信息
	PIMAGE_DATA_DIRECTORY pdir = pOption->DataDirectory;
	printf("\n数据目录表信息：%d\n", pOption->NumberOfRvaAndSizes);
	for (DWORD i=0 ;i<pOption->NumberOfRvaAndSizes;i++)
	{
		printf("区段%d 的RVA: %08x, 大小： %08x\n", i, pdir[i].VirtualAddress, pdir[i].Size);
	}

	return TRUE;
}
//获取节表信息
VOID  get_section_header(PBYTE pBuf) {
	//获取NT头首地址
	PIMAGE_DOS_HEADER pdos = (PIMAGE_DOS_HEADER)pBuf;
	PIMAGE_NT_HEADERS  pheader = (PIMAGE_NT_HEADERS)(pBuf + pdos->e_lfanew);

	//获取NT文件头
	PIMAGE_FILE_HEADER pFileHeader = &pheader->FileHeader;

	//区段信息表
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pheader);

	char pName[9] = {};
	printf("%8s|%8s|%8s|%8s|%8s|%8s|%8s\n\n", " 区段名 ", " 内存地址 ", " 内存大小 ", " 文件偏移 ", " 文件大小 ","重定位表偏移", "重定位表项数");
	//printf("\n");
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		//拷贝区段名
		memcpy_s(pName, 9, &pSec[i].Name, 8);
		printf("%8s  ", pName);
		//内存中的RVA和大小
		printf("%08x  ", pSec[i].VirtualAddress);
		printf("%08x  ", pSec[i].Misc.VirtualSize);
		//文件中的偏移和大小
		printf("%08x   ", pSec[i].PointerToRawData);
		printf("%08x   ", pSec[i].SizeOfRawData);
		//重定位信息
		printf("%08x   ", pSec[i].PointerToRelocations);
		printf("%08d   \n", pSec[i].NumberOfRelocations);
	}
}
//导入表信息
VOID get_import(PBYTE  pBuf) {
	//数据目录表的位置：NT头扩展文件头数据目录表的第二个项目
	PIMAGE_DOS_HEADER pDos = PIMAGE_DOS_HEADER(pBuf);
	PIMAGE_NT_HEADERS pNT = PIMAGE_NT_HEADERS(pBuf + pDos->e_lfanew);

	//数据目录表地址
	PIMAGE_DATA_DIRECTORY pDirectory = pNT->OptionalHeader.DataDirectory;

	//导入表的地址
	DWORD dwImportRva = pDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD dwImportSize = pDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	//printf("导入表RVA:0x%02x, 大小： %d\n", dwImportRva, dwImportSize);
	printf("\n=================导入函数信息===============\n\n");
	PIMAGE_IMPORT_DESCRIPTOR pImport1= (PIMAGE_IMPORT_DESCRIPTOR)(pBuf + Rva2Fva(dwImportRva, pNT));
	PIMAGE_IMPORT_DESCRIPTOR pImport2 = (PIMAGE_IMPORT_DESCRIPTOR)(pBuf + Rva2Fva(dwImportRva, pNT));
	//printf("Import Address: 0x%2x\n", Rva2Fva(dwImportRva, pNT));
	while (pImport1->Name)
	{
		//DLL名称  INT数组的RVA   IAT数组的RVA
		printf("导入dll的名称：%s\n", pBuf + Rva2Fva(pImport1->Name, pNT));
		//printf("INT数组的首地址RVA：%08x\n", Rva2Fva(pImport->OriginalFirstThunk, pNT));
		//printf("IAT数组的首地址RVA：%08x\n", Rva2Fva(pImport->FirstThunk, pNT));
		pImport1++;
	}
	printf("\n******各Dll详细信息*********\n");
	while (pImport2->Name)
	{
		//DLL名称  INT数组的RVA   IAT数组的RVA
		printf("\n导入dll的名称：%s\n", pBuf + Rva2Fva(pImport2->Name, pNT));
		//printf("INT数组的首地址RVA：%08x\n", Rva2Fva(pImport->OriginalFirstThunk, pNT));
		//printf("IAT数组的首地址RVA：%08x\n", Rva2Fva(pImport->FirstThunk, pNT));
		PIMAGE_THUNK_DATA32 pThunk = (PIMAGE_THUNK_DATA32)(pBuf + Rva2Fva(pImport2->OriginalFirstThunk, pNT));
		while (pThunk->u1.AddressOfData)
		{
			//如果是按照序号导入
			if (IMAGE_SNAP_BY_ORDINAL32(pThunk->u1.Ordinal))
			{
				printf("	|----序号： %04x\n", IMAGE_ORDINAL32(pThunk->u1.Ordinal));
			}
			//如果是按照名称导入
			else {
				PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(pBuf + Rva2Fva(pThunk->u1.AddressOfData, pNT));
				printf("	|----序号： %04x|---函数名： %s\n", pName->Hint, pName->Name);
			}
			pThunk++;

		}
		pImport2++;
	}

	//输入地址表
	IMAGE_THUNK_DATA x;
	IMAGE_IMPORT_BY_NAME;

}
//导出表
VOID get_Export(PBYTE pBuf) {
	//数据目录表的位置：NT头扩展文件头数据目录表的第二个项目
	PIMAGE_DOS_HEADER pDos = PIMAGE_DOS_HEADER(pBuf);
	PIMAGE_NT_HEADERS pNT = PIMAGE_NT_HEADERS(pBuf + pDos->e_lfanew);

	//数据目录表地址
	PIMAGE_DATA_DIRECTORY pDirectory = pNT->OptionalHeader.DataDirectory;
	DWORD dwExportRva = pDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pBuf + Rva2Fva(dwExportRva, pNT));
	printf("==================================================\n");
	printf("DLL名称：%s \n\n", pBuf + Rva2Fva(pExport->Name, pNT));
	printf("导出函数索引基数:%d\n", pExport->Base);
	printf("ENT个数: %2d\n", pExport->NumberOfFunctions);
	printf("ENT的RVA: 0x%2x\n", pExport->AddressOfFunctions);
	printf("EAT个数: %2d\n", pExport->NumberOfNames);
	printf("EAT的RVA: 0x%2x\n", pExport->AddressOfNames);
	printf("到处序号表的RVA: 0x%2x\n", pExport->AddressOfNameOrdinals);
	printf("==================================================\n\n");

	PWORD pOrder = (PWORD)(pBuf + Rva2Fva(pExport->AddressOfNameOrdinals, pNT));
	PDWORD pArrName = (PDWORD)(pBuf + Rva2Fva(pExport->AddressOfNames, pNT));
	PDWORD pArrDrr = (PDWORD)(pBuf + Rva2Fva(pExport->AddressOfFunctions, pNT));
	for (int i = 0; i < pExport->NumberOfFunctions; i++) {
		printf("函数序号：%04x  函数地址：%08x    ", pExport->Base + i, pArrDrr[i]);
		bool bind = false;
		for (int j = 0; j < pExport->NumberOfNames; j++) {
			if (pOrder[j] == i) {
				printf("%s\n", pBuf + (Rva2Fva(pArrName[j], pNT)));
				bind = TRUE;
			}
		}
		if (!bind) {
			printf("没有名称\n\n");
		}
	}
}
//帮助说明
void help() {
	printf("PEtools V1.0.0 For PE file Analysis\n");
	printf("Copyright 2020-08-01 0xCC\n");
	printf("By zqq <1597048403@qq.com>\n\n");
	printf("usage: PEtools <PE_file_path> [option]\n\n");
	printf("PE_file_path:    the absolute path of PE to analysis\n\n");
	printf("option: \n");
	printf("	-d:     get IMAGE_DOS_HEADER Stracture data\n");
	printf("	-p:     get IMAGE_NT_HEADER Stracture data\n");
	printf("	-s:     get IMAGE_SECTION_HEADER Stracture data\n");
	printf("	-i:     get IMAGE_IMPORT_DESCRIPTOR Stracture data\n");
	printf("	-o:     get IMAGE_EXPORT_DESCRIPTOR Stracture data\n");
// 	printf("usage: PEtools\n");
// 	printf("usage: PEtools\n");

}

int main(int argc, char *argv[]) {

	if (argc <=2)
	{
		help();
		return -1;
	}
	else
	{
		PBYTE PEbuf = ReadPEFile(argv[1]);
		//printf("PEBuf: %2x\n", PEbuf);
		if (PEbuf !=NULL) {
			char* options = argv[2];
			byte types = options[1];
			//printf("options: %s\n", options);
			//printf("options: %c\n", types);
			switch (types)
			{
			case 'd':
			{
				get_dos_header(PEbuf);
				break;
			};
			case 'p':
			{
				get_pe_header(PEbuf);
				break;
			}
			case 's':
			{
				get_section_header(PEbuf);
				break;
			}
			case 'i':
			{
				get_import(PEbuf);
				break;
			}
			case 'o':
			{
				get_Export(PEbuf);
				break;
			}
			case 'h':
			{
				help();
				break;
			}
			default:
				help();
				break;
			}

		}
		
	}
}

