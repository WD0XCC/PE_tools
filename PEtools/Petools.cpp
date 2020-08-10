#include<windows.h>
#include"iostream"

#define DOS "-d"
#define PE "-p"

//�����ַת�ļ���ַ
DWORD Rva2Fva(DWORD dwRva, PIMAGE_NT_HEADERS pNT) {
	//���ڽ�����ʽ�ǽ�PE�ļ����ص����ڴ棬 ���ļ��е�ƫ�����ļ�ƫ��
	//��Ҫ��RVAתΪ�ļ�ƫ�ƣ��������ļ�PE�ж�λ�������
	PIMAGE_SECTION_HEADER pSe = IMAGE_FIRST_SECTION(pNT);
	for (int i = 0; i < pNT->FileHeader.NumberOfSections; i++) {
		//�ж��Ƿ���ĳ��������
		if (dwRva >= pSe[i].VirtualAddress&&
			dwRva <= pSe[i].VirtualAddress + pSe[i].SizeOfRawData){
			return dwRva - pSe[i].VirtualAddress + pSe[i].PointerToRawData;
		}
	}
}
//��ȡPE�ļ����ڴ�
PBYTE ReadPEFile(char* PE_path) {
	// �ļ�·����������ת��
	int num = MultiByteToWideChar(0, 0, PE_path, -1, NULL, 0);
	wchar_t *wide = new wchar_t[num];
	MultiByteToWideChar(0, 0, PE_path, -1, wide, num);
	//printf("%ls\n", wide);

	//��PE�ļ�
	HANDLE hfile = CreateFile(
		wide,
		GENERIC_READ,
		NULL,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hfile == INVALID_HANDLE_VALUE) {
		printf("���ļ�ʧ�ܣ�%d", GetLastError());
		return NULL;
	}
	DWORD  dwSize = GetFileSize(hfile, NULL);
	//printf("�ļ���С: %d\n", dwSize);

	//���뻺������ ����PE�ļ���ȡ���ڴ�
	PBYTE peBuf = new BYTE[dwSize]{};
	if (!ReadFile(hfile, peBuf, dwSize, &dwSize, NULL)) {
		printf("��ȡPE�ļ����ڴ�ʧ��\n");
		return NULL;
	}
	return peBuf;
}
//��ȡPE�ļ�DoSͷ����Ϣ
BOOL get_dos_header(PBYTE pBuf) {
	 //��ȡPE DOSͷ����Ϣ
	 PIMAGE_DOS_HEADER pdos = (PIMAGE_DOS_HEADER)pBuf;
	 if (pdos->e_magic != IMAGE_DOS_SIGNATURE) {
		 printf("��Ч��PE�ļ�\n");
		 return FALSE;
	 }
	 printf("========== PE �ļ� DOSͷ����Ϣ===========\n");
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
//��ȡPEͷ��Ϣ
BOOL get_pe_header(PBYTE pBuf) {
	//��ȡNTͷ�׵�ַ
	PIMAGE_DOS_HEADER pdos = (PIMAGE_DOS_HEADER)pBuf;
	PIMAGE_NT_HEADERS  pheader = (PIMAGE_NT_HEADERS)(pBuf + pdos->e_lfanew);
	printf("========== PE �ļ� NTͷ����Ϣ===========\n");

	// ��ȡNTͷSignature�ֶ�
	DWORD p_header = pheader->Signature;
	if (p_header != IMAGE_NT_SIGNATURE) {
		printf("������Ч��PE�ļ�\n");
		return FALSE;
	}
	printf("NT ͷSignature�� 0x%2x\n", pheader->Signature);
	printf("NT ͷFileHeader�� 0x%2x\n", pheader->FileHeader);
	printf("NT ͷOptionalHeader�� 0x%2x\n", pheader->OptionalHeader);


	//��ȡNT�ļ�ͷ
	PIMAGE_FILE_HEADER pFile = &pheader->FileHeader;
	printf("\n�ļ�ͷ��Ϣ��\n");
	printf("Machine�� 0x%2x\n", pFile->Machine);
	printf("NumberOfSections�� %d\n", pFile->NumberOfSections);
	printf("TimeDateStamp�� 0x%2x\n", pFile->TimeDateStamp);
	printf("PointerToSymbolTable�� 0x%2x\n", pFile->PointerToSymbolTable);
	printf("NumberOfSymbols�� 0x%2x\n", pFile->NumberOfSymbols);
	printf("SizeOfOptionalHeader�� 0x%2x\n", pFile->SizeOfOptionalHeader);
	printf("Characteristics�� 0x%2x\n", pFile->Characteristics);
	

	//��ȡNT��չͷ��Ϣ
	//32΢����PIMAGE_OPTIONAL_HEADER32
	//64λ����PIMAGE_OPTIONAL_HEADER64 �����ڽṹ�ϴ���Щ�����
	PIMAGE_OPTIONAL_HEADER pOption = &pheader->OptionalHeader;
	printf("\n��չͷ��Ϣ��\n");
	printf("Magic�� 0x%2x\n", pOption->Magic );
	printf("MajorLinkerVersion�� %d\n", pOption->MajorLinkerVersion);
	printf("MinorLinkerVersion�� %d\n", pOption->MinorLinkerVersion);
	printf("SizeOfCode�� 0x%2x\n", pOption->SizeOfCode);
	printf("SizeOfInitializedData�� %d\n", pOption->SizeOfInitializedData);
	printf("SizeOfUninitializedData�� %d\n", pOption->SizeOfUninitializedData);
	printf("AddressOfEntryPoint�� 0x%2x\n", pOption->AddressOfEntryPoint);
	printf("BaseOfCode�� 0x%2x\n", pOption->BaseOfCode);
	printf("BaseOfData�� 0x%2x\n", pOption->BaseOfData);
	printf("ImageBase�� 0x%2x\n", pOption->ImageBase);
	printf("SectionAlignment�� 0x%2x\n", pOption->SectionAlignment);
	printf("FileAlignment�� 0x%2x\n", pOption->FileAlignment);
	printf("MajorOperatingSystemVersion�� %d\n", pOption->MajorOperatingSystemVersion);
	printf("MinorOperatingSystemVersion�� %d\n", pOption->MinorOperatingSystemVersion);
	printf("MajorSubsystemVersion�� %d\n", pOption->MajorSubsystemVersion);
	printf("MinorSubsystemVersion�� %d\n", pOption->MinorSubsystemVersion);
	printf("Win32VersionValue�� %d\n", pOption->Win32VersionValue);
	printf("SizeOfImage�� 0x%2x\n", pOption->SizeOfImage);
	printf("SizeOfHeaders�� 0x%2x\n", pOption->SizeOfHeaders);
	printf("CheckSum�� 0x%2x\n", pOption->CheckSum);
	printf("Subsystem�� 0x%2x\n", pOption->Subsystem);
	printf("DllCharacteristics�� 0x%2x\n", pOption->DllCharacteristics);
	printf("SizeOfStackReserve�� 0x%2x\n", pOption->SizeOfStackCommit);
	printf("SizeOfStackCommit�� 0x%2x\n", pOption->SizeOfStackCommit);
	printf("SizeOfHeapReserve�� 0x%2x\n", pOption->SizeOfStackReserve);
	printf("SizeOfHeapCommit�� 0x%2x\n", pOption->SizeOfHeapCommit);
	printf("LoaderFlags�� 0x%2x\n", pOption->LoaderFlags);
	printf("NumberOfRvaAndSizes�� 0x%2x\n", pOption->NumberOfRvaAndSizes);

	//����Ŀ¼����Ϣ
	PIMAGE_DATA_DIRECTORY pdir = pOption->DataDirectory;
	printf("\n����Ŀ¼����Ϣ��%d\n", pOption->NumberOfRvaAndSizes);
	for (DWORD i=0 ;i<pOption->NumberOfRvaAndSizes;i++)
	{
		printf("����%d ��RVA: %08x, ��С�� %08x\n", i, pdir[i].VirtualAddress, pdir[i].Size);
	}

	return TRUE;
}
//��ȡ�ڱ���Ϣ
VOID  get_section_header(PBYTE pBuf) {
	//��ȡNTͷ�׵�ַ
	PIMAGE_DOS_HEADER pdos = (PIMAGE_DOS_HEADER)pBuf;
	PIMAGE_NT_HEADERS  pheader = (PIMAGE_NT_HEADERS)(pBuf + pdos->e_lfanew);

	//��ȡNT�ļ�ͷ
	PIMAGE_FILE_HEADER pFileHeader = &pheader->FileHeader;

	//������Ϣ��
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pheader);

	char pName[9] = {};
	printf("%8s|%8s|%8s|%8s|%8s|%8s|%8s\n\n", " ������ ", " �ڴ��ַ ", " �ڴ��С ", " �ļ�ƫ�� ", " �ļ���С ","�ض�λ��ƫ��", "�ض�λ������");
	//printf("\n");
	for (int i = 0; i < pFileHeader->NumberOfSections; i++)
	{
		//����������
		memcpy_s(pName, 9, &pSec[i].Name, 8);
		printf("%8s  ", pName);
		//�ڴ��е�RVA�ʹ�С
		printf("%08x  ", pSec[i].VirtualAddress);
		printf("%08x  ", pSec[i].Misc.VirtualSize);
		//�ļ��е�ƫ�ƺʹ�С
		printf("%08x   ", pSec[i].PointerToRawData);
		printf("%08x   ", pSec[i].SizeOfRawData);
		//�ض�λ��Ϣ
		printf("%08x   ", pSec[i].PointerToRelocations);
		printf("%08d   \n", pSec[i].NumberOfRelocations);
	}
}
//�������Ϣ
VOID get_import(PBYTE  pBuf) {
	//����Ŀ¼���λ�ã�NTͷ��չ�ļ�ͷ����Ŀ¼��ĵڶ�����Ŀ
	PIMAGE_DOS_HEADER pDos = PIMAGE_DOS_HEADER(pBuf);
	PIMAGE_NT_HEADERS pNT = PIMAGE_NT_HEADERS(pBuf + pDos->e_lfanew);

	//����Ŀ¼���ַ
	PIMAGE_DATA_DIRECTORY pDirectory = pNT->OptionalHeader.DataDirectory;

	//�����ĵ�ַ
	DWORD dwImportRva = pDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD dwImportSize = pDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	//printf("�����RVA:0x%02x, ��С�� %d\n", dwImportRva, dwImportSize);
	printf("\n=================���뺯����Ϣ===============\n\n");
	PIMAGE_IMPORT_DESCRIPTOR pImport1= (PIMAGE_IMPORT_DESCRIPTOR)(pBuf + Rva2Fva(dwImportRva, pNT));
	PIMAGE_IMPORT_DESCRIPTOR pImport2 = (PIMAGE_IMPORT_DESCRIPTOR)(pBuf + Rva2Fva(dwImportRva, pNT));
	//printf("Import Address: 0x%2x\n", Rva2Fva(dwImportRva, pNT));
	while (pImport1->Name)
	{
		//DLL����  INT�����RVA   IAT�����RVA
		printf("����dll�����ƣ�%s\n", pBuf + Rva2Fva(pImport1->Name, pNT));
		//printf("INT������׵�ַRVA��%08x\n", Rva2Fva(pImport->OriginalFirstThunk, pNT));
		//printf("IAT������׵�ַRVA��%08x\n", Rva2Fva(pImport->FirstThunk, pNT));
		pImport1++;
	}
	printf("\n******��Dll��ϸ��Ϣ*********\n");
	while (pImport2->Name)
	{
		//DLL����  INT�����RVA   IAT�����RVA
		printf("\n����dll�����ƣ�%s\n", pBuf + Rva2Fva(pImport2->Name, pNT));
		//printf("INT������׵�ַRVA��%08x\n", Rva2Fva(pImport->OriginalFirstThunk, pNT));
		//printf("IAT������׵�ַRVA��%08x\n", Rva2Fva(pImport->FirstThunk, pNT));
		PIMAGE_THUNK_DATA32 pThunk = (PIMAGE_THUNK_DATA32)(pBuf + Rva2Fva(pImport2->OriginalFirstThunk, pNT));
		while (pThunk->u1.AddressOfData)
		{
			//����ǰ�����ŵ���
			if (IMAGE_SNAP_BY_ORDINAL32(pThunk->u1.Ordinal))
			{
				printf("	|----��ţ� %04x\n", IMAGE_ORDINAL32(pThunk->u1.Ordinal));
			}
			//����ǰ������Ƶ���
			else {
				PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(pBuf + Rva2Fva(pThunk->u1.AddressOfData, pNT));
				printf("	|----��ţ� %04x|---�������� %s\n", pName->Hint, pName->Name);
			}
			pThunk++;

		}
		pImport2++;
	}

	//�����ַ��
	IMAGE_THUNK_DATA x;
	IMAGE_IMPORT_BY_NAME;

}
//������
VOID get_Export(PBYTE pBuf) {
	//����Ŀ¼���λ�ã�NTͷ��չ�ļ�ͷ����Ŀ¼��ĵڶ�����Ŀ
	PIMAGE_DOS_HEADER pDos = PIMAGE_DOS_HEADER(pBuf);
	PIMAGE_NT_HEADERS pNT = PIMAGE_NT_HEADERS(pBuf + pDos->e_lfanew);

	//����Ŀ¼���ַ
	PIMAGE_DATA_DIRECTORY pDirectory = pNT->OptionalHeader.DataDirectory;
	DWORD dwExportRva = pDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(pBuf + Rva2Fva(dwExportRva, pNT));
	printf("==================================================\n");
	printf("DLL���ƣ�%s \n\n", pBuf + Rva2Fva(pExport->Name, pNT));
	printf("����������������:%d\n", pExport->Base);
	printf("ENT����: %2d\n", pExport->NumberOfFunctions);
	printf("ENT��RVA: 0x%2x\n", pExport->AddressOfFunctions);
	printf("EAT����: %2d\n", pExport->NumberOfNames);
	printf("EAT��RVA: 0x%2x\n", pExport->AddressOfNames);
	printf("������ű��RVA: 0x%2x\n", pExport->AddressOfNameOrdinals);
	printf("==================================================\n\n");

	PWORD pOrder = (PWORD)(pBuf + Rva2Fva(pExport->AddressOfNameOrdinals, pNT));
	PDWORD pArrName = (PDWORD)(pBuf + Rva2Fva(pExport->AddressOfNames, pNT));
	PDWORD pArrDrr = (PDWORD)(pBuf + Rva2Fva(pExport->AddressOfFunctions, pNT));
	for (int i = 0; i < pExport->NumberOfFunctions; i++) {
		printf("������ţ�%04x  ������ַ��%08x    ", pExport->Base + i, pArrDrr[i]);
		bool bind = false;
		for (int j = 0; j < pExport->NumberOfNames; j++) {
			if (pOrder[j] == i) {
				printf("%s\n", pBuf + (Rva2Fva(pArrName[j], pNT)));
				bind = TRUE;
			}
		}
		if (!bind) {
			printf("û������\n\n");
		}
	}
}
//�ض�λ��
VOID get_relocation(PBYTE  pBuf){
	//NTͷ
	PIMAGE_DOS_HEADER pDos = PIMAGE_DOS_HEADER(pBuf);
	PIMAGE_NT_HEADERS pNT = PIMAGE_NT_HEADERS(pBuf + pDos->e_lfanew);

	//����Ŀ¼���ַ
	PIMAGE_DATA_DIRECTORY pDirectory = pNT->OptionalHeader.DataDirectory;
	DWORD dwReloRva = pDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	PIMAGE_BASE_RELOCATION pReal = (PIMAGE_BASE_RELOCATION)(pBuf + Rva2Fva(dwReloRva, pNT));
	printf("�ض�λ����ļ�ƫ�ƣ�0x%2x\n", pReal);

	while (pReal->VirtualAddress)
	{
		DWORD dwCount = (pReal->SizeOfBlock - 8)/sizeof(WORD);
		printf("�ض�λRVA: %08x, �ض�λ��Ĵ�С�� %x\n", pReal->VirtualAddress, dwCount);

		typedef struct _TYPEOFFECT {
			WORD  offset : 12;//ƫ��ֵ
			WORD  TYpe : 4;//�ض�λ����
		}TYPEOFFECT;
		TYPEOFFECT* pOffset = (TYPEOFFECT*)(pReal + 1);
		int j = 0;
		for (int i = 0; i < dwCount; i++) {
			printf("��ţ�%2d  �ض�λ���ͣ�%d---�ض�λ��Сƫ�ƣ�%08x", j++, pOffset[i].TYpe, pOffset[i].offset);
			DWORD dwRVA = pOffset[i].offset + pReal->VirtualAddress;//��Ҫ�ض�λ�����ݵ�ַ
			if (pOffset[i].TYpe == 3) {
				DWORD dwFo = Rva2Fva(dwRVA, pNT);
				PDWORD  DATA = (PDWORD)(pBuf + dwFo);
				printf("   �ض�λ��������: %08x\n", *DATA);
			}
			else
			{
				printf("�ض�λ������Ϊ��%08x\n\n", dwRVA);
			}
		}
		pReal = (PIMAGE_BASE_RELOCATION)(PBYTE(pReal) + pReal->SizeOfBlock);

	}
	printf("\n");

}
//����˵��
void help() {
	printf("PEtools V1.0.0 For PE file Analysis\n");
	printf("Copyright 2020-08-01 0xCC\n");
	printf("powered by<1220676904@qq.com>\n\n");
	printf("usage: PEtools <PE_file_path> [option]\n\n");
	printf("PE_file_path:    the absolute path of PE to analysis\n\n");
	printf("option: \n");
	printf("	-d:     get IMAGE_DOS_HEADER Stracture data\n");
	printf("	-p:     get IMAGE_NT_HEADER Stracture data\n");
	printf("	-s:     get IMAGE_SECTION_HEADER Stracture data\n");
	printf("	-i:     get IMAGE_IMPORT_DESCRIPTOR Stracture data\n");
	printf("	-o:     get IMAGE_EXPORT_DESCRIPTOR Stracture data\n");
	printf("	-r:     get IMAGE_EXPORT_DESCRIPTOR Stracture data\n");
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
			case 'r':
			{
				get_relocation(PEbuf);
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

