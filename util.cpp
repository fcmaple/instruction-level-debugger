#include "sdb.h"
#include "ptools.h"


std::pair<long long,long long> 
parseTextSection(char *name[]) {
    const char *filename = name[1];
    long long ret = 0,sz=0;
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        perror("Failed to open ELF file");
        return {0,0};
    }

    Elf64_Ehdr elf_header;
    if (fread(&elf_header, sizeof(Elf64_Ehdr), 1, file) != 1) {
        fprintf(stderr, "Failed to read ELF header\n");
        fclose(file);
        return {0,0};
    }

    Elf64_Shdr section_header;
    fseek(file, elf_header.e_shoff + elf_header.e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET);
    fread(&section_header, sizeof(Elf64_Shdr), 1, file);

    char *section_names = (char*)malloc(section_header.sh_size);
    fseek(file, section_header.sh_offset, SEEK_SET);
    fread(section_names, section_header.sh_size, 1, file);

    fseek(file, elf_header.e_shoff, SEEK_SET);
    for (int i = 0; i < elf_header.e_shnum; ++i) {
        fread(&section_header, sizeof(Elf64_Shdr), 1, file);
        if (section_header.sh_type == SHT_PROGBITS && section_header.sh_flags == (SHF_ALLOC | SHF_EXECINSTR)) {
            // printf(".text section address: 0x%llx size : 0x%llx \n", section_header.sh_addr,section_header.sh_size);
            

            ret =  section_header.sh_addr;
            sz = section_header.sh_size;
            break;
        }
    }

    free(section_names);
    fclose(file);
    return {ret,ret+sz};
}
long long transToHex(std::string s){
    long long ret = 0;
    for(int i=2;i<(int)s.size();i++){
        if(s[i]=='x') return ret;
        if(s[i] >='a' && s[i]<='f') ret  = ret*16+(s[i]-'a'+10);
        else ret = ret*16+(s[i]-'0');
    }
    return ret;
}
void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}
void
print_instruction(long long addr, instruction1 *in) {
	char bytes[128] = "";
	if(in == NULL) {
		fprintf(stderr, "0x%012llx :\t<cannot disassemble>\n", addr);
	} else {
		for(int i = 0; i < in->size; i++) {
			snprintf(&bytes[i*3], 4, "%2.2x ", in->bytes[i]);
		}
		fprintf(stderr, "      %llx: %-32s\t%-10s%s\n", addr, bytes, in->opr.c_str(), in->opnd.c_str());
	}
}
void
disassembleAndPrint(pid_t proc, unsigned long long rip,\
std::vector<long long>& insAddr,std::pair<long long,long long>& entryPoint,\
std::map<long long, instruction1>& instructions,csh& cshandle) {
	int count;
	char buf[10000] = { 0 };
	unsigned long long ptr = rip;
	cs_insn *insn;
	std::map<long long, instruction1>::iterator mi; // from memory addr to instruction

	auto it = std::find(insAddr.begin(),insAddr.end(),rip);
	int dis = std::distance(it,insAddr.end());
	if(dis >=5){
		for(int i=0;i<5;i++){
			long long nextrip = *(it+i);
			if(nextrip>=entryPoint.second) break;
			mi = instructions.find(nextrip);
			print_instruction(nextrip,&mi->second);
		}
		if(*(it+4)>=entryPoint.second){
			printf("** the address is out of the range of the text section.\n");
		}
		return ;
	}
	for(ptr = rip; ptr < rip + entryPoint.second-entryPoint.first; ptr += PEEKSIZE) {
		long long peek;
		errno = 0;
		peek = ptrace(PTRACE_PEEKTEXT, proc, ptr, NULL);
		if(errno != 0) break;
		memcpy(&buf[ptr-rip], &peek, PEEKSIZE);
	}

	if(ptr == rip)  {
		printf("** the address is out of the range of the text section.\n");
		return;
	}
	if((count = cs_disasm(cshandle, (uint8_t*) buf, rip-ptr, rip, 0, &insn)) > 0) {
		int i;
		for(i = 0; i < count; i++) {
			instruction1 in;
			in.size = insn[i].size;
			in.opr  = insn[i].mnemonic;
			in.opnd = insn[i].op_str;
			memcpy(in.bytes, insn[i].bytes, insn[i].size);
			instructions[insn[i].address] = in;
			insAddr.push_back(insn[i].address);
			// printf("count : %d addr : %p , opnd : %s \n",i,insn[i].address,in.opnd);
		}
		cs_free(insn, count);
	}
	it = std::find(insAddr.begin(),insAddr.end(),rip);
	dis = std::distance(it,insAddr.end());
    int cc = std::min(dis,5);
    for(int i=0;i<cc;i++){
		long long nextrip = *(it+i);
		if(nextrip>=entryPoint.second) break;
        if((mi = instructions.find(nextrip)) != instructions.end()) {
            print_instruction(nextrip, &mi->second);
        } else {
            print_instruction(nextrip, NULL);
        }
    }
	if(*(it+4)>=entryPoint.second){
		printf("** the address is out of the range of the text section.\n");
	}
	return;
}