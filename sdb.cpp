

#include "ptools.h"
#include "sdb.h"
#include "util.h"

void 
SDB::setEntryPoint(std::pair<long long,long long> points){
	this-> entryPoint = points;
}
int 
SDB::loadMaps(){
	char fn[128];
	char buf[256];
	char exeName[128];
	char pn[128];
	std::vector<range_t> vec;
	FILE *fp;
	snprintf(pn, sizeof(pn), "/proc/%u/exe", this->child);
	if (realpath(pn, exeName) == NULL) 
		perror("realpath");

	snprintf(fn, sizeof(fn), "/proc/%u/maps", this->child);
	if((fp = fopen(fn, "rt")) == NULL) return -1;
	while(fgets(buf, sizeof(buf), fp) != NULL) {
		// printf("%s\n",buf);
		int nargs = 0;
		char *token, *saveptr, *args[8], *ptr = buf;
		map_entry_t m;
		while(nargs < 8 && (token = strtok_r(ptr, " \t\n\r", &saveptr)) != NULL) {
			args[nargs++] = token;
			ptr = NULL;
		}
		if(nargs == 5) {
			if((ptr = strchr(args[0], '-')) != NULL) {
				*ptr = '\0';
				unsigned long long segStart = strtol(args[0], NULL, 16);
				unsigned long long segEnd = strtol(ptr+1, NULL, 16);
				range_t rt = {segStart,segEnd};
				vec.push_back(rt);
			}
		}
		if(nargs < 6) continue;

		if((ptr = strchr(args[0], '-')) != NULL) {
			*ptr = '\0';
			m.range.begin = strtol(args[0], NULL, 16);
			m.range.end = strtol(ptr+1, NULL, 16);
		}
		m.name = basename(args[5]);
		m.perm = 0;
		if(args[1][0] == 'r') m.perm |= 0x04;
		if(args[1][1] == 'w') m.perm |= 0x02;
		if(args[1][2] == 'x') m.perm |= 0x01;
		m.offset = strtol(args[2], NULL, 16);
		this->procMaps[m.range] = m;
		if(strlen(exeName)==strlen(args[5]) && !strcmp(exeName,args[5])){
			vec.push_back(m.range);
			// printf("%s 0x%lx 0x%lx\n",exeName,m.range.begin,m.range.end);
		}
		if(m.name=="[stack]"){
			vec.push_back(m.range);
		}
	}
	this->history_addr =  vec;
	return (int)vec.size();
}

int
SDB::singleStep(){
	if(ptrace(PTRACE_SINGLESTEP, this->child, 0, 0) < 0) {
		perror("ptrace");
		cs_close(&this->cshandle);
		return -2;
	}
	if(waitpid(this->child, &this->wait_status, 0) < 0) {
		cs_close(&this->cshandle);
		return -1;
	}
	return 0;
}
int
SDB::setBreakPoint(long long addr){
	long long code = ptrace(PTRACE_PEEKTEXT,this->child,addr,0);
	this->breakpoints[addr] = code;
	if(ptrace(PTRACE_POKETEXT,this->child,addr,(code & 0xffffffffffffff00) | 0xcc) != 0 ){
		cs_close(&this->cshandle);
		// errquit("ptrace(POKETEXT)");
		return -1;
	}
	printf("** set a breakpoint at 0x%llx.\n",addr);
	return 0;
}
int
SDB::setAnchor(){
	struct user_regs_struct regs;
	if(ptrace(PTRACE_GETREGS, this->child, 0, &regs) == 0)
		this->history_regs = regs;
	else{
		cs_close(&this->cshandle);
		return -1;
	}
	for(int i=0;i<(int)this->history_addr.size();i++){
		range_t r = this->history_addr[i];
		std::vector<long long> vec; 
		for(unsigned long long j = r.begin;j<r.end;j+=8){
			long long code = ptrace(PTRACE_PEEKDATA,this->child,j,0);
			vec.push_back(code);
		}
		// printf("0x%llx 0x%llx\n",r.begin,r.end);
		history.push_back(vec);
	}
	printf("** dropped an anchor\n");
	return 0;
}
int
SDB::timetravel(){
	if(ptrace(PTRACE_SETREGS,this->child,0,&history_regs)!=0){
		cs_close(&this->cshandle);
		return -1;
	}
	for(int i=0;i<(int)this->history_addr.size();i++){
		range_t r = this->history_addr[i];
		int count = 0;
		for(unsigned long long j = r.begin;j<r.end;j+=8){
			if(ptrace(PTRACE_POKEDATA,child,j,this->history[i][count++])!= 0 ){
				cs_close(&this->cshandle);
				perror("ptrace(POKEDATA)");
				return -2;
			}
		}
		// printf("0x%llx 0x%llx\n",r.begin,r.end);
	}
	printf("** go back to the anchor point\n");
	return 0;
}
int 
SDB::checkBreakPoint(){
	struct user_regs_struct regs;
	if(ptrace(PTRACE_GETREGS, this->child, 0, &regs) == 0) {
		// find if encounter break point
		if(this->breakpoints.find(regs.rip-1)!= this->breakpoints.end()){
			printf("** hit a breakpoint at 0x%llx.\n",regs.rip-1);
			if(ptrace(PTRACE_POKETEXT,this->child,regs.rip-1,this->breakpoints[regs.rip-1]) != 0 ){
				cs_close(&this->cshandle);
				return -1;
			}
			regs.rip= regs.rip-1;
			regs.rdx = regs.rax;
			if(ptrace(PTRACE_SETREGS,this->child,0,&regs)!=0){
				cs_close(&this->cshandle);
				return -1;
			}
		}
	}
	return this->disassemble();
}
int
SDB::cont(){
	if( ptrace(PTRACE_CONT, this->child, 0, 0)< 0) {
		cs_close(&this->cshandle);
		// return -2;
	}
	if(waitpid(child, &this->wait_status, 0) < 0){
		cs_close(&this->cshandle);
		// return -1;
	} //errquit("waitpid");
	return 0;
}
int 
SDB::disassemble(){
	struct user_regs_struct regs;
	std::map<range_t, map_entry_t>::iterator mi;
	if(ptrace(PTRACE_GETREGS, child, 0, &regs) == 0) {
		mi = check_maps(regs.rip);
		disassembleAndPrint(this->child, regs.rip,this->insAddr,this->entryPoint,this->instructions,this->cshandle);
	}else{
		cs_close(&this->cshandle);
		// return -1;
	}
	return 0;
}
std::map<range_t, map_entry_t>::iterator 
SDB::check_maps(unsigned long long rip){
	std::map<range_t, map_entry_t>::iterator mi;
	range_t r = { rip, rip };
	mi = this->procMaps.find(r);
	if(mi == this->procMaps.end()) {
		this->procMaps.clear();
		loadMaps();
		fprintf(stderr, "## %zu map entries re-loaded.\n", this->procMaps.size());
		mi = this->procMaps.find(r);
	}
	return mi;
}
bool
SDB::checkWIFSTOPPED(){
	return WIFSTOPPED(this->wait_status);
}
int
SDB::end(){
	cs_close(&this->cshandle);
	return 0;
}
SDB::SDB(pid_t child){
	this->child = child;
	if(cs_open(CS_ARCH_X86, CS_MODE_64, &this->cshandle) != CS_ERR_OK){
		perror("cs_open");
	}

	if(waitpid(this->child, &this->wait_status, 0) < 0){
		cs_close(&this->cshandle);
	} //errquit("waitpid");
	ptrace(PTRACE_SETOPTIONS, this->child, 0, PTRACE_O_EXITKILL);
}