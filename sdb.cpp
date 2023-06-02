

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
		this-> procMapsVec.push_back(std::string(buf));
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
SDB::getMaps() const {
	for(std::string const & str: this->procMapsVec){
		printf("%s",str.c_str());
	}
	return 0;
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
	// printf("break : %x : %llx",addr,code);
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
	}
	setAllBreakPoints();
	revertBreakPoint();
	printf("** go back to the anchor point\n");
	return 0;
}
int
SDB::revertBreakPoint(){
	struct user_regs_struct regs;
	if(ptrace(PTRACE_GETREGS, this->child, 0, &regs) == 0)
		this->history_regs = regs;
	else{
		cs_close(&this->cshandle);
		return -1;
	}
	if(breakpoints.find(regs.rip)!=breakpoints.end()){
		long long addr = regs.rip;
		long long code = breakpoints[regs.rip];
		if(ptrace(PTRACE_POKETEXT,this->child,addr,code) != 0 ){
			cs_close(&this->cshandle);
			return -1;
		}
	}
	return 0;
}
int
SDB::setAllBreakPoints(){
	long long addr,code;
	for(auto i:breakpoints){
		addr = i.first;
		code = i.second;
		if(ptrace(PTRACE_POKETEXT,this->child,addr,(code & 0xffffffffffffff00) | 0xcc) != 0 ){
			cs_close(&this->cshandle);
			// errquit("ptrace(POKETEXT)");
			return -1;
		}
	}
	return 0;
}
int 
SDB::checkBreakPoint(int type){
	struct user_regs_struct regs;
	if(ptrace(PTRACE_GETREGS, this->child, 0, &regs) == 0) {
		// find if encounter break point
		if(type	== SINGLE_STEP || type == BREAKPOINT){
			if(this->breakpoints.find(regs.rip)!= this->breakpoints.end()){
				if(type!=BREAKPOINT)
					printf("** hit a breakpoint at 0x%llx. \n",regs.rip);
				if(ptrace(PTRACE_POKETEXT,this->child,regs.rip,this->breakpoints[regs.rip]) != 0 ){
					cs_close(&this->cshandle);
					return -1;
				}
			}
		}else{
			if(this->breakpoints.find(regs.rip-1)!= this->breakpoints.end()){
				printf("** hit a breakpoint at 0x%llx. \n",regs.rip-1);
				if(ptrace(PTRACE_POKETEXT,this->child,regs.rip-1,this->breakpoints[regs.rip-1]) != 0 ){
					cs_close(&this->cshandle);
					return -1;
				}
				regs.rip= regs.rip-1;
				if(ptrace(PTRACE_SETREGS,this->child,0,&regs)!=0){
					cs_close(&this->cshandle);
					return -1;
				}
			}
		}
		
	}
	if(type==BREAKPOINT) return 1;
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
int 
SDB::getRegister(std::pair<REG,long long> cmd) const {
	struct user_regs_struct regs;
	if(ptrace(PTRACE_GETREGS, this->child, 0, &regs) != 0)
		return -1;
	switch (cmd.first)
	{
		case R15:{
			printf("r15 : %llx\n",regs.r15);
			break;
		}
		case R14:{
			printf("r14 : %llx\n",regs.r14);
			break;
		}	
		case R13:{
			printf("r13 : %llx\n",regs.r13);
			break;
		}	
		case R12:{
			printf("r12 : %llx\n",regs.r12);
			break;
		}	
		case R11:{
			printf("r11 : %llx\n",regs.r11);
			break;
		}	
		case R10:{
			printf("r10 : %llx\n",regs.r10);
			break;
		}	
		case R9:{
			printf("r9 : %llx\n",regs.r9);
			break;
		}	
		case R8:{
			printf("r8 : %llx\n",regs.r8);
			break;
		}	
		case RAX:{
			printf("rax : %llx\n",regs.rax);
			break;
		}	
		case RCX:{
			printf("rcx : %llx\n",regs.rcx);
			break;
		}	
		case RDX:{
			printf("rdx : %llx\n",regs.rdx);
			break;
		}	
		case RSI:{
			printf("rsi : %llx\n",regs.rsi);
			break;
		}	
		case RDI:{
			printf("rdi : %llx\n",regs.rdi);
			break;
		}	
		case RIP:{
			printf("rip : %llx\n",regs.rip);
			break;
		}	
		case CS:{
			printf("cs : %llx\n",regs.cs);
			break;
		}	
		case EFLAGS:{
			printf("eflags : %llx\n",regs.eflags);
			break;
		}	
		case RSP:{
			printf("rsp : %llx\n",regs.rsp);
			break;
		}	
		case RBP:{
			printf("rbp : %llx\n",regs.rbp);
			break;
		}	
		case RBX:{
			printf("rbx : %llx\n",regs.rbx);
			break;
		}	
		case SS:{
			printf("ss : %llx\n",regs.ss);
			break;
		}	
		case FS_BASE:{
			printf("fs_base : %llx\n",regs.fs_base);
			break;
		}
		case GS_BASE:{
			printf("gs_base : %llx\n",regs.gs_base);
			break;
		}
		case DS:{
			printf("ds : %llx\n",regs.ds);
			break;
		}
		case ES:{
			printf("es : %llx\n",regs.es);
			break;
		}
		case FS:{
			printf("fs : %llx\n",regs.fs);
			break;
		}	
		case GS:{
			printf("gs : %llx\n",regs.gs);
			break;
		}		
		default:
			break;
	}
	return 0;
}
int
SDB::setRegister(std::pair<REG,long long> cmd)  {
	struct user_regs_struct regs;
	if(ptrace(PTRACE_GETREGS, this->child, 0, &regs) != 0)
		return -1;
	switch (cmd.first)
	{
		case R15:{
			regs.r15 = cmd.second;
			break;
		}
		case R14:{
			regs.r14 = cmd.second;
			break;
		}	
		case R13:{
			regs.r13 = cmd.second;
			break;
		}	
		case R12:{
			break;
		}	
		case R11:{
			regs.r11 = cmd.second;
			break;
		}	
		case R10:{
			regs.r10 = cmd.second;
			break;
		}	
		case R9:{
			regs.r9 = cmd.second;
			break;
		}	
		case R8:{
			regs.r8 = cmd.second;
			break;
		}	
		case RAX:{
			regs.rax = cmd.second;
			break;
		}	
		case RCX:{
			regs.rcx = cmd.second;
			break;
		}	
		case RDX:{
			regs.rdx = cmd.second;
			break;
		}	
		case RSI:{
			regs.rsi = cmd.second;
			break;
		}	
		case RDI:{
			regs.rdi = cmd.second;
			break;
		}	
		case RIP:{
			regs.rip = cmd.second;
			break;
		}	
		case CS:{
			regs.cs = cmd.second;
			break;
		}	
		case EFLAGS:{
			regs.eflags = cmd.second;
			break;
		}	
		case RSP:{
			regs.rsp = cmd.second;
			break;
		}	
		case RBP:{
			regs.rbp = cmd.second;
			break;
		}	
		case RBX:{
			regs.rbx = cmd.second;
			break;
		}	
		case SS:{
			regs.ss = cmd.second;
			break;
		}	
		case FS_BASE:{
			regs.fs_base = cmd.second;
			break;
		}
		case GS_BASE:{
			regs.gs_base = cmd.second;
			break;
		}
		case DS:{
			regs.ds = cmd.second;
			break;
		}
		case ES:{
			regs.es = cmd.second;
			break;
		}
		case FS:{
			regs.fs = cmd.second;
			break;
		}	
		case GS:{
			regs.gs = cmd.second;
			break;
		}		
		default:
			break;
	}
	if(ptrace(PTRACE_SETREGS,this->child,0,&regs)!=0){
		cs_close(&this->cshandle);
		return -1;
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