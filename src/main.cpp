

#include "ptools.h"
#include "sdb.h"
#include "util.h"
int 
main(int argc, char *argv[]){
    pid_t child;
    std::string cmd;
    if(argc < 2) {
		fprintf(stderr, "usage: %s program [args ...]\n", argv[0]);
		return -1;
	}
    if((child = fork()) < 0) errquit("fork");
	if(child == 0) {
		dup2(STDOUT_FILENO,STDOUT_FILENO);
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace@child");
		execvp(argv[1], argv+1);
		errquit("execvp");
	} else {
		setvbuf(stdin, nullptr, _IONBF, 0);
		setvbuf(stdout, nullptr, _IONBF, 0);
		SDB sdb(child);
		std::pair<long long,long long> entryPoint = parseTextSection(argv);
		sdb.setEntryPoint(entryPoint);
        printf("** program \'%s\' loaded. entry point 0x%llx \n",argv[0],entryPoint.first);

        if(sdb.loadMaps()==0) {
			sdb.end();
			errquit("ptrace(GETREGS)");
		}
		if(sdb.checkWIFSTOPPED()){
			if(sdb.disassemble()<0){
				errquit("ptrace(GETREGS)");
			}
		}

        while(sdb.checkWIFSTOPPED()){
            printf("(sdb) ");
            std::getline(std::cin,cmd);
			CMD command = nameToCmd(cmd);			
			switch (command)
			{
				case SI:{
					if(sdb.singleStep()<0)
						errquit("ptrace(SINGLESTEP)");
					break;
				}
				case CONT:{
					if(sdb.singleStep()<0)
						errquit("ptrace(SINGLESTEP)");
					sdb.setAllBreakPoints();
					// sdb.revertBreakPoint();
					if(sdb.cont()<0)
						errquit("ptrace(CONT)");
					break;
				}
				case BREAK:{
					long long addr = commandToAddr(cmd);
					if(addr<0){
						printf("Invalid break point\n");
						continue;
					}
					if(sdb.setBreakPoint(addr)<0)
						errquit("ptrace(POKETEXT)");
					break;
				}
				case ANCHOR:{
					if(sdb.setAnchor()<0)
						errquit("ptrace(GETREGS)");
					break;
				}
				case TIMETRAVEL:{
					if(sdb.timetravel()<0)
						errquit("ptrace(POKEDATA) or ptrace(SETREGS) ");
					break;
				}
				case GET:{
					std::pair<REG,long long> reg = commandToReg(cmd);
					if(reg.second < 0){
						printf("Invalid register value\n");
						continue;
					}
					if(sdb.getRegister(reg)<0)
						errquit("ptrace(GETREGS)");
					break;
				}
				case SET:{
					std::pair<REG,long long> reg = commandToReg(cmd);
					if(reg.second < 0){
						printf("Invalid register value\n");
						continue;
					}
					if(sdb.setRegister(reg)<0)
						errquit("ptrace(SETREGS)");
					if(sdb.getRegister(reg)<0)
						errquit("ptrace(GETREGS)");
					break;
				}
				case VMMAP:{
					if(sdb.getMaps()<0)
						errquit("maps");
					break;
				}
				default:
					break;
			}

			switch (command)
			{
				case SI:
				{
					if(sdb.checkBreakPoint(SINGLE_STEP) <0)
						errquit("ptrace(POKETEXT)");
					break;
				}
				case BREAK:
				{
					if(sdb.checkBreakPoint(BREAKPOINT) <0)
						errquit("ptrace(POKETEXT)");
					break;
				}
				case CONT:
				case TIMETRAVEL:
				{
					if(sdb.checkBreakPoint(BASE) <0)
						errquit("ptrace(POKETEXT)");
					break;
				}
				default:
					break;
			}
        }
		printf("** the target program terminated.\n");

    }
    return 0;
    
}