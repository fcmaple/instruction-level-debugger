

#include "ptools.h"
#include "sdb.h"

static std::set<std::string> commands = {"exit","cont","si","anchor","timetravel","break"};

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
		SDB sdb(child);
		std::pair<long long,long long> entryPoint = parseTextSection(argv);
		sdb.setEntryPoint(entryPoint);
        printf("** program \'%s\' loaded. entry point 0x%llx \n",argv[0],entryPoint.first);
		// std::map<range_t, map_entry_t> m;
		// std::map<range_t, map_entry_t>::iterator mi;

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
			if(commands.find(cmd)==commands.end()&&commands.find(cmd.substr(0,5))==commands.end()) continue;
            if(cmd == "exit") break;
            else if(cmd == "si"){
				if(sdb.singleStep()<0){
					errquit("ptrace(SINGLESTEP)");
				}

            }else if(cmd == "cont"){
				// sdb.cont
				if(sdb.cont()<0){
					errquit("ptrace(CONT)");
				}

            }else if(cmd.substr(0,5) == "break"){
				std::stringstream ss(cmd);
				std::vector<std::string> tokens;
				std::string token;
				while(std::getline(ss,token,' ')) tokens.push_back(token);
				long long addr = transToHex(tokens[1]);
				if(sdb.setBreakPoint(addr)<0){
					printf("ss\n");
					errquit("ptrace(POKETEXT)");
				}

				continue;
			}else if(cmd == "anchor"){
				if(sdb.setAnchor()<0){
					errquit("ptrace(GETREGS)");
				}

				continue;
			}else if(cmd== "timetravel"){
				if(sdb.timetravel()<0){
					errquit("ptrace(POKEDATA) or ptrace(SETREGS) ");
				}

			}
			if(sdb.checkBreakPoint()<0){
				errquit("ptrace(POKETEXT)");
			}


        }
		printf("** the target program terminated.\n");

    }
    return 0;
    
}