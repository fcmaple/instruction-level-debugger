#ifndef __UTIL_H__
#define __UTIL_H__
#include <iostream>
#include <string>
class instruction1 {
public:
	unsigned char bytes[16];
	int size;
	std::string opr, opnd;
};
enum CMD{
	EXIT,CONT,SI,ANCHOR,TIMETRAVEL,BREAK,GET,SET,VMMAP,INVALID,
};
enum REG{
	R15,R14,R13,R12,R11,R10,R9,R8,RAX,RCX,RDX,RSI,RDI,ORIG_RAX,RIP,CS,EFLAGS,RSP,RBP,RBX,SS,FS_BASE,GS_BASE,DS,ES,FS,GS,ERR
};
std::pair<REG,long long> commandToReg(std::string);
CMD nameToCmd(std::string);
long long commandToAddr(std::string);
std::pair<long long,long long> parseTextSection(char*[]);
long long transToHex(std::string);
void errquit(const char *);
void disassembleAndPrint(pid_t , unsigned long long ,\
std::vector<long long>& ,std::pair<long long,long long>& ,\
std::map<long long, instruction1>& ,csh& );

#endif