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
std::pair<long long,long long> parseTextSection(char*[]);
long long transToHex(std::string);
void errquit(const char *);
void disassembleAndPrint(pid_t , unsigned long long ,\
std::vector<long long>& ,std::pair<long long,long long>& ,\
std::map<long long, instruction1>& ,csh& );
#endif