#ifndef __SDB_H__
#define __SDB_H__
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <errno.h>

#include <iostream>
#include <algorithm>
#include <sstream>  
#include <string>
#include <map>
#include <set>

#include "ptools.h"
#include "util.h"
#define	PEEKSIZE	8

#define BASE 0
#define SINGLE_STEP 1
#define BREAKPOINT 2

class SDB{
public:
    SDB(pid_t child);
    void setEntryPoint(std::pair<long long,long long>);
    int loadMaps();
    int disassemble();
    int singleStep();
    int cont();
    int setBreakPoint(long long);
    int setAnchor();
    int timetravel();
    int checkBreakPoint(int);
    int end();
    bool checkWIFSTOPPED();
    int setAllBreakPoints();
    int revertBreakPoint();
    int getRegister(std::pair<REG,long long> ) const;
    int setRegister(std::pair<REG,long long>) ;
    int getMaps() const;
    std::map<range_t, map_entry_t>::iterator check_maps(unsigned long long);
private:
    pid_t child;
    int wait_status;
    csh cshandle = 0;
    std::pair<long long,long long> entryPoint; //{entry,end}
    std::map<range_t,map_entry_t> procMaps;
    std::vector<std::string> procMapsVec;
    std::vector<range_t> history_addr;
    std::vector<std::vector<long long>> history;
    std::vector<long long> insAddr;
    std::map<long long, instruction1> instructions;
    std::map<long long ,long long> breakpoints;
    struct user_regs_struct history_regs;
};


#endif