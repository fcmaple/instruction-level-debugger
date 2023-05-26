#ifndef __PTOOLS_H__
#define __PTOOLS_H__

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <elf.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <capstone/capstone.h>

#include <map>
#include <string>
#include <vector>

typedef struct range_s {
	unsigned long long begin, end;
}	range_t;

typedef struct map_entry_s {
	range_t range;
	int perm;
	long offset;
	std::string name;
}	map_entry_t;

bool operator<(range_t r1, range_t r2);
std::vector<range_t> load_maps(pid_t pid, std::map<range_t, map_entry_t>& loaded);

#endif /* __PTOOLS_H__ */
