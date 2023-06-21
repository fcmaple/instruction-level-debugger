#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <libgen.h>
#include "ptools.h"

#include <map>
#include <vector>
using namespace std;

bool operator<(range_t r1, range_t r2) {
	if(r1.begin < r2.begin && r1.end < r2.end) return true;
	return false;
}

std::vector<range_t>
load_maps(pid_t pid, map<range_t, map_entry_t>& loaded) {
	char fn[128];
	char buf[256];
	char exeName[128];
	char pn[128];
	std::vector<range_t> vec;
	FILE *fp;
	snprintf(pn, sizeof(pn), "/proc/%u/exe", pid);
	if (realpath(pn, exeName) == NULL) 
		perror("realpath");

	snprintf(fn, sizeof(fn), "/proc/%u/maps", pid);
	if((fp = fopen(fn, "rt")) == NULL) return {};
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
		loaded[m.range] = m;
		if(strlen(exeName)==strlen(args[5]) && !strcmp(exeName,args[5])){
			vec.push_back(m.range);
			// printf("%s 0x%lx 0x%lx\n",exeName,m.range.begin,m.range.end);
		}
		if(strlen(exeName)==strlen(args[5]) && !strcmp(exeName,args[5])){
			vec.push_back(m.range);
			// printf("%s 0x%lx 0x%lx\n",exeName,m.range.begin,m.range.end);
		}
		if(m.name=="[stack]"){
			vec.push_back(m.range);
		}
	}
	return vec;
}

