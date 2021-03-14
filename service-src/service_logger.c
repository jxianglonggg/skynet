#include "skynet.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <errno.h>

struct logger {
	FILE * handle;
	char * prefix;
	uint32_t starttime;
	uint32_t filesize;
	time_t createtime;
	int close;
};

struct logger *
logger_create(void) {
	struct logger * inst = skynet_malloc(sizeof(*inst));
	inst->handle = NULL;
	inst->prefix = NULL;
	inst->close = 0;
	inst->createtime = 0;

	return inst;
}

void
logger_release(struct logger * inst) {
	if (inst->close) {
		fclose(inst->handle);
	}
	skynet_free(inst->prefix);
	skynet_free(inst);
}

#define SIZETIME	32
#define SIZETIMEFMT 32
#define SIZEFILENAME 64
#define SIZEPATH   64
#define SIZEFULLNAME 128
#define MAXFILESIZE  (500 * 1024 * 1024) //每500M 换一个文件
#define HEADSIZE (22 + 12 + 1) // 时间(22) + source(12) + \n(1)

static void
timestring(time_t nowtime, char fmt[SIZETIMEFMT], char tmp[SIZETIME]) {
	struct tm *info = localtime(&nowtime);
	strftime(tmp, SIZETIME, fmt, info);
	return;
}

static bool 
issameday(time_t t1, time_t t2){
	struct tm st1;
	struct tm st2;
	localtime_r(&t1, &st1);
	localtime_r(&t2, &st2);
	return st1.tm_year == st2.tm_year && st1.tm_mon == st2.tm_mon && st1.tm_mday == st2.tm_mday;
}

static void
checkfilestate(struct logger *inst){
	uint64_t now = skynet_now();
	time_t nowtime = now/100 + inst->starttime;
	if(!issameday(nowtime, inst->createtime) || inst->filesize > MAXFILESIZE){
		char fmt[SIZETIMEFMT] = "%Y%m%d_%H%M%S";
		char tmp[SIZETIME];
		char newfilename[SIZEFILENAME];
		char path[SIZEPATH]; 
		timestring(nowtime, fmt, tmp);
		snprintf(newfilename, SIZEFILENAME, "%s_%s.log", inst->prefix, tmp);
		if (inst->close) {
			fclose(inst->handle);
			inst->close = 0;
			inst->createtime = 0;
			inst->filesize = 0;
		}
		memset(fmt, 0x0, SIZETIMEFMT);
		memset(tmp, 0x0, SIZETIME);
		snprintf(fmt, SIZETIMEFMT, "%s", "%Y%m");
		timestring(nowtime, fmt, tmp);
		snprintf(path, SIZEPATH, "./log/%s", tmp);
		if (access("./log", 0) != 0)
			mkdir("./log", 0777);
		if (access(path, 0) != 0)
			mkdir(path, 0777);
		char fullname[SIZEFULLNAME];
		snprintf(fullname, SIZEFULLNAME, "%s/%s", path, newfilename);
		inst->handle = fopen(fullname,"a");
		if(inst->handle){
			inst->close = 1;
			inst->createtime = nowtime;
			inst->filesize = 0;
		} else {
			printf("%s file:%s", strerror(errno), fullname);
		}
	}
}

static int
logger_cb(struct skynet_context * context, void *ud, int type, int session, uint32_t source, const void * msg, size_t sz) {
	struct logger * inst = ud;
	switch (type) {
	case PTYPE_SYSTEM:
		skynet_free(inst->prefix);
		inst->prefix = NULL;
		if (msg){
			inst->prefix = skynet_malloc(sz);
			memcpy(inst->prefix, msg, sz);
		} else {
			if (inst->close) {
				fclose(inst->handle);
				inst->close = 0;
				inst->createtime = 0;
				inst->filesize = 0;
			}
			inst->handle = stdout;
		}
		break;
	case PTYPE_TEXT:
		{
			char tmp[SIZETIME];
			char fmt[SIZETIMEFMT] = "%F %H:%M:%S";
			uint64_t now = skynet_now();
			time_t nowtime = now/100 + inst->starttime;
			timestring(nowtime, fmt, tmp);
			fprintf(inst->handle, "[%s] ", tmp);
			fprintf(inst->handle, "[:%08x] ", source);
			fwrite(msg, sz , 1, inst->handle);
			fprintf(inst->handle, "\n");
			fflush(inst->handle);
			if (inst->prefix) {
				inst->filesize += HEADSIZE; 
				inst->filesize += sz;
				checkfilestate(inst);
			}
		}
		break;
	}
	return 0;
}

int
logger_init(struct logger * inst, struct skynet_context *ctx, const char * parm) {
	const char * r = skynet_command(ctx, "STARTTIME", NULL);
	inst->starttime = strtoul(r, NULL, 10);
	if (parm) {
		inst->prefix = skynet_malloc(strlen(parm)+1);
		strcpy(inst->prefix, parm);
		checkfilestate(inst);
	} else {
		inst->handle = stdout;
	}
	if (inst->handle) {
		skynet_callback(ctx, inst, logger_cb);
		return 0;
	}
	return 1;
}
