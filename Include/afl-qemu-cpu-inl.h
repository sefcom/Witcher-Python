/*
   american fuzzy lop - high-performance binary-only instrumentation
   -----------------------------------------------------------------

   Written by Andrew Griffiths <agriffiths@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   Idea & design very much by Andrew Griffiths.

   Copyright 2015, 2016, 2017 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is a shim patched into the separately-distributed source
   code of QEMU 2.10.0. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting QEMU binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.

 */

#ifndef TCG__AFL_QEMU_CPU
#define TCG__AFL_QEMU_CPU

#include <sys/shm.h>
#include <stdbool.h>

//#include "afl_config.h"


#define SHM_ENV_VAR         "__AFL_SHM_ID"
#define MAP_SIZE_POW2       16
#define MAP_SIZE            (1 << MAP_SIZE_POW2)

#define HTTPREQR_ENV_VAR    "__HTTPREQR_SHM_ID"

#ifdef CONFIG_USER_ONLY
struct httpreqr_info_t {
    int initialized;
    int afl_id;
    int port;
    int reqr_process_id;
    int process_id;
    char error_type[20]; /* SQL, Command */
    char error_msg[100];
    bool capture;
};
#else // qemu-system
static bool afl_setup_complete = false;
struct httpreqr_info_t {
    int enable_logging;
    int reqr_process_id;
    int magic;
};
#endif
static struct httpreqr_info_t *httpreqr_info = NULL;
bool firstpass = true;

/***************************
 * VARIOUS AUXILIARY STUFF *
 ***************************/

/* A snippet patched into tb_find_slow to inform the parent process that
   we have hit a new block that hasn't been translated yet, and to tell
   it to translate within its own context, too (this avoids translation
   overhead in the next forked-off copy). */

/* Function declarations. */
bool is_in_address_range(target_ulong);
int get_entrypoints(target_ulong[], int);
target_ulong get_entry_point_add(void);
bool is_entry_instruction(target_ulong, uint64_t);

void set_connection_accepted(int fd);
bool is_accepted_fd(int fd);
// int  get_connection(void);
bool record_syscalls(void);
void afl_error_handler(int nSignum);
void afl_maybe_log(target_ulong);
void remove_shm(void);
void init_shared_mem(void);

void report_execve_info(const char *execed_fp, const uint8_t *ex_args, const uint8_t *ex_env, uint32_t syscall_num);
void report_httpd_service_start(const char *execed_fp, const uint8_t *ex_args, const uint8_t *ex_env);
void exfiltrate_segfault(const char *execed_fp);
void exfiltrate_killed_signal(uint32_t process_id, uint32_t signal_value);

#define AFL_QEMU_CPU_SNIPPET1 do { \
  } while (0)

bool can_check_for_afl = false;

#ifdef CONFIG_USER_ONLY
#define AFL_QEMU_CPU_SNIPPET2 do { \
        afl_maybe_log(itb->pc); \
    } while (0)
#else  // if qemu-system
#define AFL_QEMU_CPU_SNIPPET2 do { \
        afl_maybe_log(itb->pc); \
    } while (0)
#endif

unsigned char *afl_area_ptr;
static int  connection_accepted = -1;
/* Exported variables populated by the code patched into elfload.c: */
static int ins_count = 0;

target_ulong afl_entry_point, /* ELF entry point (_start) */
afl_start_code,  /* .text start pointer      */
afl_end_code;    /* .text end pointer        */

/* Set in the child process in forkserver mode: */
// unsigned int afl_forksrv_pid;

struct bindata{
    int entrypoint;
    int lastpoint;
    int entry_instruction;
};
struct bindata bindata_arr[128];
int bindata_max = 0;

#if 0
#define TEST_PROCESS_INFO_SHM_ID 0x411911
#define TEST_PROCESS_INFO_MAX_NBR 100
#define TEST_PROCESS_INFO_SMM_SIZE 0x4000
#endif

// static int witcher_log_syscalls = -1;
// static bool ins_record =false;
/* Instrumentation ratio: */

//static unsigned int afl_inst_rms = MAP_SIZE;

static target_ulong matched_entrypoint=0;


/*************************
 * ACTUAL IMPLEMENTATION *
 *************************/

bool is_in_address_range(target_ulong addr){
    //entrypoint=0, lastpoint=0, entry_instruction;
    if (bindata_max==0){
        memset(bindata_arr, 0, sizeof(struct bindata)*128);
        char *binarydata = getenv("BINARY_DATA");
        if (binarydata) {
            char *token = strtok(binarydata, ",;");

            while (token != NULL) {
                bindata_arr[bindata_max].entrypoint = atol(token);
                printf("entrypoint = %x ", bindata_arr[bindata_max].entrypoint);
                token = strtok(NULL, ",;");
                if (token != NULL) {
                    int codesize = atoi(token);
                    bindata_arr[bindata_max].lastpoint = bindata_arr[bindata_max].entrypoint + codesize;
                    printf("lastpoint = %x ", bindata_arr[bindata_max].lastpoint);
                    token = strtok(NULL, ",;");
                    if (token != NULL) {
                        bindata_arr[bindata_max].entry_instruction = atol(token);
                        printf("entry_instruction = %x ", bindata_arr[bindata_max].entry_instruction);
                        bindata_max++;
                    }
                }
                token = strtok(NULL, ",;");
            }
            printf("\n");
        }
        if (bindata_max == 0) {
            bindata_max = -1;
            return false;
        }
    }
    for (int x=0; x < bindata_max;x++){
        if (addr >= bindata_arr[x].entrypoint && addr < bindata_arr[x].lastpoint ){
            // fprintf(stderr, "ADDRESS %x IS HOOKED\n", addr);
            return true;
        }
    }
    return false;

}
target_ulong get_entry_point_add(void) {
    return matched_entrypoint;
}

int get_entrypoints(target_ulong entrypoints[], int max_allowed){

    for (int x=0; x < bindata_max && x < max_allowed;x++) {
        entrypoints[x] = bindata_arr[x].entrypoint;
    }
    return bindata_max;
}
bool is_entry_instruction(target_ulong addr, uint64_t instruction) {
    for (int x=0; x < bindata_max;x++){
        if (addr >= bindata_arr[x].entrypoint && addr < bindata_arr[x].lastpoint ){
            if (instruction == bindata_arr[x].entry_instruction){
                matched_entrypoint = bindata_arr[x].entrypoint;
                return true;
            }
        }
    }
    return false;
}

void set_connection_accepted(int fd){
    connection_accepted = fd;
    fprintf(stderr, "connection_accepted = %d\n", connection_accepted);
}

bool is_accepted_fd(int fd){
    bool test = (connection_accepted == fd);
    return test;
}

#if 0
int  get_connection(void){
    return connection_accepted;
}
#endif

bool record_syscalls(void){
    return true;
#if 0
    if (witcher_log_syscalls == -1){
        if (getenv("WITCHER_LOG_SHELL")){
            witcher_log_syscalls = 1;
        } else {
            witcher_log_syscalls = 0;
        }
    }
    if (witcher_log_syscalls){
        return true;
    }
//    if (tp_info_this == NULL){
//        init_shared_mem();
//    }
//    return (tp_info_this != NULL && tp_info_this->capture);
#endif
}

void afl_error_handler(int nSignum) {
    // make sure most recent
    if (getenv("AFL_META_INFO_ID")){
        FILE *elog = fopen("/tmp/witcher.log","a+");
        int mem_key = atoi(getenv("AFL_META_INFO_ID"));
        int shm_id = shmget(mem_key , sizeof(struct httpreqr_info_t), 0666);
        if (shm_id  >= 0 ) {
            httpreqr_info = (struct httpreqr_info_t *) shmat(shm_id, NULL, 0);  /* attach */
            if (elog) {
                fprintf(elog, "\033[36m[Witcher] set httpreqr_info=%p!!!\033[0m\n", httpreqr_info);
            }
        }
        if (elog){
            fprintf(elog, "\033[36m[Witcher] sending SEGSEGV to reqr_process_id=%d pid=%d last_insn=%d afl_id=%d capture=%d!!!\033[0m\n",
                    httpreqr_info->reqr_process_id, getpid(), ins_count, httpreqr_info->afl_id, httpreqr_info->capture);
            fclose(elog);
        }
        if (httpreqr_info->reqr_process_id != 0){
            kill(httpreqr_info->reqr_process_id, SIGSEGV);
        }
        //strcpy(httpreqr_info->error_type,"COMMAND");
    } else {
        FILE *elog = fopen("/tmp/witcher.log","a+");
        if (elog){
            fprintf(elog, "\033[36m[Witcher] detected error in child but AFL_META_INFO_ID is not set. !!!\033[0m\n");
            fclose(elog);
        }
    }
}

void report_execve_info(const char *execed_fp, const uint8_t *ex_args, const uint8_t *ex_env, uint32_t syscall_num){
#if 1
    FILE *shelllog = fopen("/tmp/shell.log", "a+");
    if (shelllog) {
        fprintf(shelllog, "[%s]\n", ex_args);
        fclose(shelllog);
    }
    shelllog = fopen("/tmp/shell_full.log", "a+");
    if (shelllog){
        fprintf(shelllog, "{\"filename\":\"%s\", \"args\": [%s],", execed_fp, ex_args);
        fprintf(shelllog, "\"env\":[%s] }\n", ex_env);
        fclose(shelllog);
    }
    //printf("\033[34mEXECVE->%d %s [%s] \033[0m\n", syscall_num, execed_fp, ex_args);
#endif
}

void report_httpd_service_start(const char *execed_fp, const uint8_t *ex_args, const uint8_t *ex_env) {
    // fprintf(stderr, "%s\n", __func__);
#if 1
    if (strstr(execed_fp,"httpd") != NULL || strcmp(execed_fp,"/bin/goahead") == 0 ||
        strcmp(execed_fp,"/bin/alphapd") == 0 || strcmp(execed_fp,"/bin/boa") == 0 ) {
        printf("[+] \033[33mHTTP service executed [%s] \033[0m [%s] \n\t[%s] \n ", execed_fp, ex_args, ex_env);
    }
#endif
}

void exfiltrate_segfault(const char *execed_fp){
#if 1
    if (strcmp(execed_fp,"/bin/segme10") == 0 || strcmp(execed_fp,"/segme10") == 0){
        // when these are triggered, the script detected a segfault, time to escalate
        if (httpreqr_info){
            fprintf(stderr, "[+] \033[31mSEGME detected, exfiltrating to httpreqr_info -> %p process_id = %d::>\n ", httpreqr_info, httpreqr_info->reqr_process_id);

            kill(httpreqr_info->reqr_process_id, SIGSEGV);
        } else {
            fprintf(stderr, "\n[-] \033[31mSEGME found BUT httpreqr_info not set \033[0m\n");
        }
    }
#endif
}

void exfiltrate_killed_signal(uint32_t process_id, uint32_t signal_value){
    // fprintf(stderr, "%s\n", __func__);

    fprintf(stderr, "[-] \033[32mKill signal reached process=%d, signal=%d \033[0m\n", process_id, signal_value);

#if 1
    if (signal_value == SIGSEGV || signal_value == SIGUSR1 || signal_value == SIGUSR2){
        if (httpreqr_info){
            fprintf(stderr, "[+] \033[31mKILL sending %d, AFL found httpreqr_info -> %p process_id = %d::>\n ",
                    signal_value, httpreqr_info, httpreqr_info->reqr_process_id);
            kill(httpreqr_info->reqr_process_id, SIGSEGV);
        } else {
            fprintf(stderr, "[-] \033[31mWitcher Received KILL signal from Guest Sigal=%d but harness not found\n", signal_value);
        }
    }
#endif
}

static int afl_meta = 0, current_afl_id = 0;
/* Set up SHM region and initialize other stuff. */
void init_shared_mem(void) {

    if (afl_meta == 0 && getenv("AFL_META_INFO_ID") ){
        afl_meta = atoi(getenv("AFL_META_INFO_ID") );
    }
    if (httpreqr_info == NULL && afl_meta != 0) {
        bool create_shm = true;
        // clean up last shared memory area
        int mem_key = atoi(getenv("AFL_META_INFO_ID"));
        int shm_id = shmget(mem_key , sizeof(struct httpreqr_info_t), 0666);
        if (shm_id  >= 0 ) {
            httpreqr_info = (struct httpreqr_info_t *) shmat(shm_id, NULL, 0);  /* attach */
            if (httpreqr_info && httpreqr_info->afl_id != 0 ){
                // if record exists we only clean up if afl_id is already set and then we fork,
                // hopefully this will limit clean up to when needed even when the damn thing forks
                shmctl(shm_id, IPC_RMID, NULL);
            } else {
                create_shm = false;
            }
        }
        if (create_shm){
            printf("\n\n*** creating shm memory %x \n", mem_key);
            shm_id = shmget(mem_key , sizeof(struct httpreqr_info_t), IPC_CREAT | 0666);
            if (shm_id < 0 ) {
                //printf("*** shmget error (server) ***\n");
                perror("*** shmget error (server) *** ERROR: ");
                exit(1);
            }

        } else {
            atexit(remove_shm);
            printf("\n\nUsing existing shm\n\n");
        }

        httpreqr_info = (struct httpreqr_info_t *) shmat(shm_id, NULL, 0);  /* attach */
        memset(httpreqr_info, 0, sizeof(struct httpreqr_info_t));

        httpreqr_info->process_id = getpid();
        if (httpreqr_info->initialized != 199){
            printf("\nAFL %d info afl_meta=%d httpreqr_id=%u state=%d AFL info addr=%p id=%d pid=%d, cap=%d", getpid(), afl_meta, shm_id, httpreqr_info->initialized, httpreqr_info, httpreqr_info->afl_id,  httpreqr_info->process_id, httpreqr_info->capture );
            FILE *elog = fopen("/tmp/witcher.log","a+");
            if (elog){
                fprintf(elog, "AFL %d info afl_meta=%d httpreqr_id=%u state=%d AFL info addr=%p id=%d pid=%d, cap=%d\n", getpid(), afl_meta, shm_id, httpreqr_info->initialized, httpreqr_info, httpreqr_info->afl_id,  httpreqr_info->process_id, httpreqr_info->capture );
                fclose(elog);
            }
        }

        httpreqr_info->initialized = 199;

        printf("\n");
    }


    if (httpreqr_info){
        if (firstpass){
            firstpass = false;
            printf("\033[36mWitcher is being executed and adding sig handler\n\033[0m");
            FILE *elog = fopen("/tmp/witcher.log","a+");
            if (elog){
                fprintf(elog, "\033[36mWitcher is being executed and adding sig handler\n\033[0m");
                fclose(elog);
            }
            signal(SIGUSR1, afl_error_handler);
            fflush(stdout);
        }

        //printf("[WC] %d \n", httpreqr_info->afl_id);
        if (afl_area_ptr == NULL && httpreqr_info->afl_id != 0){
            httpreqr_info->initialized = 10;
            //printf("[WC] Using %d to attach to afl_area_ptr\n", httpreqr_info->afl_id);
            current_afl_id = httpreqr_info->afl_id;
            afl_area_ptr = (unsigned char*)  shmat(httpreqr_info->afl_id, NULL, 0);
        }
//        if (httpreqr_info->initialized == 10){
//            printf("aap=%p init=%d afl_id=%d port=%d rpid=%d pid=%d err=%s->%s, cap=%d\n", afl_area_ptr, httpreqr_info->initialized, httpreqr_info->afl_id, httpreqr_info->port,
//               httpreqr_info->reqr_process_id, httpreqr_info->process_id, httpreqr_info->error_type, httpreqr_info->error_msg, httpreqr_info->capture);
//
//        }
    }

}

/* Set up SHM region and initialize other stuff. */

#ifndef CONFIG_USER_ONLY // qemu-system
static void afl_setup(void) {
    char *id_str = getenv(SHM_ENV_VAR);/*,
       *inst_r = getenv("AFL_INST_RATIO");*/

    int shm_id;

#if 0
    if (inst_r) {

    unsigned int r;

    r = atoi(inst_r);

    if (r > 100) r = 100;
    if (!r) r = 1;

    afl_inst_rms = MAP_SIZE * r / 100;

  }
#endif

    if (id_str) {

        shm_id = atoi(id_str);
        afl_area_ptr = shmat(shm_id, NULL, 0);

        if (afl_area_ptr == (void*)-1) exit(1);

#if 0
        /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
       so that the parent doesn't give up on us. */

    if (inst_r) afl_area_ptr[0] = 1;
#endif
    } else {
        fprintf(stderr, "%s not set, shared memory not configured\n", SHM_ENV_VAR);
    }


    id_str = getenv(HTTPREQR_ENV_VAR);
    if (id_str) {
        shm_id = atoi(id_str);
        httpreqr_info = shmat(shm_id, NULL, 0);
        if (httpreqr_info == (void*)-1) exit(1);

        fprintf(stderr, "HTTPREQR MAGIC: %x\n", httpreqr_info->magic);
        assert(httpreqr_info->magic == 0xdeadbeef);
    } else {
        fprintf(stderr, "%s not set!\n", HTTPREQR_ENV_VAR);
    }

#if 0
    if (getenv("AFL_INST_LIBS")) {

    afl_start_code = 0;
    afl_end_code   = (abi_ulong)-1;

  }
#endif
    afl_setup_complete = true;
}
#endif

void remove_shm(void){
    FILE *elog = fopen("/tmp/witcher.log","a+");
    if (elog) {
        fprintf(elog, "\n\n@@@@@@@@@@@@@@@@@ IN FUNC @@@@@@@@@@@@@@@@@\n\n");
        fclose(elog);
    }
    printf("\n\n@@@@@@@@@@@@@@@@@ IN FUNC @@@@@@@@@@@@@@@@@\n\n");
    if (httpreqr_info && httpreqr_info->afl_id != 0 ){
        printf("\n\n@@@@@@@@@@@@@@@@@ REMOVING SHM @@@@@@@@@@@@@@@@@\n\n");
        int mem_key;
        if (afl_meta){
            mem_key = afl_meta;
        } else if (getenv("")){
            mem_key = atoi(getenv("AFL_META_INFO_ID"));
        } else {
            printf("\n\n PSYCHE \n\n");
            return;
        }

        int shm_id = shmget(mem_key , sizeof(struct httpreqr_info_t), 0666);
        if (shm_id  >= 0 ) {
            shmctl(shm_id, IPC_RMID, NULL);
        }
    }
}

/* The equivalent of the tuple logging routine from afl-as.h. */


void afl_maybe_log(target_ulong cur_loc) {
    //printf("maybelog2: %x %p %p %s \n", cur_loc, afl_area_ptr, httpreqr_info, getenv("AFL_META_INFO_ID"));
#ifdef CONFIG_USER_ONLY

    if (afl_area_ptr == NULL){
        init_shared_mem();
    } else{

    }
    if (httpreqr_info && httpreqr_info->afl_id != current_afl_id){
        current_afl_id = httpreqr_info->afl_id;
        if (httpreqr_info->afl_id != 0){
            afl_area_ptr = (unsigned char*)  shmat(httpreqr_info->afl_id, NULL, 0);
        } else {

            afl_area_ptr = NULL;
        }
    }
    if (afl_area_ptr == NULL || httpreqr_info == NULL || !httpreqr_info->capture){
      return;
   }
#else
    if (!afl_setup_complete) {
        afl_setup();
    }
    if (afl_area_ptr == NULL || !httpreqr_info->enable_logging ){
        return;
    }
#endif
    // static target_ulong tmp;
    // if (cur_loc == tmp) return;
    // tmp = cur_loc;

//    if (httpreqr_info && ins_count % 50 == 0) {
//        printf("#%d httpreqr_info->reqr_process_id = %d current pid = %d \n", ins_count, httpreqr_info->reqr_process_id, getpid());
//        FILE *elog = fopen("/tmp/witcher.log","a+");
//        if (elog) {
//            fprintf(elog,"#%d httpreqr_info->reqr_process_id = %d current pid = %d \n", ins_count, httpreqr_info->reqr_process_id, getpid());
//            fclose(elog);
//        }
//    }

    ins_count++;
    static __thread target_ulong prev_loc;

    /* Optimize for cur_loc > afl_end_code, which is the most likely case on
       Linux systems. */
#ifdef CONFIG_USER_ONLY
    /* NECESSARY FOR single binary rehosting */
//  if (cur_loc > afl_end_code || cur_loc < afl_start_code || !afl_area_ptr)
//    return;
#endif
    /* Looks like QEMU always maps to fixed locations, so ASAN is not a
       concern. Phew. But instruction addresses may be aligned. Let's mangle
       the value to get something quasi-uniform. */

    cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
    cur_loc &= MAP_SIZE - 1;

    /* Implement probabilistic instrumentation by looking at scrambled block
       address. This keeps the instrumented locations stable across runs. */
#ifdef CONFIG_USER_ONLY
    //if (cur_loc >= afl_inst_rms) return;
#endif
    afl_area_ptr[cur_loc ^ prev_loc]++;
    //fprintf(stderr, "LOGGING afl_id=%d (%x ^ %x = %x): %d\n",  current_afl_id, cur_loc, prev_loc, cur_loc ^ prev_loc, afl_area_ptr[cur_loc ^ prev_loc]);

    prev_loc = cur_loc >> 1;

}


#endif  /* TCG__AFL_QEMU_CPU */
