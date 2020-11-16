//=== runtime/softboundcets-wrappers.c- SoftBound wrappers for libraries --*- C -*===// 
// Copyright (c) 2016 Santosh Nagarakatte. All rights reserved.

// Developed by: Santosh Nagarakatte, Rutgers University
//               http://www.cs.rutgers.edu/~santosh.nagarakatte/softbound/

// The  SoftBoundCETS project had contributions from:
// Santosh Nagarakatte, Rutgers University,
// Milo M K Martin, University of Pennsylvania,
// Steve Zdancewic, University of Pennsylvania,
// Jianzhou Zhao, University of Pennsylvania


// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal with the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

//   1. Redistributions of source code must retain the above copyright notice,
//      this list of conditions and the following disclaimers.

//   2. Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimers in the
//      documentation and/or other materials provided with the distribution.

//   3. Neither the names of its developers nor the names of its
//      contributors may be used to endorse or promote products
//      derived from this software without specific prior written
//      permission.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
// CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// WITH THE SOFTWARE.
//===---------------------------------------------------------------------===//

#include <arpa/inet.h>

#if defined(__linux__)
#include<errno.h>
#include<sys/wait.h>
#include <wait.h>
#include <obstack.h>
#include <libintl.h>
#endif

#include<sys/mman.h>
#include<sys/times.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<sys/time.h>
#include<sys/resource.h>
#include<sys/socket.h>
#include<fnmatch.h>
#include <wchar.h>


#include<netinet/in.h>

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <grp.h>
#include <getopt.h>
#include <glob.h>
#include <limits.h>
#include <math.h>
#include <netdb.h>
#include <pwd.h>
#include <syslog.h>
#include <setjmp.h>
#include <string.h>
#include <signal.h>
#include <stdarg.h>
#include<stdio.h>
#include<stdlib.h>

#include <ttyent.h>
#include <time.h>
#include <unistd.h>
#include <langinfo.h>
#include <regex.h>

#ifdef HAVE_ICONV_H
#include <iconv.h>
#endif

#include <utime.h>
#include <math.h>
#include <locale.h>

#include <fcntl.h>
#include <wctype.h>


typedef size_t key_type;
typedef void* lock_type;

#include "softboundcets.h"

typedef void(*sighandler_t)(int);
typedef void(*void_func_ptr)(void);

extern size_t* __softboundcets_global_lock;

extern void __softboundcets_process_memory_total();



__WEAK_INLINE void 
__softboundcets_read_shadow_stack_metadata_store(char** endptr, int arg_num){

#ifdef __HW_SECURITY

  printf("kenny warning: somebody using read_shadow_stack_metadata_store, we presume it only use arg_num=1\n");
  
  asm volatile ("sbdl a0, 0(%[rs])\n\tsbdu a0, 0(%[rs])"
		: 
		: [rs]"r" (endptr)
		:
		);

#else
  
#ifdef __SOFTBOUNDCETS_SPATIAL
    void* nptr_base = __softboundcets_load_base_shadow_stack(arg_num);
    void* nptr_bound = __softboundcets_load_bound_shadow_stack(arg_num);

    __softboundcets_metadata_store(endptr, nptr_base, nptr_bound);

#elif __SOFTBOUNDCETS_TEMPORAL

    size_t nptr_key = __softboundcets_load_key_shadow_stack(arg_num);
    void* nptr_lock = __softboundcets_load_lock_shadow_stack(arg_num);

    __softboundcets_metadata_store(endptr, nptr_key, nptr_lock);

#elif __SOFTBOUNDCETS_SPATIAL_TEMPORAL
    void* nptr_base = __softboundcets_load_base_shadow_stack(arg_num);
    void* nptr_bound = __softboundcets_load_bound_shadow_stack(arg_num);
    size_t nptr_key = __softboundcets_load_key_shadow_stack(arg_num);
    void* nptr_lock = __softboundcets_load_lock_shadow_stack(arg_num);
    __softboundcets_metadata_store(endptr, nptr_base, nptr_bound, nptr_key, 
                                   nptr_lock);

#else

    void* nptr_base = __softboundcets_load_base_shadow_stack(arg_num);
    void* nptr_bound = __softboundcets_load_bound_shadow_stack(arg_num);
    size_t nptr_key = __softboundcets_load_key_shadow_stack(arg_num);
    void* nptr_lock = __softboundcets_load_lock_shadow_stack(arg_num);
    __softboundcets_metadata_store(endptr, nptr_base, nptr_bound, nptr_key, 
                                   nptr_lock);

#endif
#endif //end __HW_SECURITY
}

__WEAK_INLINE void 
__softboundcets_propagate_metadata_shadow_stack_from(int from_argnum, 
                                                     int to_argnum){

#ifdef __HW_SECURITY
  printf("kenny warning: somebody is using propagate_metadata_shadow_stack_from (which is not correctly impl.)\n");

  /*
  if (from_argnum == 1)
    {
      asm volatile ("shall copy the shadow register of a1 to a0 but not change the value in a0"
		    :
		    :
		    :
		    );

    }
  if (from_argnum == 2)
    {
      asm volatile ("shall copy the shadow register of a2 to a0 but not change the value in a0"
		    :
		    :
		    :
		    );
    }
  else
    printf("kenny: from_argnum is not supported please check\n");
  */
  
#else
  
#ifdef __SOFTBOUNDCETS_SPATIAL

  void* base = __softboundcets_load_base_shadow_stack(from_argnum);
  void* bound = __softboundcets_load_bound_shadow_stack(from_argnum);
  __softboundcets_store_base_shadow_stack(base, to_argnum);
  __softboundcets_store_bound_shadow_stack(bound, to_argnum);

 
#elif __SOFTBOUNDCETS_TEMPORAL

 size_t key = __softboundcets_load_key_shadow_stack(from_argnum);
 void* lock = __softboundcets_load_lock_shadow_stack(from_argnum);
 __softboundcets_store_key_shadow_stack(key, to_argnum);
 __softboundcets_store_lock_shadow_stack(lock, to_argnum);
 
#elif __SOFTBOUNDCETS_SPATIAL_TEMPORAL

  void* base = __softboundcets_load_base_shadow_stack(from_argnum);
  void* bound = __softboundcets_load_bound_shadow_stack(from_argnum);
  size_t key = __softboundcets_load_key_shadow_stack(from_argnum);
  void* lock = __softboundcets_load_lock_shadow_stack(from_argnum);
  
  __softboundcets_store_base_shadow_stack(base, to_argnum);
  __softboundcets_store_bound_shadow_stack(bound, to_argnum);
  __softboundcets_store_key_shadow_stack(key, to_argnum);
  __softboundcets_store_lock_shadow_stack(lock, to_argnum);

#else

  void* base = __softboundcets_load_base_shadow_stack(from_argnum);
  void* bound = __softboundcets_load_bound_shadow_stack(from_argnum);
  size_t key = __softboundcets_load_key_shadow_stack(from_argnum);
  void* lock = __softboundcets_load_lock_shadow_stack(from_argnum);
  
  __softboundcets_store_base_shadow_stack(base, to_argnum);
  __softboundcets_store_bound_shadow_stack(bound, to_argnum);
  __softboundcets_store_key_shadow_stack(key, to_argnum);
  __softboundcets_store_lock_shadow_stack(lock, to_argnum);

#endif
#endif //end __HW_SECURITY

}

__WEAK_INLINE void __softboundcets_store_null_return_metadata(){

#ifdef __HW_SECURITY
  printf("kenny warning: store_null_return shall not be used\n");
  /*
  register int *reg_a0 asm ("a0");
  asm volatile ("bndr %[rd], zero, zero"
		: [rd]"+r"(reg_a0)
		: 
		: 
		);
  */
#else
  
#ifdef __SOFTBOUNDCETS_SPATIAL

  __softboundcets_store_base_shadow_stack(NULL, 0);
  __softboundcets_store_bound_shadow_stack(NULL, 0);

#elif __SOFTBOUNDCETS_TEMPORAL

  __softboundcets_store_key_shadow_stack(0, 0);
  __softboundcets_store_lock_shadow_stack(NULL, 0);

#elif __SOFTBOUNDCETS_SPATIAL_TEMPORAL

  __softboundcets_store_base_shadow_stack(NULL, 0);
  __softboundcets_store_bound_shadow_stack(NULL, 0);
  __softboundcets_store_key_shadow_stack(0, 0);
  __softboundcets_store_lock_shadow_stack(NULL, 0);

#else 

  __softboundcets_store_base_shadow_stack(NULL, 0);
  __softboundcets_store_bound_shadow_stack(NULL, 0);
  __softboundcets_store_key_shadow_stack(0, 0);
  __softboundcets_store_lock_shadow_stack(NULL, 0);

#endif
#endif //end __HW_SECURITY
}

__WEAK_INLINE void 
__softboundcets_store_return_metadata(void* base, void* bound, size_t key, 
                                      void* lock){

#ifdef __HW_SECURITY
  printf("kenny warning: store_return_metadata shall not be used\n");
  /*
  register int *reg_a0 asm ("a0");
  asm volatile ("bndr %[rd], %[rs1], %[rs2]"
		: [rd]"+r"(reg_a0)
		: [rs1]"r" (base), [rs2]"r" (bound)
		: 
		);
  */
#else
      
#ifdef __SOFTBOUNDCETS_SPATIAL

  __softboundcets_store_base_shadow_stack(base, 0);
  __softboundcets_store_bound_shadow_stack(bound, 0);


#elif __SOFTBOUNDCETS_TEMPORAL

  __softboundcets_store_key_shadow_stack(key, 0);
  __softboundcets_store_lock_shadow_stack(lock, 0);


#elif __SOFTBOUNDCETS_SPATIAL_TEMPORAL

  __softboundcets_store_base_shadow_stack(base, 0);
  __softboundcets_store_bound_shadow_stack(bound, 0);
  __softboundcets_store_key_shadow_stack(key, 0);
  __softboundcets_store_lock_shadow_stack(lock, 0);

#else

  __softboundcets_store_base_shadow_stack(base, 0);
  __softboundcets_store_bound_shadow_stack(bound, 0);
  __softboundcets_store_key_shadow_stack(key, 0);
  __softboundcets_store_lock_shadow_stack(lock, 0);

#endif
#endif //end __HW_SECURITY
}



/* wrappers for library calls (incomplete) */
//////////////////////system wrappers //////////////////////

__WEAK_INLINE int 
softboundcets_setenv(const char *name, const char *value, int overwrite){

  return setenv(name, value, overwrite);
}

__WEAK_INLINE 
int softboundcets_unsetenv(const char *name){
  
  return unsetenv(name);
}


__WEAK_INLINE int softboundcets_system(char* ptr){

  return system(ptr);
}

__WEAK_INLINE int softboundcets_setreuid(uid_t ruid, uid_t euid) {

  /* tested */
  return setreuid(ruid, euid);
}

__WEAK_INLINE int softboundcets_mkstemp(char* template) {
  
  /* tested */
  return mkstemp(template);
}

__WEAK_INLINE uid_t softboundcets_geteuid(){
  return geteuid();
}

__WEAK_INLINE uid_t softboundcets_getuid(void) {

  /* tested */
  return getuid();
}

__WEAK_INLINE int 
softboundcets_getrlimit(int resource, struct rlimit* rlim){

  /* tested */
  return getrlimit(resource, rlim);
}

__WEAK_INLINE int 
softboundcets_setrlimit(int resource, const struct rlimit* rlim){

  /* tested */
  return setrlimit(resource, rlim);
}

__WEAK_INLINE size_t
softboundcets_fread_unlocked(void *ptr, size_t size, 
                             size_t n, FILE *stream){
  
  return fread_unlocked(ptr, size, n, stream);
}

#if 0
__WEAK_INLINE int 
softboundcets_fputs_unlocked(const char *s, FILE *stream){
  return fputs_unlocked(s, stream);
}
#endif

__WEAK_INLINE size_t 
softboundcets_fread(void *ptr, size_t size, size_t nmemb, FILE *stream){
  /* tested */
  return fread(ptr, size, nmemb, stream);
}

__WEAK_INLINE mode_t softboundcets_umask(mode_t mask) {

  /* tested */
  return umask(mask);
}

__WEAK_INLINE int softboundcets_mkdir(const char* pathname, mode_t mode){
  
  /* tested */
  return mkdir(pathname, mode);
}

__WEAK_INLINE int softboundcets_chroot(const char* path){
  /* tested */
  return chroot(path);
}

__WEAK_INLINE int softboundcets_rmdir(const char* pathname){

  /* tested */
  return rmdir(pathname);
}

__WEAK_INLINE int softboundcets_stat(const char* path, struct stat* buf){
  /* tested */
  return stat(path, buf);
}

__WEAK_INLINE int softboundcets_fputc(int c, FILE* stream){

  /* tested */
  return fputc(c, stream);
}

__WEAK_INLINE int softboundcets_fileno(FILE* stream){

  return fileno(stream);
}

__WEAK_INLINE int softboundcets_fgetc(FILE* stream){

  return fgetc(stream);
}

__WEAK_INLINE int softboundcets_ungetc(int c,  FILE* stream){
  
  return ungetc(c, stream);
}

__WEAK_INLINE int 
softboundcets_strncmp(const char* s1, const char* s2, size_t n){
  return strncmp(s1, s2, n);
}

__WEAK_INLINE double softboundcets_log(double x) {

  return log(x);
}


__WEAK_INLINE  long long 
softboundcets_fwrite(char* ptr, size_t size, size_t nmemb, FILE* stream){
  return fwrite(ptr, size, nmemb, stream);
}

__WEAK_INLINE double softboundcets_atof(char* ptr){
  return atof(ptr);
}

__WEAK_INLINE int softboundcets_feof(FILE* stream){
  return feof(stream);
}

__WEAK_INLINE int softboundcets_remove(const char* pathname){

  return remove(pathname);
}

///////////////////// Math library functions here //////////////////

__WEAK_INLINE double softboundcets_acos(double x) {

  return acos(x);
}

__WEAK_INLINE double softboundcets_atan2(double y, double x) {

  return atan2(y, x);
}
__WEAK_INLINE float softboundcets_sqrtf(float x) {

  return sqrtf(x);
}

__WEAK_INLINE float softboundcets_expf(float x) {

  return expf(x);
}

double exp2(double);

__WEAK_INLINE double softboundcets_exp2(double x) {

  return exp2(x);
}


__WEAK_INLINE float softboundcets_floorf(float x) {

  return floorf(x);
}

__WEAK_INLINE double softboundcets_ceil(double x){

  return ceil(x);
}

__WEAK_INLINE float softboundcets_ceilf(float x) {

  return ceilf(x);
}
__WEAK_INLINE double softboundcets_floor(double x) {

  return floor(x);
}

__WEAK_INLINE double softboundcets_sqrt(double x) {

  return sqrt(x);
}

__WEAK_INLINE double softboundcets_fabs(double x) {

  return fabs(x);
}

__WEAK_INLINE int softboundcets_abs(int j){
  return abs(j);
}

__WEAK_INLINE void softboundcets_srand(unsigned int seed){
  srand(seed);
}

__WEAK_INLINE void softboundcets_srand48(long int seed){
  srand48(seed);
}


__WEAK_INLINE double softboundcets_pow(double x, double y) {
  
  return pow(x,y);

}

__WEAK_INLINE float softboundcets_fabsf(float x) {

  return fabsf(x);
}

__WEAK_INLINE double softboundcets_tan(double x ) {

  return tan(x);
}

__WEAK_INLINE float softboundcets_tanf(float x) {

  return tanf(x);
}
/* kenny prevent unsupported toolchain lib sinl
__WEAK_INLINE long double softboundcets_tanl(long double x) {


  return tanl(x);
}
*/
__WEAK_INLINE double softboundcets_log10(double x) {

  return log10(x);
}
__WEAK_INLINE double softboundcets_sin(double x) {

  return sin(x);
}

__WEAK_INLINE float softboundcets_sinf(float x) {

  return sinf(x);
}

/* kenny prevent unsupported toolchain lib sinl
__WEAK_INLINE long double softboundcets_sinl(long double x) {

  return sinl(x);
}
*/
__WEAK_INLINE double softboundcets_cos(double x) {

  return cos(x);
}

__WEAK_INLINE float softboundcets_cosf(float x) {

  return cosf(x);
}
/* kenny prevent unsupported toolchain lib sinl
__WEAK_INLINE long double softboundcets_cosl(long double x) {

  return cosl(x);
}
*/
__WEAK_INLINE double softboundcets_exp(double x) {

  return exp(x);
}

__WEAK_INLINE double softboundcets_ldexp(double x, int exp) {
  
  return ldexp(x, exp);
}


////////////////File Library Wrappers here //////////////////////

__WEAK_INLINE FILE* softboundcets_tmpfile(void) {

  printf("kenny warning: tmpfile\n");
  void* ret_ptr = tmpfile();
  void* ret_ptr_bound = (char*) ret_ptr + sizeof(FILE);
  __softboundcets_store_return_metadata(ret_ptr, ret_ptr_bound, 
                                        1, __softboundcets_global_lock);
  return ret_ptr;
}

__WEAK_INLINE int softboundcets_ferror(FILE* stream){

  return ferror(stream);
}

__WEAK_INLINE long softboundcets_ftell(FILE* stream){ 

  return ftell(stream);
}

__WEAK_INLINE int softboundcets_fstat(int filedes, struct stat* buff){

  return fstat(filedes, buff);
}

__WEAK_INLINE int softboundcets___lxstat (int __ver, const char *__filename,     
                                          struct stat *__stat_buf) {

  return __lxstat(__ver, __filename, __stat_buf);
}

__WEAK_INLINE size_t softboundcets_mbrtowc(wchar_t *pwc, const char *s, 
                                           size_t n, mbstate_t *ps){
  return mbrtowc(pwc, s, n, ps);
}


__WEAK_INLINE int softboundcets_mbsinit(const mbstate_t *ps){
  return mbsinit(ps);
}



__WEAK_INLINE int softboundcets___fxstat(int ver, int file_des, struct stat * stat_struct){
  return __fxstat(ver, file_des, stat_struct);
}

__WEAK_INLINE int softboundcets___fxstatat(int ver, int file_des, const char* filename, struct stat * stat_struct, int flag){
  return __fxstatat(ver, file_des, filename, stat_struct, flag);
}


__WEAK_INLINE int softboundcets_fflush(FILE* stream){

  return fflush(stream);
}

__WEAK_INLINE int softboundcets_fputs(const char* s, FILE* stream){
  
  return fputs(s, stream);
}

__WEAK_INLINE int softboundcets_fsync(int fd){
  return fsync(fd);
}


//This function wrapper might the the reason why Mibench/Dijkstra opt-O3 got memory violation?
__WEAK_INLINE DIR* softboundcets_fdopendir(int fd){

  printf("kenny warning: fdopendir\n");
  void* ret_ptr = (void*) fdopendir(fd);
  void* ret_ptr_bound = (char *) ret_ptr + 1024 * 1024;
  __softboundcets_store_return_metadata(ret_ptr, ret_ptr_bound, 
                                        1, (void*) __softboundcets_global_lock);
  return (DIR*)ret_ptr;
  
}

__WEAK_INLINE int softboundcets_fseeko(FILE *stream, off_t offset, int whence){
  
  return fseeko(stream, offset, whence);
}

__WEAK_INLINE  char * softboundcets_mkdtemp(char *template){
  printf("kenny warning: mkdtemp\n");
  char* ret_ptr = mkdtemp(template);
  __softboundcets_propagate_metadata_shadow_stack_from(1, 0);
  return ret_ptr;
}

__WEAK_INLINE int softboundcets_raise(int sig){
  return raise(sig);
}

__WEAK_INLINE int softboundcets_linkat(int olddirfd, const char *oldpath,
                                       int newdirfd, const char *newpath, 
                                       int flags){

  return  linkat(olddirfd, oldpath, newdirfd, newpath, flags);
}

__WEAK_INLINE int softboundcets_utimes(const char *filename, 
                                       const struct timeval times[2]){
  
  return utimes(filename, times);
}

#if 0
__WEAK_INLINE int softboundcets_futimesat(int dirfd, const char *pathname,
                                          const struct timeval times[2]){
  
  return futimesat(dirfd, pathname, times);
}
#endif

__WEAK_INLINE int softboundcets_futimens(int fd, const struct timespec times[2]){

  return futimens(fd, times);
}

__WEAK_INLINE int 
softboundcets_utimensat(int dirfd, const char *pathname,
                        const struct timespec times[2], int flags){

  return utimensat(dirfd, pathname, times, flags);
}

__WEAK_INLINE size_t 
softboundcets___ctype_get_mb_cur_max(void){
  return __ctype_get_mb_cur_max();  
}

__WEAK_INLINE int 
softboundcets_iswprint(wint_t wc){
  return iswprint(wc);
}

__WEAK_INLINE int 
softboundcets_getpagesize(void){
  return getpagesize();
}

__WEAK_INLINE int softboundcets_dirfd(DIR *dirp){
  return dirfd(dirp);
}

__WEAK_INLINE struct lconv *softboundcets_localeconv(void){
  struct lconv* temp = localeconv();
  printf("kenny warning: localeconv\n");
  __softboundcets_store_return_metadata(temp, temp + 1024, 
                                        1, (void*) __softboundcets_global_lock);
  
  return temp;
}

__WEAK_INLINE struct tm *softboundcets_gmtime(const time_t *timep){

  struct tm * temp = gmtime(timep);
  printf("kenny warning: gmtime\n");
  __softboundcets_store_return_metadata(temp, temp + 1024, 
                                        1, (void*) __softboundcets_global_lock);

  return temp;
}

__WEAK_INLINE void *
softboundcets_bsearch(const void *key, const void *base,
                      size_t nmemb, size_t size,
                      int (*compar)(const void *, const void *)){
  printf("kenny warning: bsearch\n");
  void* ret_ptr = bsearch(key, base, nmemb, size, compar);

  __softboundcets_propagate_metadata_shadow_stack_from(2, 0);
    return ret_ptr;

}

/* kenny disable function wrapper that dont suport static linking for qemu-riscv simulator */
/*
__WEAK_INLINE 
struct group *softboundcets_getgrnam(const char *name){
  printf("kenny warning: getgrnam\n");
  void* ret_ptr = getgrnam(name);
  __softboundcets_store_return_metadata(ret_ptr, (char*) ret_ptr + 1024 * 1024, 
                                        1, (void*) __softboundcets_global_lock);

  return ret_ptr;  
}
*/

__WEAK_INLINE
int softboundcets_rpmatch(const char *response){
  return rpmatch(response);
}

__WEAK_INLINE
int softboundcets_regcomp(regex_t *preg, const char *regex, int cflags){
  return regcomp(preg, regex, cflags);
}

__WEAK_INLINE
size_t softboundcets_regerror(int errcode, const regex_t *preg, char *errbuf,
                              size_t errbuf_size){

  return regerror(errcode, preg, errbuf, errbuf_size);
}

__WEAK_INLINE
int softboundcets_regexec(const regex_t *preg, const char *string, 
                          size_t nmatch,
                          regmatch_t pmatch[], int eflags){
  return regexec(preg, string, nmatch, pmatch, eflags);
}


#ifdef HAVE_ICONV_H
__WEAK_INLINE
size_t softboundcets_iconv(iconv_t cd,
                           char **inbuf, size_t *inbytesleft,
                           char **outbuf, size_t *outbytesleft){

  return iconv(cd, inbuf, inbytesleft, outbuf, outbytesleft);
}

__WEAK_INLINE
iconv_t softboundcets_iconv_open(const char *tocode, const char *fromcode){

  return iconv_open(tocode, fromcode);
}
#endif



/* kenny disable function wrapper that dont suport static linking for qemu-riscv simulator */
/*
__WEAK_INLINE 
struct passwd * softboundcets_getpwnam(const char *name){
  printf("kenny warning: getpwnam\n");
  void* ret_ptr = getpwnam(name);
  __softboundcets_store_return_metadata(ret_ptr, (char*) ret_ptr + 1024 * 1024, 
                                        1, (void*) __softboundcets_global_lock);

  return ret_ptr;  
}
*/

/* kenny disable function wrapper that dont suport static linking for qemu-riscv simulator */
/*
__WEAK_INLINE struct passwd *softboundcets_getpwuid(uid_t uid){
  printf("kenny warning: getpwuid\n");
  void* ret_ptr= getpwuid(uid);

  __softboundcets_store_return_metadata(ret_ptr, (char*) ret_ptr + 1024 * 1024, 
                                        1, (void*) __softboundcets_global_lock);

  return ret_ptr;  
}
*/

/* kenny disable function wrapper that dont suport static linking for qemu-riscv simulator */
/*
__WEAK_INLINE struct group *softboundcets_getgrgid(gid_t gid){
  printf("kenny warning: getgrgid\n");
  void* ret_ptr = getgrgid(gid);
  __softboundcets_store_return_metadata(ret_ptr, (char*) ret_ptr + 1024 * 1024, 
                                        1, (void*) __softboundcets_global_lock);

  return ret_ptr;  

}
*/



__WEAK_INLINE FILE* softboundcets_fopen(const char* path, const char* mode){                                  

  void* ret_ptr = (void*) fopen(path, mode);
  void* ret_ptr_bound = (char*) ret_ptr + sizeof(FILE);

#ifdef __HW_SECURITY
  asm volatile ("bndr %[rd], %[rs1], %[rs2]"
		: [rd]"+r" (ret_ptr)
		: [rs1]"r" (ret_ptr), [rs2]"r" (ret_ptr_bound)
		:
		);
#else

  printf("kenny warning: fopen\n");
  __softboundcets_store_return_metadata(ret_ptr, ret_ptr_bound, 
                                        1, (void*) __softboundcets_global_lock);
  
#endif
  return (FILE*)ret_ptr;
}

__WEAK_INLINE FILE* softboundcets_fdopen(int fildes, const char* mode){

  void* ret_ptr = (void*) fdopen(fildes, mode);
  void* ret_ptr_bound = (char*) ret_ptr + sizeof(FILE);
  printf("kenny warning: fdopen\n");
  __softboundcets_store_return_metadata(ret_ptr, ret_ptr_bound, 
                                        1, (void*)__softboundcets_global_lock);
  return (FILE*)ret_ptr;
}


__WEAK_INLINE int softboundcets_fseek(FILE* stream, long offset, int whence){

  return fseek(stream, offset, whence);
}

__WEAK_INLINE int softboundcets_ftruncate(int fd, off_t length) {
  return ftruncate(fd, length);
}



__WEAK_INLINE FILE* softboundcets_popen(const char* command, const char* type){

  void* ret_ptr = (void*) popen(command, type);
  void* ret_ptr_bound = (char*)ret_ptr + sizeof(FILE);
  printf("kenny warning: popen\n");
  __softboundcets_store_return_metadata(ret_ptr, ret_ptr_bound, 
                                        1, (void*) __softboundcets_global_lock);  
  return (FILE*)ret_ptr;

}

__WEAK_INLINE int softboundcets_fclose(FILE* fp){
  return fclose(fp);
}


__WEAK_INLINE int softboundcets_pclose(FILE* stream){

  return pclose(stream);
}

__WEAK_INLINE void softboundcets_rewind(FILE* stream){ 
  
  rewind(stream);
}

__WEAK_INLINE struct dirent*  softboundcets_readdir(DIR* dir){

  void* ret_ptr = (void*) readdir(dir);
  void* ret_ptr_bound = (char*)ret_ptr + sizeof(struct dirent);
  printf("kenny warning: readdir\n");
  __softboundcets_store_return_metadata(ret_ptr, ret_ptr_bound, 
                                        1, (void*) __softboundcets_global_lock);

  return (struct dirent*)ret_ptr;

}

__WEAK_INLINE  int
softboundcets_creat(const char *pathname, mode_t mode){
  
  return creat(pathname, mode);
}

__WEAK_INLINE int 
softboundcets_fnmatch(const char *pattern, const char *string, int flags){

  return fnmatch(pattern, string, flags);
}



//This function wrapper might the the reason why Mibench/Dijkstra opt-O3 got memory violation?
__WEAK_INLINE DIR* softboundcets_opendir(const char* name){

  void* ret_ptr = opendir(name);

  /* FIX Required, don't know the sizeof(DIR) */
  void* ret_ptr_bound = (char*) ret_ptr + 1024* 1024;
  printf("kenny warning: opendir\n");
  __softboundcets_store_return_metadata(ret_ptr, ret_ptr_bound, 
                                        1,  (void*)__softboundcets_global_lock);

  return (DIR*)ret_ptr;
}

__WEAK_INLINE int softboundcets_closedir(DIR* dir){

  return closedir(dir);
}

__WEAK_INLINE int 
softboundcets_rename(const char* old_path, const char* new_path){

  return rename(old_path, new_path);
}


////////////////////unistd.h wrappers ////////////////////////////////

__WEAK_INLINE unsigned int softboundcets_sleep(unsigned int seconds) {

  return sleep(seconds);
}

__WEAK_INLINE char* softboundcets_getcwd(char* buf, size_t size){ 

  printf("kenny warning: getcwd\n");
  
  if(buf == NULL) {
    printf("This case not handled, requesting memory from system\n");
    __softboundcets_abort();
  }

#ifdef __SOFTBOUNDCETS_SPATIAL
  
  char* base = (char*)__softboundcets_load_base_shadow_stack(1);
  char* bound = (char*)__softboundcets_load_bound_shadow_stack(1);
  
  if (buf < base || buf + size > bound){
    __softboundcets_printf("[getcwd], overflow in buf in getcwd\n");
    __softboundcets_abort();
  }
  
#endif

#ifdef __SOFTBOUNDCETS_SPATIAL_TEMPORAL
  char* base = (char *)__softboundcets_load_base_shadow_stack(1);
  char* bound = (char *) __softboundcets_load_bound_shadow_stack(1);
  
  if (buf < base || buf + size > bound){
    __softboundcets_printf("[getcwd], overflow in buf in getcwd\n");
    __softboundcets_abort();
  }


#endif

  char* ret_ptr = getcwd(buf, size);

  __softboundcets_propagate_metadata_shadow_stack_from(1, 0);

  return ret_ptr;
}

__WEAK_INLINE int softboundcets_setgid(gid_t gid){
  return setgid(gid);
}



__WEAK_INLINE gid_t softboundcets_getgid(void){
  return getgid();
}

__WEAK_INLINE gid_t softboundcets_getegid(void){
  return getegid();
}
__WEAK_INLINE
int softboundcets_readlinkat(int dirfd, const char *pathname,
                             char *buf, size_t bufsiz){
  return readlinkat(dirfd, pathname, buf, bufsiz);
}

__WEAK_INLINE
int softboundcets_renameat(int olddirfd, const char *oldpath,
                           int newdirfd, const char *newpath){
  return renameat(olddirfd, oldpath, newdirfd, newpath);
}

__WEAK_INLINE 
int softboundcets_unlinkat(int dirfd, const char *pathname, int flags){
  return unlinkat(dirfd, pathname, flags);
}

__WEAK_INLINE
int softboundcets_symlinkat(const char *oldpath, int newdirfd, 
                            const char *newpath){

  return symlinkat(oldpath, newdirfd, newpath);
}

__WEAK_INLINE
int softboundcets_mkdirat(int dirfd, const char *pathname, mode_t mode){

  return mkdirat(dirfd, pathname, mode);
}

__WEAK_INLINE
int softboundcets_fchown(int fd, uid_t owner, gid_t group){
  return fchown(fd, owner, group);
}

__WEAK_INLINE
int softboundcets_fchownat(int dirfd, const char *pathname,
                           uid_t owner, gid_t group, int flags){
  
  return fchownat(dirfd, pathname, owner, group, flags);
}

__WEAK_INLINE
int softboundcets_fchmod(int fd, mode_t mode){
  return fchmod(fd, mode);
}

__WEAK_INLINE
int softboundcets_chmod(const char *path, mode_t mode){
  return chmod(path, mode);
}

__WEAK_INLINE 
int softboundcets_openat(int dirfd, const char *pathname, int flags){
  return openat(dirfd, pathname, flags);
}

__WEAK_INLINE
int softboundcets_fchmodat(int dirfd, const char *pathname, 
                           mode_t mode, int flags){
  return fchmodat(dirfd, pathname, mode, flags);
}

#if defined (__linux__)

__WEAK_INLINE 
int softboundcets___xmknodat (int __ver, int __fd, const char *__path,
                              __mode_t __mode, __dev_t *__dev){
 return  __xmknodat(__ver, __fd, __path, __mode, __dev);
}

__WEAK_INLINE
int softboundcets_mkfifoat(int dirfd, const char *pathname, mode_t mode){
  return mkfifoat(dirfd, pathname, mode);
}

#endif

__WEAK_INLINE 
pid_t softboundcets_getpid(void){
  return getpid();
}

__WEAK_INLINE pid_t softboundcets_getppid(void){
  return getppid();
}


#if 0
__WEAK_INLINE 
int softboundcets_openat(int dirfd, const char *pathname, int flags, mode_t mode){
  return opennat(dirfd, pathname, flags, mode);
}
#endif



__WEAK_INLINE int 
softboundcets_chown(const char* path, uid_t owner, gid_t group){  
  return chown(path, owner, group);
  
}

__WEAK_INLINE
wint_t softboundcets_towlower(wint_t wc){
  return towlower(wc);
}



__WEAK_INLINE int softboundcets_isatty(int desc) {

  return isatty(desc);
}

__WEAK_INLINE int softboundcets_chdir(const char* path){
  return chdir(path);
}

__WEAK_INLINE
int softboundcets_fchdir(int fd){
  return fchdir(fd);
}


///////////////////String related wrappers ////////////////////////////


__WEAK_INLINE int softboundcets_strcmp(const char* s1, const char* s2){
  
  return strcmp(s1, s2);
}


__WEAK_INLINE int softboundcets_strcasecmp(const char* s1, const char* s2){

  return strcasecmp(s1,s2);
}

__WEAK_INLINE int 
softboundcets_strncasecmp(const char* s1, const char* s2, size_t n){
  return strncasecmp(s1, s2, n);
}

__WEAK_INLINE size_t softboundcets_strlen(const char* s){

  return strlen(s);
}

__WEAK_INLINE char* softboundcets_strpbrk(const char* s, const char* accept){ 

  printf("kenny warning: strpbrk\n");
  char* ret_ptr = strpbrk(s, accept);
  if(ret_ptr != NULL) {

    __softboundcets_propagate_metadata_shadow_stack_from(1, 0);
  }
  else {

    __softboundcets_store_null_return_metadata();
  }

  return ret_ptr;
}



__WEAK_INLINE char* softboundcets_gets(char* s){ 

  printf("[SBCETS] gets used and should not be used\n");
  __softboundcets_abort();
#if 0
  printf("[Softboundcets][Warning] Should not use gets\n");
  char* ret_ptr = gets(s);
  __softboundcets_propagate_metadata_shadow_stack_from(1, 0);
  return ret_ptr;
#endif
  return NULL;

}

__WEAK_INLINE char* softboundcets_fgets(char* s, int size, FILE* stream){

  char* ret_ptr = fgets(s, size, stream);
  // our FPGA hardware dont have lbdls  
#ifdef __HW_SECURITY
  //void* container;
  /*
  asm volatile("sbdl %[char_s], 0(%[container])\n\tsbdu %[char_s], 0(%[container])\n\tlbdls %[ret_ptr], 0(%[container])\n\tlbdus %[ret_ptr], 0(%[container])"
	       : [ret_ptr]"+r" (ret_ptr)
	       : [container]"r" (&ret_ptr), [char_s]"r" (s)
	       :
	       );
  */

  //kenny FIXME: non-optimal solution has potential security problem.
  void* base = ret_ptr;
  void* bound = ret_ptr+size;
  asm volatile ("bndr %[rd], %[rs1], %[rs2]"
		: [rd]"+r" (ret_ptr)
		: [rs1]"r" (base), [rs2]"r" (bound)
		:
		);
#else

  printf("kenny warning: fgets\n");
  __softboundcets_propagate_metadata_shadow_stack_from(1,0);

#endif  

  return ret_ptr;
}


__WEAK_INLINE void softboundcets_perror(const char* s){
  perror(s);
}

__WEAK_INLINE size_t softboundcets_strspn(const char* s, const char* accept){
  
  return strspn(s, accept);
}

__WEAK_INLINE size_t softboundcets_strcspn(const char* s, const char* reject){
  
  return strcspn(s, reject);
}

#ifdef _GNU_SOURCE

__WEAK_INLINE void* softboundcets_mempcpy(void * dest, const void * src, size_t n){
  printf("kenny warning: mempcpy\n");
  // IMP: need to copy the metadata 
  void* ret_ptr = mempcpy(dest, src, n);
  __softboundcets_propagate_metadata_shadow_stack_from(1,0);
  return ret_ptr;
}

#endif

__WEAK_INLINE int 
softboundcets_memcmp(const void* s1, const void* s2, size_t n){
  return memcmp(s1, s2, n);
}

#ifdef _GNU_SOURCE

__WEAK_INLINE void* softboundcets_memrchr(const void * s, int c, size_t n){
  printf("kenny warning: memrchr\n");
  void* ret_ptr = memrchr(s, c, n);
  if(ret_ptr != NULL) {
    __softboundcets_propagate_metadata_shadow_stack_from(1, 0);
  }
  else{
    __softboundcets_store_null_return_metadata();
  }
  return ret_ptr;
}
#endif

__WEAK_INLINE void softboundcets_rewinddir(DIR *dirp){
  rewinddir(dirp);  
}



__WEAK_INLINE void* softboundcets_memchr(const void * s, int c, size_t n){
  printf("kenny warning: memchr\n");
  void* ret_ptr = memchr(s, c, n);
  if(ret_ptr != NULL) {
    __softboundcets_propagate_metadata_shadow_stack_from(1, 0);
  }
  else{
    __softboundcets_store_null_return_metadata();
  }
  return ret_ptr;
}

__WEAK_INLINE char* softboundcets_rindex(char* s, int c){
  printf("kenny warning: rindex\n");
  char* ret_ptr = rindex(s,c);
  __softboundcets_propagate_metadata_shadow_stack_from(1,0);
  return ret_ptr;
}

__WEAK_INLINE ssize_t 
softboundcets___getdelim(char **lineptr, size_t *n, int delim, FILE *stream){
  printf("kenny warning: getdelim\n");

  int metadata_prop = 1;
  if(*lineptr == NULL){
    metadata_prop = 0;
  }

  ssize_t ret_val = getdelim(lineptr, n, delim, stream);

  if(metadata_prop){
    __softboundcets_read_shadow_stack_metadata_store(lineptr, 1);
  }
  else{

    __softboundcets_store_return_metadata(*lineptr, 
                                          (*lineptr) + strlen(*lineptr),
                                          1, __softboundcets_global_lock);
  }
  
  return ret_val;
  

}

__WEAK_INLINE unsigned long int 
softboundcets_strtoul(const char* nptr, char ** endptr, int base){
  printf("kenny warning: strtoul\n");
  unsigned long temp = strtoul(nptr, endptr, base);
  if(endptr != NULL){
    __softboundcets_read_shadow_stack_metadata_store(endptr, 1);
    
  }

  return temp;
}

__WEAK_INLINE double softboundcets_strtod(const char* nptr, char** endptr){
  printf("kenny warning: strtod\n");
  double temp = strtod(nptr, endptr);
  
  if(endptr != NULL) {
    __softboundcets_read_shadow_stack_metadata_store(endptr, 1);
  }
  return temp;
 }
 
__WEAK_INLINE long 
softboundcets_strtol(const char* nptr, char **endptr, int base){
   printf("kenny warning: strtol\n");
   long temp = strtol(nptr, endptr, base);
   if(endptr != NULL) {
     //    __softboundcets_printf("*endptr=%p\n", *endptr);
     __softboundcets_read_shadow_stack_metadata_store(endptr, 1);
  }
  return temp;
}

#ifdef _GNU_SOURCE

__WEAK_INLINE char* softboundcets_strchrnul(const char* s, int c){
  printf("kenny warning: strchrnul\n");
  char* ret_ptr = strchrnul(s, c);
   __softboundcets_propagate_metadata_shadow_stack_from(1, 0);
   return ret_ptr;
}
#endif

__WEAK_INLINE char* softboundcets_strchr(const char* s, int c){
  printf("kenny warning: strchr\n");
  char* ret_ptr = strchr(s, c);
   __softboundcets_propagate_metadata_shadow_stack_from(1, 0);
   return ret_ptr;
}

__WEAK_INLINE char* softboundcets_strrchr(const char* s, int c){
  printf("kenny warning: strrchr\n");
  char* ret_ptr = strrchr(s, c);
  __softboundcets_propagate_metadata_shadow_stack_from(1, 0);
  return ret_ptr;
}

__WEAK_INLINE char* softboundcets_stpcpy(char* dest, char* src){
  printf("kenny warning: stpcpy\n");
  void* ret_ptr = stpcpy(dest, src);
  __softboundcets_propagate_metadata_shadow_stack_from(1, 0);
  return ret_ptr;
}

__WEAK_INLINE char* softboundcets_strcpy(char* dest, char* src){

#ifdef __HW_SECURITY

  //hardware check shall be perform here
  //kenny FIXME: currently there is no check due to lack of access from shadow regiser to normal register

  void* container = (void*) src;
  asm volatile("sbdl %[src], 0(%[container])\n\tsbdu %[src], 0(%[container])"
	       : 
	       : [container]"r" (&container), [src]"r" (src)
	       :
	       );
  
#else

#ifdef __SOFTBOUNDCETS_SPATIAL  
  char* dest_base = __softboundcets_load_base_shadow_stack(1);
  char* dest_bound = __softboundcets_load_bound_shadow_stack(1);

  char* src_base = __softboundcets_load_base_shadow_stack(2);
  char* src_bound = __softboundcets_load_bound_shadow_stack(2);

  /* There will be an out-of-bound read before we trigger an error as
     we currently use strlen. Can either (dest + size) or (src + size)
     overflow?
  */
  size_t size = strlen(src);
  if(dest < dest_base || (dest > dest_bound - size -1) || (size > (size_t) dest_bound)){
    printf("[strcpy] overflow in strcpy with dest\n");
    __softboundcets_abort();
  }  
  if(src < src_base || (src > src_bound -size -1) || (size > (size_t) src_bound)){
    printf("[strcpy] overflow in strcpy with src\n");
    __softboundcets_abort();
  }
#endif

#ifdef __SOFTBOUNDCETS_SPATIAL_TEMPORAL
  
  char* dest_base = __softboundcets_load_base_shadow_stack(1);
  char* dest_bound = __softboundcets_load_bound_shadow_stack(1);

  char* src_base = __softboundcets_load_base_shadow_stack(2);
  char* src_bound = __softboundcets_load_bound_shadow_stack(2);

  /* There will be an out-of-bound read before we trigger an error as
     we currently use strlen. Can either (dest + size) or (src + size)
     overflow?
  */
#ifndef __NOSIM_CHECKS
  size_t size = strlen(src);
  if(dest < dest_base || (dest > dest_bound - size -1) || (size > (size_t) dest_bound)){
    printf("[strcpy] overflow in strcpy with dest\n");
    __softboundcets_abort();
  }  
  if(src < src_base || (src > src_bound -size -1 ) || (size > (size_t) src_bound)){
    printf("[strcpy] overflow in strcpy with src\n");
    __softboundcets_abort();
  }
#endif
#endif
#endif //end of __HW_SECURITY
  
  void * ret_ptr = strcpy(dest, src);
  
#ifdef __HW_SECURITY
  
  // hardware replacement of  __softboundcets_propagate_metadata_shadow_stack_from(1, 0);
  // metadata from source shadow register shall be copy to dest shadow register

  /* This is for lbdl that is loading from shadow memroy to shadow register
  asm volatile("lbdl %[ret], 0(%[container])\n\tlbdu %[ret], 0(%[container])"
	       : [ret]"=r" (ret_ptr)
	       : [container]"r" (&container)
	       :
	       );
  */

  //new update for lbdl that is loading from shadow memory to normal register
  char* k_base = "a"; //just use a place holder, if it is void* null then compiler will not allocate a register for it.
  char* k_bound = "b";
  asm volatile("lbdl %[base], 0(%[container])\n\tlbdu %[bound], 0(%[container])\n\tbndr %[ret], %[base], %[bound]"
	       : [ret]"+r" (ret_ptr)
	       : [container]"r" (&container), [base]"r" (k_base), [bound]"r" (k_bound)
	       :
	       );

#else
  __softboundcets_propagate_metadata_shadow_stack_from(1, 0);
#endif
  
  return ret_ptr;
}


__WEAK_INLINE void softboundcets_abort() {
  abort();
}

 __WEAK_INLINE int softboundcets_rand() {
   return rand();
 }
 
 /////////////////* TODO *///////////////////////////

 __WEAK_INLINE int softboundcets_atoi(const char* ptr){

  if(ptr == NULL) {
    __softboundcets_abort();
  }
  return atoi(ptr);    
 }
 
 __WEAK_INLINE void softboundcets_puts(char* ptr){
   puts(ptr);
 }


__WEAK_INLINE void softboundcets_exit(int status) {
  
  exit(status);
}

__WEAK_INLINE char*  softboundcets_strtok(char* str, const char* delim){

  char* ret_ptr = strtok(str, delim);
  
#ifdef __HW_SECURITY
  void* base = (void*)0;
  void* bound = (void*)(281474976710656);
  
  asm volatile ("bndr %[rd], %[rs1], %[rs2]"
		: [rd]"+r" (ret_ptr)
		: [rs1]"r" (base), [rs2]"r" (bound)
		:
		);
  
#else
  printf("kenny warning: strtok\n");  
  __softboundcets_store_return_metadata((void*)0, (void*)(281474976710656), 
                                        1, __softboundcets_global_lock);
#endif
  return ret_ptr;
}

__WEAK_INLINE void __softboundcets_strdup_handler(void* ret_ptr){
  key_type ptr_key;
  lock_type ptr_lock;

  printf("kenny warning: strdup_handler\n");
    
  if(ret_ptr == NULL) {
    __softboundcets_store_null_return_metadata();
  }
  else {
    //    printf("strndup malloced pointer %p\n", ret_ptr);

    __softboundcets_memory_allocation(ret_ptr, &ptr_lock, &ptr_key);
    __softboundcets_store_return_metadata(ret_ptr, 
                                          (void*)
                                          ((char*)ret_ptr + strlen(ret_ptr) + 1), 
                                          ptr_key, ptr_lock); 
  } 
}

//strdup, allocates memory from the system using malloc, thus can be freed
__WEAK_INLINE char* softboundcets_strndup(const char* s, size_t n){

  printf("kenny warning: strndup\n");
  /* IMP: strndup just copies the string s */  
  char* ret_ptr = strndup(s, n);
  __softboundcets_strdup_handler(ret_ptr);  
  return ret_ptr;
 }


//strdup, allocates memory from the system using malloc, thus can be freed
__WEAK_INLINE char* softboundcets_strdup(const char* s){

  printf("kenny warning: strdup\n");
  /* IMP: strdup just copies the string s */  
  void* ret_ptr = strdup(s);
  
  __softboundcets_strdup_handler(ret_ptr);
  return ret_ptr;
 }

__WEAK_INLINE char* softboundcets___strdup(const char* s){

  printf("kenny warning: __strdup\n");
  void* ret_ptr = strdup(s);
  __softboundcets_strdup_handler(ret_ptr);
  return ret_ptr;
}


 __WEAK_INLINE char* softboundcets_strcat (char* dest, const char* src){

#if 0
  if(dest + strlen(dest) + strlen(src) > dest_bound){
    printf("overflow with strcat, dest = %p, strlen(dest)=%d, 
            strlen(src)=%d, dest_bound=%p \n", 
           dest, strlen(dest), strlen(src), dest_bound);
    __softboundcets_abort();
  } 
#endif
  printf("kenny warning: __strcat\n");
  char* ret_ptr = strcat(dest, src);
  __softboundcets_propagate_metadata_shadow_stack_from(1, 0);
  return ret_ptr;
}

__WEAK_INLINE char* 
softboundcets_strncat (char* dest,const char* src, size_t n){
  printf("kenny warning: strncat\n");
  char* ret_ptr = strncat(dest, src, n);
  __softboundcets_propagate_metadata_shadow_stack_from(1, 0);
  return ret_ptr;
}

__WEAK_INLINE char* 
softboundcets_strncpy(char* dest, char* src, size_t n){

#ifdef __HW_SECURITY

  //hardware check shall be perform here
  //kenny FIXME: currently there is no check due to lack of access from shadow regiser to normal register

  void* container = (void*) src;
  asm volatile("sbdl %[src], 0(%[container])\n\tsbdu %[src], 0(%[container])"
	       : 
	       : [container]"r" (&container), [src]"r" (src)
	       :
	       );
  
#else
  
#ifdef __SOFTBOUNDCETS_SPATIAL  
  char* dest_base = __softboundcets_load_base_shadow_stack(1);
  char* dest_bound = __softboundcets_load_bound_shadow_stack(1);

  char* src_base = __softboundcets_load_base_shadow_stack(2);
  char* src_bound = __softboundcets_load_bound_shadow_stack(2);

  /* Can either (dest + n) or (src + n) overflow? */
  if(dest < dest_base || (dest > dest_bound - n) || (n > (size_t) dest_bound)){
    printf("[strncpy] overflow in strncpy with dest\n");
    __softboundcets_abort();
  }  
  if(src < src_base || (src > src_bound -n) || (n > (size_t) src_bound)){
    __softboundcets_abort();
  }
#endif

#ifdef __SOFTBOUNDCETS_SPATIAL_TEMPORAL

#ifdef __SOFTBOUNDCETS_WRAPPER_CHECKS

  char* dest_base = __softboundcets_load_base_shadow_stack(1);
  char* dest_bound = __softboundcets_load_bound_shadow_stack(1);

  char* src_base = __softboundcets_load_base_shadow_stack(2);
  char* src_bound = __softboundcets_load_bound_shadow_stack(2);

  /* Can either (dest + n) or (src + n) overflow? */
  if(dest < dest_base || dest + n > dest_bound){
    printf("[strncpy] overflow in strncpy with dest\n");
    __softboundcets_abort();
  }  
  if(src < src_base || src + n > src_bound){
    //    printf("[strncpy] overflow in strncpy with src, src=%zx, src_base=%zx, src_bound=%zx\n", src, src_base, src_bound);
    __softboundcets_abort();
  }
#endif
#endif
#endif //end __HW_SECURITY
  char* ret_ptr = strncpy(dest, src, n);

#ifdef __HW_SECURITY
  
  // hardware replacement of  __softboundcets_propagate_metadata_shadow_stack_from(1, 0);
  // metadata from source shadow register shall be copy to dest shadow register
  /*
  asm volatile("lbdl %[ret], 0(%[container])\n\tlbdu %[ret], 0(%[container])"
	       : [ret]"=r" (ret_ptr)
	       : [container]"r" (&container)
	       :
	       );
  */
  
  //new update for lbdl that is loading from shadow memory to normal register
  char* k_base = "a"; //just use a place holder, if it is void* null then compiler will not allocate a register for it.
  char* k_bound = "b";
  asm volatile("lbdl %[base], 0(%[container])\n\tlbdu %[bound], 0(%[container])\n\tbndr %[ret], %[base], %[bound]"
	       : [ret]"+r" (ret_ptr)
	       : [container]"r" (&container), [base]"r" (k_base), [bound]"r" (k_bound)
	       :
	       );

#else
  __softboundcets_propagate_metadata_shadow_stack_from(1, 0);
#endif

  return ret_ptr;
}

__WEAK_INLINE char* 
softboundcets_strstr(const char* haystack, const char* needle){
  printf("kenny warning: strstr\n");
  char* ret_ptr = strstr(haystack, needle);
  if(ret_ptr != NULL) {    
    __softboundcets_propagate_metadata_shadow_stack_from(1, 0);
  }
  else {
    __softboundcets_store_null_return_metadata();
  }
  return ret_ptr;
}

__WEAK_INLINE sighandler_t 
softboundcets_signal(int signum, sighandler_t handler){

  printf("kenny warning: signal\n");
      
  sighandler_t ptr = signal(signum, handler);
  __softboundcets_store_return_metadata((void*)ptr, (void*) ptr, 
                                        1, __softboundcets_global_lock);
  return ptr;
}

__WEAK_INLINE clock_t softboundcets_clock(void){
  return clock();
}


__WEAK_INLINE long softboundcets_atol(const char* nptr){ 
  return atol(nptr);
}

__WEAK_INLINE void* softboundcets_realloc(void* ptr, size_t size){

  void* ret_ptr = realloc(ptr, size);
  
#if 0
  /* TODO: may be necessary to copy metadata */
   printf("performing relloc, which can cause ptr=%p\n", ptr);
#endif

   
#ifndef __HW_SECURITY
   __softboundcets_allocation_secondary_trie_allocate(ret_ptr);
   size_t ptr_key = 1;
   void* ptr_lock = __softboundcets_global_lock;

#ifdef __SOFTBOUNDCETS_TEMPORAL
   ptr_key = __softboundcets_load_key_shadow_stack(1);
   ptr_lock = __softboundcets_load_lock_shadow_stack(1);
#elif __SOFTBOUNDCETS_SPATIAL_TEMPORAL
   ptr_key = __softboundcets_load_key_shadow_stack(1);
   ptr_lock = __softboundcets_load_lock_shadow_stack(1);
#else
   ptr_key = __softboundcets_load_key_shadow_stack(1);
   ptr_lock = __softboundcets_load_lock_shadow_stack(1);
#endif

   printf("kenny warning: realloc\n");
   __softboundcets_store_return_metadata(ret_ptr, 
                                         (char*)(ret_ptr) + size, 
                                         ptr_key, ptr_lock);

   if(ret_ptr != ptr){
     __softboundcets_check_remove_from_free_map(ptr_key, ptr);
     __softboundcets_add_to_free_map(ptr_key, ret_ptr);
     __softboundcets_copy_metadata(ret_ptr, ptr, size);
   }
#endif //end ifndef __HW_SECURITY
   
#ifdef __HW_SECURITY
   char* ret_ptr_bound = (char*)(ret_ptr) + size;
   asm volatile ("bndr %[rd], %[rs1], %[rs2]"
		 : [rd]"+r" (ret_ptr)
		 : [rs1]"r" (ret_ptr), [rs2]"r" (ret_ptr_bound)
		 :
		 );
   if(ret_ptr != ptr){
     __softboundcets_copy_metadata(ret_ptr, ptr, size);
   }
#endif
   
   return ret_ptr;
}

__WEAK_INLINE void* softboundcets_calloc(size_t nmemb, size_t size) {
  
  
#ifndef __HW_SECURITY
  printf("kenny warning: calloc\n");
  
  key_type ptr_key = 1 ;
  lock_type  ptr_lock = NULL;
  
  void* ret_ptr = calloc(nmemb, size);   
  if(ret_ptr != NULL) {    
    
#ifdef __SOFTBOUNDCETS_TEMPORAL     
    __softboundcets_memory_allocation(ret_ptr, &ptr_lock, &ptr_key);     
#elif __SOFTBOUNDCETS_SPATIAL_TEMPORAL
    __softboundcets_memory_allocation(ret_ptr, &ptr_lock, &ptr_key);     
#endif
    
    __softboundcets_store_return_metadata(ret_ptr, 
					  ((char*)(ret_ptr) + (nmemb * size)), 
					  ptr_key, ptr_lock); 
    
    if(__SOFTBOUNDCETS_FREE_MAP) {
#if 0
      __softboundcets_printf("calloc ptr=%p, ptr_key=%zx\n", 
			     ret_ptr, ptr_key);
#endif
      //       __softboundcets_add_to_free_map(ptr_key, ret_ptr);
    }
  }
  else{
    __softboundcets_store_null_return_metadata();
  }
#endif //end of ifndef __HW_SECURITY
  
#ifdef __HW_SECURITY
  void* ret_ptr = calloc(nmemb, size);
  if(ret_ptr != NULL){
    char* ret_ptr_bound = ((char*)(ret_ptr) + (nmemb * size));
    
    asm volatile ("bndr %[rd], %[rs1], %[rs2]"
		  : [rd]"+r" (ret_ptr)
		  : [rs1]"r" (ret_ptr), [rs2]"r" (ret_ptr_bound)
		  :
		  );
  }
  else{
    asm volatile ("bndr %[rd], zero, zero"
		  : [rd]"+r" (ret_ptr)
		  : 
		  :
		  );
  }
  
#endif
  
  return ret_ptr;
}

__WEAK_INLINE void* softboundcets_mmap(void* addr, size_t length, 
                                       int prot, int flags, int fd, 
                                       off_t offset){

  printf("kenny warning: mmap\n");
  
  key_type ptr_key=1;
  lock_type ptr_lock=__softboundcets_global_lock;
  char* ret_ptr = mmap(addr, length, prot, flags, fd, offset);
  if(ret_ptr == (void*) -1){
    __softboundcets_store_null_return_metadata();
  }
  else{

    char* ret_bound = ret_ptr + length;
    __softboundcets_store_return_metadata(ret_ptr, ret_bound, 
                                          ptr_key, ptr_lock);
    
  }
  return ret_ptr;
}
 
__WEAK_INLINE void* softboundcets_malloc(size_t size) {
  

  char* ret_ptr = (char*)malloc(size);
  if(ret_ptr == NULL){
    
#ifdef __HW_SECURITY
    register int *reg_a0 asm ("a0");
    asm volatile ("bndr %[rd], zero, zero"
		  : [rd]"+r"(reg_a0)
		  : 
		  : 
		  );

#else
    __softboundcets_store_null_return_metadata();
#endif
    
  }
  else{

#ifndef __HW_SECURITY
    key_type ptr_key=1;
    lock_type ptr_lock=NULL;
    
#ifdef __SOFTBOUNDCETS_TEMPORAL

    __softboundcets_memory_allocation(ret_ptr, &ptr_lock, &ptr_key);
#elif __SOFTBOUNDCETS_SPATIAL_TEMPORAL
    __softboundcets_memory_allocation(ret_ptr, &ptr_lock, &ptr_key);
#endif
#endif
    
    char* ret_bound = ret_ptr + size;

#ifdef __HW_SECURITY
    // [rd] (shall be a0) is the return register which contains the pointer and it's shadow registers contain the base/bound
    asm volatile ("bndr %[rd], %[rs1], %[rs2]"
		  : [rd]"+r" (ret_ptr)
		  : [rs1]"r" (ret_ptr), [rs2]"r" (ret_bound)
		  : 
		  );    
#else
    __softboundcets_store_return_metadata(ret_ptr, ret_bound, 
                                          ptr_key, ptr_lock);
#endif
    if(__SOFTBOUNDCETS_FREE_MAP) {
#if 0
       __softboundcets_printf("malloc ptr=%p, ptr_key=%zx\n", 
                              ret_ptr, ptr_key);
#endif
       //      __softboundcets_add_to_free_map(ptr_key, ret_ptr);
    }
  }
  return ret_ptr;
}


__WEAK_INLINE int softboundcets_putchar(int c) {

  return putchar(c);
}


 __WEAK_INLINE clock_t softboundcets_times(struct tms* buf){
  return times(buf);
}

__WEAK_INLINE size_t 
softboundcets_strftime(char* s, size_t max, 
                       const char* format, const struct tm *tm){
  
  return strftime(s, max, format, tm);
}


__WEAK_INLINE time_t softboundcets_mktime(struct tm *tm){
  return mktime(tm);
}

__WEAK_INLINE long softboundcets_pathconf(char *path, int name){
  return pathconf(path, name);
}


__WEAK_INLINE struct tm* softboundcets_localtime(const time_t* timep){
  printf("kenny warning: localtime\n");
    
  struct tm * ret_ptr = localtime(timep);
  __softboundcets_store_return_metadata(ret_ptr, 
                                        (char*)ret_ptr + sizeof(struct tm), 
                                        1, __softboundcets_global_lock); 
  return ret_ptr;
}

 __WEAK_INLINE time_t softboundcets_time(time_t* t){

   return time(t);
 }

__WEAK_INLINE double softboundcets_drand48(){

  return drand48();
}

__WEAK_INLINE void softboundcets_free(void* ptr){
  /* more checks required to check if it is a malloced address */
#ifdef __SOFTBOUNDCETS_TEMPORAL 
  if(ptr != NULL){
    void* ptr_lock = __softboundcets_load_lock_shadow_stack(1);
    size_t ptr_key = __softboundcets_load_key_shadow_stack(1);
    
    __softboundcets_memory_deallocation(ptr_lock, ptr_key);
    
    if(__SOFTBOUNDCETS_FREE_MAP){
#if 0
      __softboundcets_printf("free =%p, ptr_key=%zx\n", ptr, ptr_key);
#endif
      __softboundcets_check_remove_from_free_map(ptr_key, ptr);
    }
  }  
#endif  

#ifdef __SOFTBOUNDCETS_SPATIAL_TEMPORAL
  if(ptr != NULL){
    void* ptr_lock = __softboundcets_load_lock_shadow_stack(1);
    size_t ptr_key = __softboundcets_load_key_shadow_stack(1);
    __softboundcets_memory_deallocation(ptr_lock, ptr_key);
     
    if(__SOFTBOUNDCETS_FREE_MAP){
#if 0
      __softboundcets_printf("free =%p, ptr_key=%zx\n", ptr, ptr_key);
#endif
      __softboundcets_check_remove_from_free_map(ptr_key, ptr);
    }
  }
#endif
   free(ptr);
}


__WEAK_INLINE long int softboundcets_lrand48(){
  return lrand48();
}


/* ////////////////////Time Related Library Wrappers///////////////////////// */


__WEAK_INLINE char* softboundcets_ctime( const time_t* timep){
  printf("kenny warning: ctime\n");
      
  char* ret_ptr = ctime(timep);

  if(ret_ptr == NULL){
    __softboundcets_store_null_return_metadata();
  }
  else {
    __softboundcets_store_return_metadata(ret_ptr, ret_ptr + strlen(ret_ptr) + 1, 
                                          1, __softboundcets_global_lock);
  }
  return ret_ptr;

}



__WEAK_INLINE double softboundcets_difftime(time_t time1, time_t time0) {  
  return difftime(time1, time0);
}

__WEAK_INLINE int softboundcets_toupper(int c) {

  return toupper(c);
}

__WEAK_INLINE int softboundcets_tolower(int c){

  return tolower(c);
}

__WEAK_INLINE void softboundcets_setbuf(FILE* stream, char* buf){  
  setbuf(stream, buf);
}

__WEAK_INLINE char* softboundcets_getenv(const char* name){

  char* ret_ptr = getenv(name);
#ifdef __HW_SECURITY
  if(ret_ptr != NULL){
    char* ret_ptr_bound = ret_ptr + strlen(ret_ptr) + 1;
    asm volatile ("bndr %[rd], %[rs1], %[rs2]"
		  : [rd]"+r" (ret_ptr)
		  : [rs1]"r" (ret_ptr), [rs2]"r" (ret_ptr_bound)
		  :
		  );
  }
  else{
    asm volatile ("bndr %[rd], zero, zero"
		  : [rd]"+r" (ret_ptr)
		  : 
		  :
		  );
  }
#else
  if(ret_ptr != NULL){  
    printf("kenny warning: getenv\n");
    __softboundcets_store_return_metadata(ret_ptr, 
                                          ret_ptr + strlen(ret_ptr) + 1, 
                                          1, __softboundcets_global_lock);
    
					  }
    else {
      __softboundcets_store_null_return_metadata();
    }
#endif
    
  return ret_ptr;
}

__WEAK_INLINE int softboundcets_atexit(void_func_ptr function){
  return atexit(function);

}

#ifdef _GNU_SOURCE
__WEAK_INLINE char* softboundcets_strerror_r(int errnum, char* buf, 
                                             size_t buf_len) {
  printf("kenny warning: strerror_r\n");
  void* ret_ptr = strerror_r(errnum, buf, buf_len);
  __softboundcets_store_return_metadata(ret_ptr, 
                                        (void*)
                                        ((char*)ret_ptr + strlen(ret_ptr) +1),
                                        1, __softboundcets_global_lock);
  return ret_ptr;
}
#endif

__WEAK_INLINE char* softboundcets_strerror(int errnum) {
  printf("kenny warning: strerror\n");
  void* ret_ptr = strerror(errnum);
  __softboundcets_store_return_metadata(ret_ptr, 
                                        (void*)
                                        ((char*)ret_ptr + strlen(ret_ptr) +1),
                                        1, __softboundcets_global_lock);
  return ret_ptr;
}


__WEAK_INLINE int softboundcets_unlink(const char* pathname){
  return unlink(pathname);
}


__WEAK_INLINE int softboundcets_close(int fd) {

  return close(fd);
}


__WEAK_INLINE int softboundcets_open(const char *pathname, int flags){  
  return open(pathname, flags);

}

__WEAK_INLINE ssize_t softboundcets_read(int fd, void* buf, size_t count){
  
  return read(fd, buf, count);
}

__WEAK_INLINE ssize_t softboundcets_write(int fd, void* buf, size_t count){
  return write(fd, buf, count);
}


__WEAK_INLINE off_t softboundcets_lseek(int fildes, off_t offset, int whence) {

  return lseek(fildes, offset, whence);
}


__WEAK_INLINE int 
softboundcets_gettimeofday(struct timeval* tv, struct timezone* tz){
  return gettimeofday(tv, tz);
}


__WEAK_INLINE int 
softboundcets_select(int nfds, fd_set* readfds, fd_set* writefds,
                     fd_set* exceptfds, struct timeval* timeout){
  return select(nfds, readfds, writefds, exceptfds, timeout);
}

#if defined (__linux__)

__WEAK_INLINE char* 
softboundcets_setlocale(int category, const char* locale){
  printf("kenny warning: setlocale\n");
  void* ret_ptr = setlocale(category, locale);
  __softboundcets_store_return_metadata(ret_ptr, 
                                        (void*) 
                                        ((char*) ret_ptr+ strlen(ret_ptr)),
                                        1, __softboundcets_global_lock);
  return ret_ptr;  

}

__WEAK_INLINE char*
softboundcets_textdomain(const char* domainname){
  printf("kenny warning: textdomain\n");
  void* ret_ptr = textdomain(domainname);
  __softboundcets_store_return_metadata(ret_ptr,
                                        (void *)
                                        ((char*) ret_ptr + strlen(ret_ptr)),
                                        1, __softboundcets_global_lock);
  
  return ret_ptr;
  
}


__WEAK_INLINE char*
softboundcets_bindtextdomain(const char* domainname, const char* dirname){
  printf("kenny warning: bindtextdomain\n");
  void* ret_ptr = bindtextdomain(domainname, dirname);
  __softboundcets_store_return_metadata(ret_ptr,
                                        (void *)
                                        ((char*) ret_ptr + strlen(ret_ptr)),
                                        1, __softboundcets_global_lock);

  return ret_ptr;

}

__WEAK_INLINE char * 
softboundcets_gettext(const char * msgid){
  printf("kenny warning: gettext\n");
  void* ret_ptr = gettext(msgid);
  __softboundcets_store_return_metadata(ret_ptr,
                                        (void*)
                                        ((char*) ret_ptr + strlen(ret_ptr)),
                                        1, __softboundcets_global_lock);

  return ret_ptr;  

}


__WEAK_INLINE char * 
softboundcets_dcngettext (const char * domainname,
                          const char * msgid, const char * msgid_plural,
                          unsigned long int n, int category){
  printf("kenny warning: dcngettext\n");
  void* ret_ptr = dcngettext(domainname, msgid, msgid_plural, n, category);
  __softboundcets_store_return_metadata(ret_ptr,
                                        (void*)
                                        ((char*) ret_ptr + strlen(ret_ptr)),
                                        1, __softboundcets_global_lock);

  return ret_ptr;  
    
}


/* IMP: struct hostent may have pointers in the structure being returned,
   we need to store the metadata for all those pointers */
/* kenny disable function wrapper that dont suport static linking for qemu-riscv simulator
__WEAK_INLINE 
struct hostent * softboundcets_gethostbyname(const char *name){
  
  struct hostent * ret_ptr = gethostbyname(name);

  void* ret_bound = ret_ptr + sizeof(struct hostent);
  __softboundcets_store_return_metadata(ret_ptr,
                                        ret_bound,
                                        1, __softboundcets_global_lock);
  
  return ret_ptr;  
}
*/


__WEAK_INLINE char*
softboundcets_dcgettext (const char * domainname, 
                         const char * msgid,
                         int category) {
  printf("kenny warning: dcgettext\n");
  void* ret_ptr = dcgettext(domainname, msgid, category);
  __softboundcets_store_return_metadata(ret_ptr,
                                        (void*)
                                        ((char*) ret_ptr + strlen(ret_ptr)),
                                        1, __softboundcets_global_lock);

  return ret_ptr;  
  
}

#endif

#if defined(__linux__)
__WEAK_INLINE int* softboundcets___errno_location() {
  printf("kenny warning: __errno_location\n");
  void* ret_ptr = (int *)__errno_location();
  //  printf("ERRNO: ptr is %lx", ptrs->ptr);
  __softboundcets_store_return_metadata(ret_ptr, 
                                        (void*)((char*)ret_ptr + sizeof(int*)),
                                        1, __softboundcets_global_lock);
  
  return ret_ptr;
}

__WEAK_INLINE unsigned short const** 
softboundcets___ctype_b_loc(void) {

  unsigned short const** ret_ptr =__ctype_b_loc();
#ifdef __HW_SECURITY
  void* base = (void*) ret_ptr;
  void* bound = (void*) ((char*) ret_ptr + 1024*1024);
  asm volatile ("bndr %[rd], %[rs1], %[rs2]"
		: [rd]"+r"(ret_ptr)
		: [rs1]"r" (base), [rs2]"r" (bound)
		:
		); 
#else
  __softboundcets_store_return_metadata((void*) ret_ptr,
					(void*) ((char*) ret_ptr + 1024*1024), 
                                        1,
					__softboundcets_global_lock);
#endif //end of __HW_SECURITY
  return ret_ptr;
}

__WEAK_INLINE int const**  softboundcets___ctype_toupper_loc(void) {

  int const ** ret_ptr  =  __ctype_toupper_loc();

#ifdef __HW_SECURITY
  void*  ret_bound = (void*) ((char*)ret_ptr + 1024*1024);
  asm volatile ("bndr %[rd], %[rs1], %[rs2]"
		: [rd]"+r" (ret_ptr)
		: [rs1]"r" (ret_ptr), [rs2]"r" (ret_bound)
		:
		);
#else  
  printf("kenny warning: __ctype_toupper_loc\n");
  __softboundcets_store_return_metadata((void*) ret_ptr, 
                                        (void*) ((char*)ret_ptr + 1024*1024), 
                                        1, __softboundcets_global_lock);
#endif
  return ret_ptr;

}


__WEAK_INLINE int const**  softboundcets___ctype_tolower_loc(void) {

  int const ** ret_ptr  =  __ctype_tolower_loc();

#ifdef __HW_SECURITY
  void*  ret_bound = (void*) ((char*)ret_ptr + 1024*1024);
  asm volatile ("bndr %[rd], %[rs1], %[rs2]"
		: [rd]"+r" (ret_ptr)
		: [rs1]"r" (ret_ptr), [rs2]"r" (ret_bound)
		:
		);
#else
  printf("kenny warning: __ctype_tolower_loc\n");
  __softboundcets_store_return_metadata((void*) ret_ptr, 
                                        (void*) ((char*)ret_ptr + 1024*1024),
                                        1, __softboundcets_global_lock);
#endif
  
  return ret_ptr;

}
#endif

/* This is a custom implementation of qsort */

static int 
compare_elements_helper(void* base, size_t element_size, 
                        int idx1, int idx2, 
                        int (*comparer)(const void*, const void*)){
  
  char* base_bytes = base;
  return comparer(&base_bytes[idx1 * element_size], 
                  &base_bytes[idx2*element_size]);
}

#define element_less_than(i,j) (compare_elements_helper(base, element_size, (i), (j), comparer) < 0)

static void 
exchange_elements_helper(void* base, size_t element_size, 
                         int idx1, int idx2){

  printf("kenny warning: _elements_helper\n");
  char* base_bytes = base;
  size_t i;

  for (i=0; i < element_size; i++){
    char temp = base_bytes[idx1* element_size + i];
    base_bytes[idx1 * element_size + i] = base_bytes[idx2 * element_size + i];
    base_bytes[idx2 * element_size + i] = temp;
  }  

  for(i=0; i < element_size; i+= 8){
    void* base_idx1;
    void* bound_idx1;

    void* base_idx2;
    void* bound_idx2;
    /* kenny get rid of unused variable for spatial safety only    
    size_t key_idx1=1;
    size_t key_idx2=1;

    void* lock_idx1=NULL;
    void* lock_idx2=NULL;
    */
    char* addr_idx1 = &base_bytes[idx1 * element_size + i];
    char* addr_idx2 = &base_bytes[idx2 * element_size + i];

    //    printf("addr_idx1= %p, addr_idx2=%p\n", addr_idx1, addr_idx2);

#ifdef __SOFTBOUNDCETS_SPATIAL
    __softboundcets_metadata_load(addr_idx1, &base_idx1, &bound_idx1);
    __softboundcets_metadata_load(addr_idx2, &base_idx2, &bound_idx2);

    __softboundcets_metadata_store(addr_idx1, base_idx2, bound_idx2);
    __softboundcets_metadata_store(addr_idx2, base_idx1, bound_idx1);

#elif __SOFTBOUNDCETS_TEMPORAL
    size_t key_idx1=1;
    size_t key_idx2=1;

    void* lock_idx1=NULL;
    void* lock_idx2=NULL;

    __softboundcets_metadata_load(addr_idx1, &key_idx1, &lock_idx1);
    __softboundcets_metadata_load(addr_idx2, &key_idx2, &lock_idx2);

    __softboundcets_metadata_store(addr_idx1, key_idx2, lock_idx2);
    __softboundcets_metadata_store(addr_idx2, key_idx1, lock_idx1);

#elif __SOFTBOUNDCETS_SPATIAL_TEMPORAL
    size_t key_idx1=1;
    size_t key_idx2=1;

    void* lock_idx1=NULL;
    void* lock_idx2=NULL;
    
    __softboundcets_metadata_load(addr_idx1, &base_idx1, &bound_idx1, 
                                  &key_idx1, &lock_idx1);
    __softboundcets_metadata_load(addr_idx2, &base_idx2, &bound_idx2, 
                                  &key_idx2, &lock_idx2);

    __softboundcets_metadata_store(addr_idx1, base_idx2, bound_idx2, 
                                   key_idx2, lock_idx2);
    __softboundcets_metadata_store(addr_idx2, base_idx1, bound_idx1, 
                                   key_idx1, lock_idx1);

#else
    __softboundcets_printf("not implemented\n");
    __softboundcets_abort();
#endif
        
  }

}

#define exchange_elements(i,j) (exchange_elements_helper(base, element_size, (i), (j)))

#define MIN_QSORT_LIST_SIZE 32

__WEAK__ 
void my_qsort(void* base, size_t num_elements, 
              size_t element_size, 
              int (*comparer)(const void*, const void*)){

  size_t i;

  for(i = 0; i < num_elements; i++){
    int j;
    for (j = i - 1; j >= 0; j--){      
      if(element_less_than(j, j + 1)) break;
      exchange_elements(j, j + 1);
    }
  }
  /* may be implement qsort here */

}


__WEAK_INLINE void 
softboundcets_qsort(void* base, size_t nmemb, size_t size, 
                    int (*compar)(const void*, const void*)){

  my_qsort(base, nmemb, size, compar);
  //kenny change the qsort to default glibc for proper performance measurment in mibench/qsort.
  //qsort(base, nmemb, size, compar);
}

#if defined(__linux__)

__WEAK_INLINE 
void softboundcets__obstack_newchunk(struct obstack *obj, int b){
  
  _obstack_newchunk(obj, b);
}

__WEAK_INLINE
int softboundcets__obstack_begin(struct obstack * obj, int a, int b, 
                                 void *(foo) (long), void (bar) (void *)){
  return _obstack_begin(obj, a, b, foo, bar);
}

__WEAK_INLINE
void softboundcets_obstack_free(struct obstack *obj, void *object){
  obstack_free(obj, object);
}


__WEAK_INLINE 
char * softboundcets_nl_langinfo(nl_item item){
  printf("kenny warning: nl_langinfo\n");
  
  char* ret_ptr = nl_langinfo(item);

  __softboundcets_store_return_metadata(ret_ptr, 
                                        ret_ptr + 1024 * 1024,
                                        1, __softboundcets_global_lock);
  
  return ret_ptr;
}

__WEAK_INLINE
int softboundcets_clock_gettime(clockid_t clk_id, struct timespec *tp){
  return clock_gettime(clk_id, tp);
}

#endif

#if 0

int softboundcets__obstack_memory_used(struct obstack *h){
  return _obstack_memory_used(h);
}

#endif
