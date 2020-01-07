#define APPMACROS_ONLY
#include "applink.c"

extern void *OPENSSL_UplinkTable[];

// OfficeDev: make all __cdecl (since OpenSSL's inline assembly code that calls this assumes __cdecl)

#define UP_stdin  (*(void *(__cdecl *)(void))OPENSSL_UplinkTable[APPLINK_STDIN])()
#define UP_stdout (*(void *(__cdecl *)(void))OPENSSL_UplinkTable[APPLINK_STDOUT])()
#define UP_stderr (*(void *(__cdecl *)(void))OPENSSL_UplinkTable[APPLINK_STDERR])()
#define UP_fprintf (*(int (__cdecl *)(void *,const char *,...))OPENSSL_UplinkTable[APPLINK_FPRINTF])
#define UP_fgets  (*(char *(__cdecl *)(char *,int,void *))OPENSSL_UplinkTable[APPLINK_FGETS])
#define UP_fread  (*(size_t (__cdecl *)(void *,size_t,size_t,void *))OPENSSL_UplinkTable[APPLINK_FREAD])
#define UP_fwrite (*(size_t (__cdecl *)(const void *,size_t,size_t,void *))OPENSSL_UplinkTable[APPLINK_FWRITE])
#define UP_fsetmod (*(int (__cdecl *)(void *,char))OPENSSL_UplinkTable[APPLINK_FSETMOD])
#define UP_feof   (*(int (__cdecl *)(void *))OPENSSL_UplinkTable[APPLINK_FEOF])
#define UP_fclose (*(int (__cdecl *)(void *))OPENSSL_UplinkTable[APPLINK_FCLOSE])

#define UP_fopen  (*(void *(__cdecl *)(const char *,const char *))OPENSSL_UplinkTable[APPLINK_FOPEN])
#define UP_fseek  (*(int (__cdecl *)(void *,long,int))OPENSSL_UplinkTable[APPLINK_FSEEK])
#define UP_ftell  (*(long (__cdecl *)(void *))OPENSSL_UplinkTable[APPLINK_FTELL])
#define UP_fflush (*(int (__cdecl *)(void *))OPENSSL_UplinkTable[APPLINK_FFLUSH])
#define UP_ferror (*(int (__cdecl *)(void *))OPENSSL_UplinkTable[APPLINK_FERROR])
#define UP_clearerr (*(void (__cdecl *)(void *))OPENSSL_UplinkTable[APPLINK_CLEARERR])
#define UP_fileno (*(int (__cdecl *)(void *))OPENSSL_UplinkTable[APPLINK_FILENO])

#define UP_open   (*(int (__cdecl *)(const char *,int,...))OPENSSL_UplinkTable[APPLINK_OPEN])
#define UP_read   (*(ossl_ssize_t (__cdecl *)(int,void *,size_t))OPENSSL_UplinkTable[APPLINK_READ])
#define UP_write  (*(ossl_ssize_t (__cdecl *)(int,const void *,size_t))OPENSSL_UplinkTable[APPLINK_WRITE])
#define UP_lseek  (*(long (__cdecl *)(int,long,int))OPENSSL_UplinkTable[APPLINK_LSEEK])
#define UP_close  (*(int (__cdecl *)(int))OPENSSL_UplinkTable[APPLINK_CLOSE])
