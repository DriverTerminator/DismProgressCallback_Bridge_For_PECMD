// main.c
// VS2008 / C89 / pure C
//
// 这个文件同时承担了 4 组职责：
// 1. 保留原始 DismBridge 的“回调桥接”能力。
// 2. 提供一个最小手工映射 DLL 加载器，绕过标准 LoadLibraryW 的导入阶段限制。
// 3. 在手工解析导入表时，定向劫持某些 NT5 不存在的 API。
// 4. 为 bcrypt.dll 的若干哈希接口提供 NT5 可运行的兼容实现。
//
// 当前项目的核心使用场景是：
// - 宿主程序运行在 NT5（XP / 2003）这类老系统上；
// - 目标 DLL 是面向更高版本 Windows 构建的；
// - 目标 DLL 在标准加载阶段会因为缺少某些新 API 而直接失败；
// - 因此改为“手工映射 + 导入替换 + 本地兼容实现”的思路。

#include <windows.h>
#include <excpt.h>
#include <stddef.h>

#if defined(_M_IX86)
EXCEPTION_DISPOSITION __cdecl _except_handler4_common(
    PUINT_PTR cookiePointer,
    void *cookieCheckFunction,
    PEXCEPTION_RECORD exceptionRecord,
    void *establisherFrame,
    PCONTEXT contextRecord,
    PVOID dispatcherContext);
#endif

/*
 * 老工具链 / 老 SDK 里不一定带有较新的 NTSTATUS 常量和 SHA2 算法常量。
 * 这里做本地兜底定义，目的是让 VS2008 + 较旧头文件也能直接编译。
 * 这些值与新系统头文件中的定义保持一致。
 */
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((LONG)0x00000000L)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((LONG)0xC0000023L)
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((LONG)0xC000000DL)
#endif
#ifndef STATUS_NO_MEMORY
#define STATUS_NO_MEMORY ((LONG)0xC0000017L)
#endif
#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED ((LONG)0xC00000BBL)
#endif
#ifndef STATUS_INTERNAL_ERROR
#define STATUS_INTERNAL_ERROR ((LONG)0xC00000E5L)
#endif
#ifndef CALG_SHA_256
#define CALG_SHA_256 (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256)
#endif
#ifndef CALG_SHA_384
#define CALG_SHA_384 (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_384)
#endif
#ifndef CALG_SHA_512
#define CALG_SHA_512 (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_512)
#endif

#define BCRYPT_OBJECT_LENGTH_PROPERTY L"ObjectLength"
#define BCRYPT_HASH_LENGTH_PROPERTY L"HashDigestLength"
#define BCRYPT_HASH_BLOCK_LENGTH_PROPERTY L"HashBlockLength"
#define BCRYPT_ALGORITHM_NAME_PROPERTY L"AlgorithmName"

#define BCRYPT_HANDLE_SIGNATURE_ALG  0x31474142UL
#define BCRYPT_HANDLE_SIGNATURE_HASH 0x48534842UL

/*
 * g_WndProc:
 * 原项目遗留的回调入口，供 SetCallback / DismProgressCallback 使用。
 *
 * g_LastMissingImport*:
 * 手工加载失败时，记录“最后一个缺失的导入”。
 * 这样宿主就不必只看到 ERROR_PROC_NOT_FOUND(127)，
 * 而是能继续问出“究竟是哪个模块 / 哪个导出没找到”。
 */
static WNDPROC g_WndProc = NULL;
static CHAR g_LastMissingImportModule[260] = "";
static CHAR g_LastMissingImportProc[260] = "";
static WORD g_LastMissingImportOrdinal = 0;
static BOOL g_LastMissingImportByOrdinal = FALSE;

typedef BOOL (WINAPI *PFN_DLL_ENTRY)(HINSTANCE, DWORD, LPVOID);
typedef VOID (NTAPI *PFN_TLS_CALLBACK)(PVOID, DWORD, PVOID);

/*
 * 下面这两个结构并不是 Windows 真正的 bcrypt 句柄结构，
 * 而是我们在 NT5 上自行定义的“伪句柄对象”。
 *
 * 思路是：
 * - 对外导出 BCryptOpenAlgorithmProvider / BCryptCreateHash 等接口；
 * - 对内则把这些句柄翻译成 CryptoAPI 的 Provider / Hash；
 * - 这样目标模块仍旧以“bcrypt 风格”调用，但底层实际落到 NT5 可用的 CryptoAPI。
 *
 * Signature 字段的作用：
 * - 在运行期快速判断传进来的句柄是不是我们自己分配的对象；
 * - 防止调用方传入无效指针后直接被当成结构体解引用。
 */
typedef struct _FAKE_BCRYPT_ALG
{
    DWORD Signature;
    ALG_ID AlgId;
    DWORD HashLength;
    DWORD HashBlockLength;
    DWORD ObjectLength;
    HCRYPTPROV Provider;
    WCHAR Name[32];
} FAKE_BCRYPT_ALG;

typedef struct _FAKE_BCRYPT_HASH
{
    DWORD Signature;
    FAKE_BCRYPT_ALG *Algorithm;
    HCRYPTHASH Hash;
} FAKE_BCRYPT_HASH;

/*
 * MANUAL_IMPORT_MODULE:
 * 记录“这次手工加载过程中，由我们主动调用 LoadLibraryA 拉起的依赖模块”。
 * 只有这类模块才应在手工卸载时做对应的 FreeLibrary 平衡引用计数。
 *
 * MANUAL_MODULE:
 * 记录一个手工映射模块的运行期元数据。
 * 之所以单独维护这个结构，是因为单靠模块基址不足以完成完整卸载：
 * - 需要知道它的 NT Headers 位置；
 * - 需要知道它额外拉起了哪些依赖模块；
 * - 需要能从 hMapped 反查回整套上下文。
 */
typedef struct _MANUAL_IMPORT_MODULE
{
    HMODULE ModuleHandle;
    struct _MANUAL_IMPORT_MODULE *Next;
} MANUAL_IMPORT_MODULE;

typedef struct _MANUAL_MODULE
{
    HMODULE ModuleBase;
    PIMAGE_NT_HEADERS NtHeaders;
    DWORD ImageSize;
    MANUAL_IMPORT_MODULE *LoadedImports;
    struct _MANUAL_MODULE *Next;
} MANUAL_MODULE;

static MANUAL_MODULE *g_ManualModules = NULL;

/*
 * 函数声明按功能分组：
 * - PE 手工加载
 * - 导入解析与劫持
 * - bcrypt 兼容层辅助
 * - 错误诊断辅助
 */
static BOOL ReadFileToBuffer(LPCWSTR filePath, BYTE **buffer, DWORD *size);
static BOOL ValidateImage(const BYTE *buffer, PIMAGE_NT_HEADERS *ntHeaders);
static HMODULE MapImageBuffer(const BYTE *buffer, PIMAGE_NT_HEADERS ntHeaders, MANUAL_MODULE *manualModule);
static BOOL CopyImageSections(HMODULE moduleBase, const BYTE *buffer, PIMAGE_NT_HEADERS ntHeaders);
static BOOL ApplyRelocations(HMODULE moduleBase, PIMAGE_NT_HEADERS ntHeaders);
static FARPROC ResolveImportedProc(MANUAL_MODULE *manualModule, LPCSTR moduleName, LPCSTR procName, WORD ordinal);
static BOOL ResolveImports(MANUAL_MODULE *manualModule);
static void ProtectImageSections(HMODULE moduleBase, PIMAGE_NT_HEADERS ntHeaders);
static void RunTlsCallbacks(HMODULE moduleBase, PIMAGE_NT_HEADERS ntHeaders, DWORD reason);
static FARPROC FindExportAddress(HMODULE moduleBase, LPCSTR procName, WORD ordinal, BOOL byOrdinal);
static DWORD SectionCharacteristicsToProtect(DWORD characteristics);
static BOOL NamesEqualInsensitiveA(LPCSTR left, LPCSTR right);
static BOOL IsMsvcrtExceptHandlerImport(LPCSTR moduleName, LPCSTR procName);
static BOOL IsBcryptDestroyHashImport(LPCSTR moduleName, LPCSTR procName);
static BOOL IsBcryptFinishHashImport(LPCSTR moduleName, LPCSTR procName);
static BOOL IsBcryptHashDataImport(LPCSTR moduleName, LPCSTR procName);
static BOOL IsBcryptCreateHashImport(LPCSTR moduleName, LPCSTR procName);
static BOOL IsBcryptGetPropertyImport(LPCSTR moduleName, LPCSTR procName);
static BOOL IsBcryptOpenAlgorithmProviderImport(LPCSTR moduleName, LPCSTR procName);
static BOOL IsBcryptCloseAlgorithmProviderImport(LPCSTR moduleName, LPCSTR procName);
static BOOL TryAcquireHashProvider(ALG_ID algId, HCRYPTPROV *provider);
static BOOL GetAlgorithmDetails(LPCWSTR algorithmName, ALG_ID *algId, DWORD *hashLength, DWORD *hashBlockLength);
static LONG WriteUlongProperty(PUCHAR output, ULONG outputSize, ULONG value, ULONG *resultSize);
static LONG WriteWideStringProperty(PUCHAR output, ULONG outputSize, LPCWSTR value, ULONG *resultSize);
static FAKE_BCRYPT_ALG *GetAlgorithmHandle(PVOID handle);
static FAKE_BCRYPT_HASH *GetHashHandle(PVOID handle);
static BOOL TrackLoadedImport(MANUAL_MODULE *manualModule, HMODULE moduleHandle);
static void ReleaseTrackedImports(MANUAL_MODULE *manualModule);
static void RegisterManualModule(MANUAL_MODULE *manualModule);
static MANUAL_MODULE *DetachManualModule(HMODULE moduleBase);
static void FreeManualModuleRecord(MANUAL_MODULE *manualModule);
static void ClearLastMissingImport(void);
static void RecordMissingImport(LPCSTR moduleName, LPCSTR procName, WORD ordinal, BOOL byOrdinal);
static void CopyAnsiStringA(LPSTR destination, SIZE_T destinationCount, LPCSTR source);

/*
 * 原始桥接接口：
 * 把外部传来的回调函数缓存起来，后续由 DismProgressCallback 转调。
 */
void WINAPI SetCallback(WNDPROC proc)
{
    g_WndProc = proc;
}

/*
 * 原始桥接逻辑：
 * 把 DISM 风格的 3 参数回调，适配成外部需要的 4 参数窗口过程风格。
 *
 * 注意：
 * 这里的参数映射本质上是“协议约定”，不代表语义上真的把 Current 当 HWND 用。
 * 它只是沿用项目原始设计，把 3 个输入塞到调用方期待的 4 个参数槽位里。
 */
VOID CALLBACK DismProgressCallback(
    UINT Current,
    UINT Total,
    PVOID UserData
)
{
    if (g_WndProc)
    {
        g_WndProc(
            (HWND)(ULONG_PTR)Current,
            (UINT)Total,
            (WPARAM)UserData,
            (LPARAM)0
        );
    }
}

PVOID WINAPI GetDismCallback(void)
{
    return (PVOID)DismProgressCallback;
}

/*
 * msvcrt!_except_handler4_common：
 * Win32 下的完整实现见 eh4_x86.c（仅 Win32 平台参与编译）。
 */
#if !defined(_M_IX86)
EXCEPTION_DISPOSITION __cdecl _except_handler4_common(
    PUINT_PTR cookiePointer,
    void *cookieCheckFunction,
    PEXCEPTION_RECORD exceptionRecord,
    void *establisherFrame,
    PCONTEXT contextRecord,
    PVOID dispatcherContext)
{
    (void)cookiePointer;
    (void)cookieCheckFunction;
    (void)exceptionRecord;
    (void)establisherFrame;
    (void)contextRecord;
    (void)dispatcherContext;
    return ExceptionContinueSearch;
}
#endif

/*
 * BCryptDestroyHash:
 * 释放我们自己创建的伪 bcrypt 哈希句柄，并销毁底层 CryptoAPI hash。
 */
LONG WINAPI BCryptDestroyHash(PVOID hHash)
{
    FAKE_BCRYPT_HASH *hashHandle = GetHashHandle(hHash);

    if (!hashHandle)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (hashHandle->Hash)
    {
        CryptDestroyHash(hashHandle->Hash);
    }

    hashHandle->Signature = 0;
    HeapFree(GetProcessHeap(), 0, hashHandle);
    return STATUS_SUCCESS;
}

/*
 * BCryptFinishHash:
 * 从底层 CryptoAPI 取回最终摘要。
 *
 * 与真实 bcrypt 行为相近的部分：
 * - 先查询摘要长度；
 * - 如果调用方缓冲区太小，返回 STATUS_BUFFER_TOO_SMALL；
 * - 长度足够时再写出摘要内容。
 */
LONG WINAPI BCryptFinishHash(PVOID hHash, PUCHAR pbOutput, ULONG cbOutput, ULONG dwFlags)
{
    FAKE_BCRYPT_HASH *hashHandle = GetHashHandle(hHash);
    DWORD hashSize = 0;
    DWORD resultSize = sizeof(hashSize);

    UNREFERENCED_PARAMETER(dwFlags);

    if (!hashHandle || !pbOutput)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (!CryptGetHashParam(hashHandle->Hash, HP_HASHSIZE, (BYTE *)&hashSize, &resultSize, 0))
    {
        return STATUS_INTERNAL_ERROR;
    }

    if (cbOutput < hashSize)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (!CryptGetHashParam(hashHandle->Hash, HP_HASHVAL, pbOutput, &hashSize, 0))
    {
        return STATUS_INTERNAL_ERROR;
    }

    return STATUS_SUCCESS;
}

/*
 * BCryptHashData:
 * 把输入数据继续喂给底层 CryptoAPI hash。
 * 允许空输入直接成功返回，和很多系统 API 的宽松行为一致。
 */
LONG WINAPI BCryptHashData(PVOID hHash, PUCHAR pbInput, ULONG cbInput, ULONG dwFlags)
{
    FAKE_BCRYPT_HASH *hashHandle = GetHashHandle(hHash);

    UNREFERENCED_PARAMETER(dwFlags);

    if (!hashHandle)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (!pbInput || cbInput == 0)
    {
        return STATUS_SUCCESS;
    }

    if (!CryptHashData(hashHandle->Hash, pbInput, cbInput, 0))
    {
        return STATUS_INTERNAL_ERROR;
    }

    return STATUS_SUCCESS;
}

/*
 * BCryptCreateHash:
 * 在某个算法句柄之上创建哈希上下文。
 *
 * 当前限制：
 * - 不支持 keyed hash / HMAC；
 * - 也就是说 pbSecret / cbSecret 只要有值，就直接返回 STATUS_NOT_SUPPORTED。
 */
LONG WINAPI BCryptCreateHash(
    PVOID hAlgorithm,
    PVOID *phHash,
    PUCHAR pbHashObject,
    ULONG cbHashObject,
    PUCHAR pbSecret,
    ULONG cbSecret,
    ULONG dwFlags
)
{
    FAKE_BCRYPT_ALG *algorithmHandle = GetAlgorithmHandle(hAlgorithm);
    FAKE_BCRYPT_HASH *hashHandle;

    UNREFERENCED_PARAMETER(pbHashObject);
    UNREFERENCED_PARAMETER(cbHashObject);
    UNREFERENCED_PARAMETER(dwFlags);

    if (!algorithmHandle || !phHash)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if ((pbSecret && cbSecret) || (!pbSecret && cbSecret))
    {
        return STATUS_NOT_SUPPORTED;
    }

    hashHandle = (FAKE_BCRYPT_HASH *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FAKE_BCRYPT_HASH));
    if (!hashHandle)
    {
        return STATUS_NO_MEMORY;
    }

    hashHandle->Signature = BCRYPT_HANDLE_SIGNATURE_HASH;
    hashHandle->Algorithm = algorithmHandle;

    if (!CryptCreateHash(algorithmHandle->Provider, algorithmHandle->AlgId, 0, 0, &hashHandle->Hash))
    {
        HeapFree(GetProcessHeap(), 0, hashHandle);
        return STATUS_INTERNAL_ERROR;
    }

    *phHash = hashHandle;
    return STATUS_SUCCESS;
}

/*
 * BCryptGetProperty:
 * 目前只实现 tbs.dll 这类调用路径里最常见的几类属性。
 *
 * 如果后面目标模块继续查询新的 bcrypt 属性，
 * 可以在这里继续补分支，而不用动导入劫持层。
 */
LONG WINAPI BCryptGetProperty(
    PVOID hObject,
    LPCWSTR pszProperty,
    PUCHAR pbOutput,
    ULONG cbOutput,
    ULONG *pcbResult,
    ULONG dwFlags
)
{
    FAKE_BCRYPT_ALG *algorithmHandle = GetAlgorithmHandle(hObject);
    FAKE_BCRYPT_HASH *hashHandle = GetHashHandle(hObject);

    UNREFERENCED_PARAMETER(dwFlags);

    if (!pszProperty)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (hashHandle)
    {
        algorithmHandle = hashHandle->Algorithm;
    }

    if (!algorithmHandle)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (lstrcmpiW(pszProperty, BCRYPT_OBJECT_LENGTH_PROPERTY) == 0)
    {
        return WriteUlongProperty(pbOutput, cbOutput, algorithmHandle->ObjectLength, pcbResult);
    }

    if (lstrcmpiW(pszProperty, BCRYPT_HASH_LENGTH_PROPERTY) == 0)
    {
        return WriteUlongProperty(pbOutput, cbOutput, algorithmHandle->HashLength, pcbResult);
    }

    if (lstrcmpiW(pszProperty, BCRYPT_HASH_BLOCK_LENGTH_PROPERTY) == 0)
    {
        return WriteUlongProperty(pbOutput, cbOutput, algorithmHandle->HashBlockLength, pcbResult);
    }

    if (lstrcmpiW(pszProperty, BCRYPT_ALGORITHM_NAME_PROPERTY) == 0)
    {
        return WriteWideStringProperty(pbOutput, cbOutput, algorithmHandle->Name, pcbResult);
    }

    return STATUS_NOT_SUPPORTED;
}

/*
 * BCryptOpenAlgorithmProvider:
 * 把“算法名字符串”翻译成 NT5 上可用的 CryptoAPI 算法与 Provider。
 *
 * 这里创建的是一个我们自定义的算法对象：
 * - 记录算法 ID；
 * - 记录摘要长度 / 分组长度；
 * - 记录底层 Provider；
 * - 供后续 CreateHash / GetProperty 使用。
 */
LONG WINAPI BCryptOpenAlgorithmProvider(
    PVOID *phAlgorithm,
    LPCWSTR pszAlgId,
    LPCWSTR pszImplementation,
    ULONG dwFlags
)
{
    ALG_ID algId;
    DWORD hashLength;
    DWORD hashBlockLength;
    FAKE_BCRYPT_ALG *algorithmHandle;

    UNREFERENCED_PARAMETER(pszImplementation);
    UNREFERENCED_PARAMETER(dwFlags);

    if (!phAlgorithm || !pszAlgId)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (!GetAlgorithmDetails(pszAlgId, &algId, &hashLength, &hashBlockLength))
    {
        return STATUS_NOT_SUPPORTED;
    }

    algorithmHandle = (FAKE_BCRYPT_ALG *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FAKE_BCRYPT_ALG));
    if (!algorithmHandle)
    {
        return STATUS_NO_MEMORY;
    }

    algorithmHandle->Signature = BCRYPT_HANDLE_SIGNATURE_ALG;
    algorithmHandle->AlgId = algId;
    algorithmHandle->HashLength = hashLength;
    algorithmHandle->HashBlockLength = hashBlockLength;
    algorithmHandle->ObjectLength = sizeof(FAKE_BCRYPT_HASH);
    lstrcpynW(algorithmHandle->Name, pszAlgId, sizeof(algorithmHandle->Name) / sizeof(algorithmHandle->Name[0]));

    if (!TryAcquireHashProvider(algId, &algorithmHandle->Provider))
    {
        HeapFree(GetProcessHeap(), 0, algorithmHandle);
        return STATUS_NOT_SUPPORTED;
    }

    *phAlgorithm = algorithmHandle;
    return STATUS_SUCCESS;
}

/*
 * BCryptCloseAlgorithmProvider:
 * 关闭算法对象并释放底层 Provider。
 */
LONG WINAPI BCryptCloseAlgorithmProvider(PVOID hAlgorithm, ULONG dwFlags)
{
    FAKE_BCRYPT_ALG *algorithmHandle = GetAlgorithmHandle(hAlgorithm);

    UNREFERENCED_PARAMETER(dwFlags);

    if (!algorithmHandle)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (algorithmHandle->Provider)
    {
        CryptReleaseContext(algorithmHandle->Provider, 0);
    }

    algorithmHandle->Signature = 0;
    HeapFree(GetProcessHeap(), 0, algorithmHandle);
    return STATUS_SUCCESS;
}

/*
 * 下面三个接口是给宿主程序用的诊断辅助：
 * - GetLastMissingImportModuleA  -> 缺失模块名
 * - GetLastMissingImportProcA    -> 缺失函数名
 * - GetLastMissingImportOrdinal  -> 缺失序号导入
 */
LPCSTR WINAPI GetLastMissingImportModuleA(void)
{
    return g_LastMissingImportModule;
}

LPCSTR WINAPI GetLastMissingImportProcA(void)
{
    return g_LastMissingImportProc;
}

DWORD WINAPI GetLastMissingImportOrdinal(void)
{
    return g_LastMissingImportByOrdinal ? (DWORD)g_LastMissingImportOrdinal : 0;
}

/*
 * 手工卸载入口：
 * - 反查出模块对应的元数据；
 * - 调用 DllMain(DLL_PROCESS_DETACH)；
 * - 补发 TLS 的 DLL_PROCESS_DETACH；
 * - 平衡释放加载时额外拉起的依赖模块；
 * - 最后释放整块手工映射镜像和元数据本身。
 *
 * 注意：
 * 这里释放的是“由 LoadTargetLibraryW 手工映射”的模块，
 * 不能拿来卸载系统正常 LoadLibrary 得到的模块句柄。
 */
BOOL WINAPI UnloadTargetLibrary(HMODULE moduleBase)
{
    MANUAL_MODULE *manualModule;
    PFN_DLL_ENTRY dllMain;

    if (!moduleBase)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    manualModule = DetachManualModule(moduleBase);
    if (!manualModule)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    dllMain = NULL;
    if (manualModule->NtHeaders &&
        manualModule->NtHeaders->OptionalHeader.AddressOfEntryPoint != 0)
    {
        dllMain = (PFN_DLL_ENTRY)((BYTE *)moduleBase +
            manualModule->NtHeaders->OptionalHeader.AddressOfEntryPoint);
    }

    if (dllMain)
    {
        dllMain((HINSTANCE)moduleBase, DLL_PROCESS_DETACH, NULL);
    }

    if (manualModule->NtHeaders)
    {
        RunTlsCallbacks(moduleBase, manualModule->NtHeaders, DLL_PROCESS_DETACH);
    }

    ReleaseTrackedImports(manualModule);
    VirtualFree(moduleBase, 0, MEM_RELEASE);
    FreeManualModuleRecord(manualModule);
    return TRUE;
}

/*
 * 手工加载入口：
 * 1. 读入整个目标 DLL 文件；
 * 2. 校验 PE 头；
 * 3. 手工映射镜像；
 * 4. 运行 TLS 回调；
 * 5. 调用 DllMain(DLL_PROCESS_ATTACH)；
 * 6. 返回“映射基址”作为宿主继续操作的句柄。
 *
 * 注意：
 * 返回值只是我们自己映射出来的模块基址，
 * 不是系统 loader 维护的 HMODULE，因此后续导出查询要用 GetMappedProcAddress。
 */
HMODULE WINAPI LoadTargetLibraryW(LPCWSTR filePath)
{
    BYTE *buffer = NULL;
    DWORD size = 0;
    PIMAGE_NT_HEADERS ntHeaders = NULL;
    HMODULE moduleBase = NULL;
    PFN_DLL_ENTRY dllMain = NULL;
    MANUAL_MODULE *manualModule = NULL;

    if (!filePath || !filePath[0])
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    ClearLastMissingImport();

    if (!ReadFileToBuffer(filePath, &buffer, &size))
    {
        return NULL;
    }

    if (!ValidateImage(buffer, &ntHeaders))
    {
        LocalFree(buffer);
        return NULL;
    }

    UNREFERENCED_PARAMETER(size);

    manualModule = (MANUAL_MODULE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MANUAL_MODULE));
    if (!manualModule)
    {
        LocalFree(buffer);
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }

    moduleBase = MapImageBuffer(buffer, ntHeaders, manualModule);
    LocalFree(buffer);

    if (!moduleBase)
    {
        FreeManualModuleRecord(manualModule);
        return NULL;
    }

    dllMain = (PFN_DLL_ENTRY)((BYTE *)moduleBase +
        ntHeaders->OptionalHeader.AddressOfEntryPoint);

    if (ntHeaders->OptionalHeader.AddressOfEntryPoint != 0)
    {
        if (!dllMain((HINSTANCE)moduleBase, DLL_PROCESS_ATTACH, NULL))
        {
            ReleaseTrackedImports(manualModule);
            VirtualFree(moduleBase, 0, MEM_RELEASE);
            FreeManualModuleRecord(manualModule);
            SetLastError(ERROR_DLL_INIT_FAILED);
            return NULL;
        }
    }

    RegisterManualModule(manualModule);
    return moduleBase;
}

/*
 * 手工模块版 GetProcAddress：
 * 在我们自己映射出来的镜像里查导出，不能直接调用系统 GetProcAddress。
 */
FARPROC WINAPI GetMappedProcAddress(HMODULE moduleBase, LPCSTR procName)
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;

    if (!moduleBase || !procName)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return NULL;
    }

    ntHeaders = (PIMAGE_NT_HEADERS)((BYTE *)moduleBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return NULL;
    }

    return FindExportAddress(moduleBase, procName, 0, FALSE);
}

/*
 * 把整个 DLL 文件读入内存。
 * 手工映射的第一步不是让系统加载，而是先把原始文件字节完整拿到手。
 */
static BOOL ReadFileToBuffer(LPCWSTR filePath, BYTE **buffer, DWORD *size)
{
    HANDLE fileHandle;
    LARGE_INTEGER fileSize;
    BYTE *localBuffer;
    DWORD bytesRead;

    *buffer = NULL;
    *size = 0;

    fileHandle = CreateFileW(
        filePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    if (!GetFileSizeEx(fileHandle, &fileSize))
    {
        CloseHandle(fileHandle);
        return FALSE;
    }

    if (fileSize.QuadPart <= 0 || fileSize.QuadPart > 0x7fffffff)
    {
        CloseHandle(fileHandle);
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return FALSE;
    }

    localBuffer = (BYTE *)LocalAlloc(LMEM_FIXED, (SIZE_T)fileSize.QuadPart);
    if (!localBuffer)
    {
        CloseHandle(fileHandle);
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }

    if (!ReadFile(fileHandle, localBuffer, (DWORD)fileSize.QuadPart, &bytesRead, NULL) ||
        bytesRead != (DWORD)fileSize.QuadPart)
    {
        DWORD lastError = GetLastError();
        LocalFree(localBuffer);
        CloseHandle(fileHandle);
        SetLastError(lastError ? lastError : ERROR_READ_FAULT);
        return FALSE;
    }

    CloseHandle(fileHandle);

    *buffer = localBuffer;
    *size = (DWORD)fileSize.QuadPart;
    return TRUE;
}

/*
 * 校验输入缓冲是不是一个 DLL PE。
 * 这里只做“能否继续手工映射”的最小必要检查，不做更重的完整性验证。
 */
static BOOL ValidateImage(const BYTE *buffer, PIMAGE_NT_HEADERS *ntHeaders)
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS localNtHeaders;

    if (!buffer)
    {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return FALSE;
    }

    dosHeader = (PIMAGE_DOS_HEADER)buffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return FALSE;
    }

    localNtHeaders = (PIMAGE_NT_HEADERS)(buffer + dosHeader->e_lfanew);
    if (localNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return FALSE;
    }

    if (localNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL)
    {
        *ntHeaders = localNtHeaders;
        return TRUE;
    }

    SetLastError(ERROR_BAD_EXE_FORMAT);
    return FALSE;
}

/*
 * 手工映射核心流程：
 * - 优先尝试按目标首选基址分配；
 * - 如果失败，再随机找一块可用地址；
 * - 拷贝 PE 头与节区；
 * - 做重定位；
 * - 修导入；
 * - 运行 TLS；
 * - 恢复各节保护属性。
 */
static HMODULE MapImageBuffer(const BYTE *buffer, PIMAGE_NT_HEADERS ntHeaders, MANUAL_MODULE *manualModule)
{
    HMODULE moduleBase;

    moduleBase = (HMODULE)VirtualAlloc(
        (LPVOID)(ULONG_PTR)ntHeaders->OptionalHeader.ImageBase,
        ntHeaders->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );

    if (!moduleBase)
    {
        moduleBase = (HMODULE)VirtualAlloc(
            NULL,
            ntHeaders->OptionalHeader.SizeOfImage,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE
        );
    }

    if (!moduleBase)
    {
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }

    CopyMemory(
        moduleBase,
        buffer,
        ntHeaders->OptionalHeader.SizeOfHeaders
    );

    manualModule->ModuleBase = moduleBase;
    manualModule->NtHeaders = (PIMAGE_NT_HEADERS)((BYTE *)moduleBase +
        ((PIMAGE_DOS_HEADER)moduleBase)->e_lfanew);
    manualModule->ImageSize = ntHeaders->OptionalHeader.SizeOfImage;

    if (!CopyImageSections(moduleBase, buffer, ntHeaders) ||
        !ApplyRelocations(moduleBase, ntHeaders) ||
        !ResolveImports(manualModule))
    {
        DWORD lastError = GetLastError();
        ReleaseTrackedImports(manualModule);
        VirtualFree(moduleBase, 0, MEM_RELEASE);
        SetLastError(lastError);
        return NULL;
    }

    RunTlsCallbacks(moduleBase, ntHeaders, DLL_PROCESS_ATTACH);
    ProtectImageSections(moduleBase, ntHeaders);
    FlushInstructionCache(GetCurrentProcess(), moduleBase, ntHeaders->OptionalHeader.SizeOfImage);

    return moduleBase;
}

/*
 * 把文件中的每个节复制到内存镜像中。
 * 这里的 destination 是“运行期虚拟地址”，不是文件偏移。
 */
static BOOL CopyImageSections(HMODULE moduleBase, const BYTE *buffer, PIMAGE_NT_HEADERS ntHeaders)
{
    PIMAGE_SECTION_HEADER section;
    WORD index;

    section = IMAGE_FIRST_SECTION(ntHeaders);

    for (index = 0; index < ntHeaders->FileHeader.NumberOfSections; ++index, ++section)
    {
        BYTE *destination = (BYTE *)moduleBase + section->VirtualAddress;
        DWORD rawSize = section->SizeOfRawData;
        DWORD virtualSize = section->Misc.VirtualSize;
        DWORD totalSize = virtualSize > rawSize ? virtualSize : rawSize;

        if (totalSize)
        {
            ZeroMemory(destination, totalSize);
        }

        if (rawSize)
        {
            CopyMemory(destination, buffer + section->PointerToRawData, rawSize);
        }
    }

    return TRUE;
}

/*
 * 处理基址重定位。
 * 如果镜像没能分配到首选 ImageBase，就必须把所有绝对地址修正到新基址。
 */
static BOOL ApplyRelocations(HMODULE moduleBase, PIMAGE_NT_HEADERS ntHeaders)
{
    DWORD relocRva;
    DWORD relocSize;
    BYTE *relocBase;
    BYTE *relocEnd;
    ULONG_PTR delta;

    delta = (ULONG_PTR)moduleBase - (ULONG_PTR)ntHeaders->OptionalHeader.ImageBase;
    if (delta == 0)
    {
        return TRUE;
    }

    relocRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    relocSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    if (relocRva == 0 || relocSize == 0)
    {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return FALSE;
    }

    relocBase = (BYTE *)moduleBase + relocRva;
    relocEnd = relocBase + relocSize;

    while (relocBase < relocEnd)
    {
        PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)relocBase;
        WORD *entry = (WORD *)(reloc + 1);
        DWORD count;
        DWORD entryIndex;

        if (reloc->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
        {
            break;
        }

        count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        for (entryIndex = 0; entryIndex < count; ++entryIndex)
        {
            WORD type = (WORD)(entry[entryIndex] >> 12);
            WORD offset = (WORD)(entry[entryIndex] & 0x0fff);
            BYTE *patchAddress = (BYTE *)moduleBase + reloc->VirtualAddress + offset;

            switch (type)
            {
            case IMAGE_REL_BASED_ABSOLUTE:
                break;

            case IMAGE_REL_BASED_HIGHLOW:
                *(DWORD *)patchAddress += (DWORD)delta;
                break;

#ifdef _WIN64
            case IMAGE_REL_BASED_DIR64:
                *(ULONGLONG *)patchAddress += (ULONGLONG)delta;
                break;
#endif

            default:
                SetLastError(ERROR_BAD_EXE_FORMAT);
                return FALSE;
            }
        }

        relocBase += reloc->SizeOfBlock;
    }

    return TRUE;
}

/*
 * 单个导入解析器：
 * - 先看是否命中我们要“手工接管”的兼容 API；
 * - 如果命中，直接返回本项目内的替代实现地址；
 * - 否则再退回到真实系统模块的 GetProcAddress。
 *
 * 这个函数是整个兼容层的关键：
 * 标准 LoadLibraryW 在导入阶段失败的地方，
 * 我们就是在这里把它改造成“由自己决定导向哪里”。
 */
static FARPROC ResolveImportedProc(MANUAL_MODULE *manualModule, LPCSTR moduleName, LPCSTR procName, WORD ordinal)
{
    HMODULE importModule;
    BOOL loadedNow;

    if (IsMsvcrtExceptHandlerImport(moduleName, procName))
    {
        UNREFERENCED_PARAMETER(manualModule);
        UNREFERENCED_PARAMETER(ordinal);
        return (FARPROC)_except_handler4_common;
    }

    if (IsBcryptDestroyHashImport(moduleName, procName))
    {
        UNREFERENCED_PARAMETER(manualModule);
        UNREFERENCED_PARAMETER(ordinal);
        return (FARPROC)BCryptDestroyHash;
    }

    if (IsBcryptFinishHashImport(moduleName, procName))
    {
        UNREFERENCED_PARAMETER(manualModule);
        UNREFERENCED_PARAMETER(ordinal);
        return (FARPROC)BCryptFinishHash;
    }

    if (IsBcryptHashDataImport(moduleName, procName))
    {
        UNREFERENCED_PARAMETER(manualModule);
        UNREFERENCED_PARAMETER(ordinal);
        return (FARPROC)BCryptHashData;
    }

    if (IsBcryptCreateHashImport(moduleName, procName))
    {
        UNREFERENCED_PARAMETER(manualModule);
        UNREFERENCED_PARAMETER(ordinal);
        return (FARPROC)BCryptCreateHash;
    }

    if (IsBcryptGetPropertyImport(moduleName, procName))
    {
        UNREFERENCED_PARAMETER(manualModule);
        UNREFERENCED_PARAMETER(ordinal);
        return (FARPROC)BCryptGetProperty;
    }

    if (IsBcryptOpenAlgorithmProviderImport(moduleName, procName))
    {
        UNREFERENCED_PARAMETER(manualModule);
        UNREFERENCED_PARAMETER(ordinal);
        return (FARPROC)BCryptOpenAlgorithmProvider;
    }

    if (IsBcryptCloseAlgorithmProviderImport(moduleName, procName))
    {
        UNREFERENCED_PARAMETER(manualModule);
        UNREFERENCED_PARAMETER(ordinal);
        return (FARPROC)BCryptCloseAlgorithmProvider;
    }

    loadedNow = FALSE;
    importModule = GetModuleHandleA(moduleName);
    if (!importModule)
    {
        importModule = LoadLibraryA(moduleName);
        loadedNow = (importModule != NULL);
    }

    if (!importModule)
    {
        return NULL;
    }

    if (loadedNow && !TrackLoadedImport(manualModule, importModule))
    {
        FreeLibrary(importModule);
        SetLastError(ERROR_OUTOFMEMORY);
        return NULL;
    }

    if (procName)
    {
        return GetProcAddress(importModule, procName);
    }

    return GetProcAddress(importModule, (LPCSTR)(ULONG_PTR)ordinal);
}

/*
 * 遍历 IMAGE_IMPORT_DESCRIPTOR，逐个修补 IAT。
 *
 * 一旦某个导入解析失败：
 * - 立即记录缺失模块 / 函数 / 序号；
 * - 设置 ERROR_PROC_NOT_FOUND；
 * - 终止整个手工映射流程。
 */
static BOOL ResolveImports(MANUAL_MODULE *manualModule)
{
    DWORD importRva;
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor;
    HMODULE moduleBase;
    PIMAGE_NT_HEADERS ntHeaders;

    moduleBase = manualModule->ModuleBase;
    ntHeaders = manualModule->NtHeaders;
    importRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRva == 0)
    {
        return TRUE;
    }

    importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)moduleBase + importRva);

    while (importDescriptor->Name)
    {
        LPCSTR moduleName = (LPCSTR)((BYTE *)moduleBase + importDescriptor->Name);
        PIMAGE_THUNK_DATA lookupThunk;
        PIMAGE_THUNK_DATA addressThunk;

        if (importDescriptor->OriginalFirstThunk)
        {
            lookupThunk = (PIMAGE_THUNK_DATA)((BYTE *)moduleBase + importDescriptor->OriginalFirstThunk);
        }
        else
        {
            lookupThunk = (PIMAGE_THUNK_DATA)((BYTE *)moduleBase + importDescriptor->FirstThunk);
        }

        addressThunk = (PIMAGE_THUNK_DATA)((BYTE *)moduleBase + importDescriptor->FirstThunk);

        while (lookupThunk->u1.AddressOfData)
        {
            FARPROC procAddress;
            LPCSTR currentProcName = NULL;
            WORD currentOrdinal = 0;
            BOOL currentByOrdinal = FALSE;

            if (IMAGE_SNAP_BY_ORDINAL(lookupThunk->u1.Ordinal))
            {
                currentOrdinal = (WORD)IMAGE_ORDINAL(lookupThunk->u1.Ordinal);
                currentByOrdinal = TRUE;
                procAddress = ResolveImportedProc(
                    manualModule,
                    moduleName,
                    NULL,
                    currentOrdinal
                );
            }
            else
            {
                PIMAGE_IMPORT_BY_NAME importByName =
                    (PIMAGE_IMPORT_BY_NAME)((BYTE *)moduleBase + lookupThunk->u1.AddressOfData);

                currentProcName = (LPCSTR)importByName->Name;
                procAddress = ResolveImportedProc(
                    manualModule,
                    moduleName,
                    currentProcName,
                    0
                );
            }

            if (!procAddress)
            {
                RecordMissingImport(
                    moduleName,
                    currentProcName,
                    currentOrdinal,
                    currentByOrdinal
                );
                SetLastError(ERROR_PROC_NOT_FOUND);
                return FALSE;
            }

#ifdef _WIN64
            addressThunk->u1.Function = (ULONGLONG)(ULONG_PTR)procAddress;
#else
            addressThunk->u1.Function = (DWORD)(ULONG_PTR)procAddress;
#endif

            ++lookupThunk;
            ++addressThunk;
        }

        ++importDescriptor;
    }

    return TRUE;
}

/*
 * 根据 PE 节属性换算成 Win32 页面保护常量。
 * 这样映射完成后，代码节、只读节、可写节会尽量恢复到接近真实 loader 的状态。
 */
static DWORD SectionCharacteristicsToProtect(DWORD characteristics)
{
    BOOL canRead = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    BOOL canWrite = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    BOOL canExecute = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

    if (canExecute)
    {
        if (canWrite)
        {
            return canRead ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_WRITECOPY;
        }

        return canRead ? PAGE_EXECUTE_READ : PAGE_EXECUTE;
    }

    if (canWrite)
    {
        return canRead ? PAGE_READWRITE : PAGE_WRITECOPY;
    }

    return canRead ? PAGE_READONLY : PAGE_NOACCESS;
}

/*
 * 恢复各节的页面保护属性。
 * 手工映射初期统一用了 PAGE_READWRITE，完成修补后再按节属性改回去。
 */
static void ProtectImageSections(HMODULE moduleBase, PIMAGE_NT_HEADERS ntHeaders)
{
    PIMAGE_SECTION_HEADER section;
    WORD index;

    section = IMAGE_FIRST_SECTION(ntHeaders);

    for (index = 0; index < ntHeaders->FileHeader.NumberOfSections; ++index, ++section)
    {
        DWORD oldProtect;
        DWORD sectionSize = section->Misc.VirtualSize;

        if (sectionSize == 0)
        {
            sectionSize = section->SizeOfRawData;
        }

        if (sectionSize == 0)
        {
            continue;
        }

        VirtualProtect(
            (BYTE *)moduleBase + section->VirtualAddress,
            sectionSize,
            SectionCharacteristicsToProtect(section->Characteristics),
            &oldProtect
        );
    }
}

/*
 * 运行 TLS 回调。
 * 有些 DLL 的初始化逻辑并不只在 DllMain 里，还会放在 TLS callback 中。
 * 如果不主动执行，某些模块虽然“加载成功”，但状态并不完整。
 */
static void RunTlsCallbacks(HMODULE moduleBase, PIMAGE_NT_HEADERS ntHeaders, DWORD reason)
{
    DWORD tlsRva;
    PIMAGE_TLS_DIRECTORY tlsDirectory;
    PIMAGE_TLS_CALLBACK *callback;

    tlsRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (tlsRva == 0)
    {
        return;
    }

    tlsDirectory = (PIMAGE_TLS_DIRECTORY)((BYTE *)moduleBase + tlsRva);
    if (!tlsDirectory->AddressOfCallBacks)
    {
        return;
    }

    callback = (PIMAGE_TLS_CALLBACK *)(ULONG_PTR)tlsDirectory->AddressOfCallBacks;
    while (*callback)
    {
        (*callback)((LPVOID)moduleBase, reason, NULL);
        ++callback;
    }
}

/*
 * 手工导出查询。
 * 同时支持按名称和按序号查找。
 */
static FARPROC FindExportAddress(HMODULE moduleBase, LPCSTR procName, WORD ordinal, BOOL byOrdinal)
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    DWORD exportRva;
    PIMAGE_EXPORT_DIRECTORY exportDirectory;
    DWORD *functionTable;
    DWORD *nameTable;
    WORD *ordinalTable;
    DWORD index;

    dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    ntHeaders = (PIMAGE_NT_HEADERS)((BYTE *)moduleBase + dosHeader->e_lfanew);
    exportRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    if (exportRva == 0)
    {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return NULL;
    }

    exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)moduleBase + exportRva);
    functionTable = (DWORD *)((BYTE *)moduleBase + exportDirectory->AddressOfFunctions);
    nameTable = (DWORD *)((BYTE *)moduleBase + exportDirectory->AddressOfNames);
    ordinalTable = (WORD *)((BYTE *)moduleBase + exportDirectory->AddressOfNameOrdinals);

    if (byOrdinal)
    {
        DWORD functionIndex;

        if (ordinal < exportDirectory->Base)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return NULL;
        }

        functionIndex = ordinal - (WORD)exportDirectory->Base;
        if (functionIndex >= exportDirectory->NumberOfFunctions)
        {
            SetLastError(ERROR_PROC_NOT_FOUND);
            return NULL;
        }

        return (FARPROC)((BYTE *)moduleBase + functionTable[functionIndex]);
    }

    for (index = 0; index < exportDirectory->NumberOfNames; ++index)
    {
        LPCSTR exportName = (LPCSTR)((BYTE *)moduleBase + nameTable[index]);

        if (lstrcmpA(exportName, procName) == 0)
        {
            WORD functionIndex = ordinalTable[index];
            return (FARPROC)((BYTE *)moduleBase + functionTable[functionIndex]);
        }
    }

    SetLastError(ERROR_PROC_NOT_FOUND);
    return NULL;
}

/*
 * 一个非常保守的 ASCII 不区分大小写比较。
 * 这里不依赖额外 CRT 行为，方便老环境下保持可控。
 */
static BOOL NamesEqualInsensitiveA(LPCSTR left, LPCSTR right)
{
    CHAR leftChar;
    CHAR rightChar;

    if (!left || !right)
    {
        return FALSE;
    }

    for (;;)
    {
        leftChar = *left++;
        rightChar = *right++;

        if (leftChar >= 'A' && leftChar <= 'Z')
        {
            leftChar = (CHAR)(leftChar - 'A' + 'a');
        }

        if (rightChar >= 'A' && rightChar <= 'Z')
        {
            rightChar = (CHAR)(rightChar - 'A' + 'a');
        }

        if (leftChar != rightChar)
        {
            return FALSE;
        }

        if (leftChar == '\0')
        {
            return TRUE;
        }
    }
}

/*
 * 下面这一组 IsXxxImport 函数只做一件事：
 * 判断“当前导入的模块名 + 符号名”是不是我们要接管的目标。
 *
 * 这样 ResolveImportedProc 可以保持清晰，
 * 不会把一长串字符串比较逻辑全部堆在主流程里。
 */
static BOOL IsMsvcrtExceptHandlerImport(LPCSTR moduleName, LPCSTR procName)
{
    if (!procName)
    {
        return FALSE;
    }

    if (!NamesEqualInsensitiveA(procName, "_except_handler4_common"))
    {
        return FALSE;
    }

    return
        NamesEqualInsensitiveA(moduleName, "msvcrt.dll") ||
        NamesEqualInsensitiveA(moduleName, "msvcr71.dll") ||
        NamesEqualInsensitiveA(moduleName, "msvcr80.dll") ||
        NamesEqualInsensitiveA(moduleName, "msvcr90.dll") ||
        NamesEqualInsensitiveA(moduleName, "msvcr100.dll") ||
        NamesEqualInsensitiveA(moduleName, "msvcr110.dll") ||
        NamesEqualInsensitiveA(moduleName, "msvcr120.dll");
}

static BOOL IsBcryptDestroyHashImport(LPCSTR moduleName, LPCSTR procName)
{
    return
        procName &&
        NamesEqualInsensitiveA(moduleName, "bcrypt.dll") &&
        NamesEqualInsensitiveA(procName, "BCryptDestroyHash");
}

static BOOL IsBcryptFinishHashImport(LPCSTR moduleName, LPCSTR procName)
{
    return
        procName &&
        NamesEqualInsensitiveA(moduleName, "bcrypt.dll") &&
        NamesEqualInsensitiveA(procName, "BCryptFinishHash");
}

static BOOL IsBcryptHashDataImport(LPCSTR moduleName, LPCSTR procName)
{
    return
        procName &&
        NamesEqualInsensitiveA(moduleName, "bcrypt.dll") &&
        NamesEqualInsensitiveA(procName, "BCryptHashData");
}

static BOOL IsBcryptCreateHashImport(LPCSTR moduleName, LPCSTR procName)
{
    return
        procName &&
        NamesEqualInsensitiveA(moduleName, "bcrypt.dll") &&
        NamesEqualInsensitiveA(procName, "BCryptCreateHash");
}

static BOOL IsBcryptGetPropertyImport(LPCSTR moduleName, LPCSTR procName)
{
    return
        procName &&
        NamesEqualInsensitiveA(moduleName, "bcrypt.dll") &&
        NamesEqualInsensitiveA(procName, "BCryptGetProperty");
}

static BOOL IsBcryptOpenAlgorithmProviderImport(LPCSTR moduleName, LPCSTR procName)
{
    return
        procName &&
        NamesEqualInsensitiveA(moduleName, "bcrypt.dll") &&
        NamesEqualInsensitiveA(procName, "BCryptOpenAlgorithmProvider");
}

static BOOL IsBcryptCloseAlgorithmProviderImport(LPCSTR moduleName, LPCSTR procName)
{
    return
        procName &&
        NamesEqualInsensitiveA(moduleName, "bcrypt.dll") &&
        NamesEqualInsensitiveA(procName, "BCryptCloseAlgorithmProvider");
}

static BOOL TryAcquireHashProvider(ALG_ID algId, HCRYPTPROV *provider)
{
    DWORD providerType;

    if (!provider)
    {
        return FALSE;
    }

    *provider = 0;
    providerType = (algId == CALG_MD5 || algId == CALG_SHA1) ? PROV_RSA_FULL : PROV_RSA_AES;

    if (CryptAcquireContextW(provider, NULL, MS_ENH_RSA_AES_PROV_W, providerType, CRYPT_VERIFYCONTEXT))
    {
        return TRUE;
    }

    if ((algId == CALG_MD5 || algId == CALG_SHA1) &&
        CryptAcquireContextW(provider, NULL, MS_ENHANCED_PROV_W, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        return TRUE;
    }

    return FALSE;
}

/*
 * 把 bcrypt 的算法名翻译成 CryptoAPI 可识别的算法与固定参数。
 * 当前只实现本项目已经需要到的常见摘要算法。
 */
static BOOL GetAlgorithmDetails(LPCWSTR algorithmName, ALG_ID *algId, DWORD *hashLength, DWORD *hashBlockLength)
{
    if (!algorithmName || !algId || !hashLength || !hashBlockLength)
    {
        return FALSE;
    }

    if (lstrcmpiW(algorithmName, L"MD5") == 0)
    {
        *algId = CALG_MD5;
        *hashLength = 16;
        *hashBlockLength = 64;
        return TRUE;
    }

    if (lstrcmpiW(algorithmName, L"SHA1") == 0 || lstrcmpiW(algorithmName, L"SHA-1") == 0)
    {
        *algId = CALG_SHA1;
        *hashLength = 20;
        *hashBlockLength = 64;
        return TRUE;
    }

    if (lstrcmpiW(algorithmName, L"SHA256") == 0 || lstrcmpiW(algorithmName, L"SHA-256") == 0)
    {
        *algId = CALG_SHA_256;
        *hashLength = 32;
        *hashBlockLength = 64;
        return TRUE;
    }

    if (lstrcmpiW(algorithmName, L"SHA384") == 0 || lstrcmpiW(algorithmName, L"SHA-384") == 0)
    {
        *algId = CALG_SHA_384;
        *hashLength = 48;
        *hashBlockLength = 128;
        return TRUE;
    }

    if (lstrcmpiW(algorithmName, L"SHA512") == 0 || lstrcmpiW(algorithmName, L"SHA-512") == 0)
    {
        *algId = CALG_SHA_512;
        *hashLength = 64;
        *hashBlockLength = 128;
        return TRUE;
    }

    return FALSE;
}

/*
 * 把 ULONG 属性写入调用方缓冲区。
 * 这是 BCryptGetProperty 的一个小辅助，避免重复写缓冲区长度检查。
 */
static LONG WriteUlongProperty(PUCHAR output, ULONG outputSize, ULONG value, ULONG *resultSize)
{
    if (resultSize)
    {
        *resultSize = sizeof(ULONG);
    }

    if (!output || outputSize < sizeof(ULONG))
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    *(ULONG *)output = value;
    return STATUS_SUCCESS;
}

/*
 * 把宽字符串属性写入调用方缓冲区。
 * 这里返回的大小单位是字节，与系统 API 的常见约定一致。
 */
static LONG WriteWideStringProperty(PUCHAR output, ULONG outputSize, LPCWSTR value, ULONG *resultSize)
{
    ULONG bytesRequired;

    if (!value)
    {
        return STATUS_INVALID_PARAMETER;
    }

    bytesRequired = ((ULONG)lstrlenW(value) + 1) * sizeof(WCHAR);

    if (resultSize)
    {
        *resultSize = bytesRequired;
    }

    if (!output || outputSize < bytesRequired)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    CopyMemory(output, value, bytesRequired);
    return STATUS_SUCCESS;
}

/*
 * 从外部传入句柄中还原我们自己的算法对象 / 哈希对象。
 * 通过 Signature 做最小合法性校验。
 */
static FAKE_BCRYPT_ALG *GetAlgorithmHandle(PVOID handle)
{
    FAKE_BCRYPT_ALG *algorithmHandle = (FAKE_BCRYPT_ALG *)handle;

    if (!algorithmHandle || algorithmHandle->Signature != BCRYPT_HANDLE_SIGNATURE_ALG)
    {
        return NULL;
    }

    return algorithmHandle;
}

static FAKE_BCRYPT_HASH *GetHashHandle(PVOID handle)
{
    FAKE_BCRYPT_HASH *hashHandle = (FAKE_BCRYPT_HASH *)handle;

    if (!hashHandle || hashHandle->Signature != BCRYPT_HANDLE_SIGNATURE_HASH)
    {
        return NULL;
    }

    return hashHandle;
}

/*
 * 把一个“由我们主动 LoadLibraryA 拉起”的依赖模块登记到当前手工模块下。
 * 卸载时只平衡释放这些登记过的模块，避免误释放原本就在进程里的系统模块。
 */
static BOOL TrackLoadedImport(MANUAL_MODULE *manualModule, HMODULE moduleHandle)
{
    MANUAL_IMPORT_MODULE *importNode;

    if (!manualModule || !moduleHandle)
    {
        return FALSE;
    }

    importNode = (MANUAL_IMPORT_MODULE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MANUAL_IMPORT_MODULE));
    if (!importNode)
    {
        return FALSE;
    }

    importNode->ModuleHandle = moduleHandle;
    importNode->Next = manualModule->LoadedImports;
    manualModule->LoadedImports = importNode;
    return TRUE;
}

/*
 * 逆序释放当前手工模块在加载阶段额外拉起的依赖模块。
 * 这里不碰那些原本就已加载的模块，只平衡我们自己额外增加的引用计数。
 */
static void ReleaseTrackedImports(MANUAL_MODULE *manualModule)
{
    MANUAL_IMPORT_MODULE *importNode;
    MANUAL_IMPORT_MODULE *nextNode;

    if (!manualModule)
    {
        return;
    }

    importNode = manualModule->LoadedImports;
    while (importNode)
    {
        nextNode = importNode->Next;
        if (importNode->ModuleHandle)
        {
            FreeLibrary(importNode->ModuleHandle);
        }
        HeapFree(GetProcessHeap(), 0, importNode);
        importNode = nextNode;
    }

    manualModule->LoadedImports = NULL;
}

/*
 * 把成功加载完成的手工模块登记到全局链表。
 * 这样后续 UnloadTargetLibrary 才能从模块基址找回对应上下文。
 */
static void RegisterManualModule(MANUAL_MODULE *manualModule)
{
    if (!manualModule)
    {
        return;
    }

    manualModule->Next = g_ManualModules;
    g_ManualModules = manualModule;
}

/*
 * 从全局链表中拆下一个手工模块并返回。
 * “拆下”而不是“只查找”的目的，是防止同一个模块被重复卸载。
 */
static MANUAL_MODULE *DetachManualModule(HMODULE moduleBase)
{
    MANUAL_MODULE *current;
    MANUAL_MODULE *previous;

    previous = NULL;
    current = g_ManualModules;

    while (current)
    {
        if (current->ModuleBase == moduleBase)
        {
            if (previous)
            {
                previous->Next = current->Next;
            }
            else
            {
                g_ManualModules = current->Next;
            }

            current->Next = NULL;
            return current;
        }

        previous = current;
        current = current->Next;
    }

    return NULL;
}

/*
 * 释放 MANUAL_MODULE 自身，不负责释放镜像或依赖模块。
 * 这些动作由调用方按顺序先做完，最后再销毁元数据。
 */
static void FreeManualModuleRecord(MANUAL_MODULE *manualModule)
{
    if (!manualModule)
    {
        return;
    }

    HeapFree(GetProcessHeap(), 0, manualModule);
}

/*
 * 清空“最后缺失导入”诊断状态。
 * 每次新的 LoadTargetLibraryW 尝试开始前都要先重置一次。
 */
static void ClearLastMissingImport(void)
{
    g_LastMissingImportModule[0] = '\0';
    g_LastMissingImportProc[0] = '\0';
    g_LastMissingImportOrdinal = 0;
    g_LastMissingImportByOrdinal = FALSE;
}

/*
 * 保存最近一次导入失败的详细信息。
 * 宿主后续可以通过导出的查询函数把这些信息取出来。
 */
static void RecordMissingImport(LPCSTR moduleName, LPCSTR procName, WORD ordinal, BOOL byOrdinal)
{
    CopyAnsiStringA(g_LastMissingImportModule, sizeof(g_LastMissingImportModule), moduleName);

    if (byOrdinal)
    {
        g_LastMissingImportProc[0] = '\0';
        g_LastMissingImportOrdinal = ordinal;
        g_LastMissingImportByOrdinal = TRUE;
    }
    else
    {
        CopyAnsiStringA(g_LastMissingImportProc, sizeof(g_LastMissingImportProc), procName);
        g_LastMissingImportOrdinal = 0;
        g_LastMissingImportByOrdinal = FALSE;
    }
}

/*
 * 一个安全的 ANSI 字符串复制辅助：
 * - 不依赖额外 CRT；
 * - 永远保证目标缓冲区以 '\0' 结束。
 */
static void CopyAnsiStringA(LPSTR destination, SIZE_T destinationCount, LPCSTR source)
{
    SIZE_T index;

    if (!destination || destinationCount == 0)
    {
        return;
    }

    if (!source)
    {
        destination[0] = '\0';
        return;
    }

    for (index = 0; index + 1 < destinationCount && source[index] != '\0'; ++index)
    {
        destination[index] = source[index];
    }

    destination[index] = '\0';
}

/*
 * DllMain 目前保持最小化。
 * 这个 DLL 的主要初始化逻辑不依赖进程附加阶段，因此这里不做额外动作。
 */
BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpReserved
)
{
    UNREFERENCED_PARAMETER(hinstDLL);
    UNREFERENCED_PARAMETER(lpReserved);

    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

