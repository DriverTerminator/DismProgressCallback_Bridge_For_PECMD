// eh4_x86.c
// VS2008 / C89 / pure C / 仅 x86（Win32）
// 文件编码：UTF-8（建议带 BOM，以便旧版 VS 与记事本正确识别中文）
//
// 本文件职责：
// 实现 msvcrt 导出的 _except_handler4_common，供 main.c 在手工映射 DLL 时把
// “对 msvcrt!_except_handler4_common 的导入”劫持到本模块，从而在 NT5 等缺少
// 该符号的系统上仍能完成导入解析，并在运行期按 MSVC EH4 规则处理 __try/__except/__finally。
//
// 实现依据（控制流与栈上布局）：
// - MSVC CRT：chandler4.c（含安全 cookie 校验与 scope 表解码）
// - Wine：dlls/msvcrt/except_i386.c（filter / finally funclet 的调用约定）
//
// 同类开源参考生态：YY-Thunks、VC-LTL5、One-Core-API 等。
//
// 限制：
// - 仅 Win32；x64/ARM 使用不同异常模型，工程中已通过 ExcludedFromBuild 排除本文件。
// - 未实现 C++ 抛掷对象析构（_pDestructExceptionObject）；以纯 C 的 SEH 为主。

#if defined(_M_IX86)

#pragma warning(disable : 4731)

#include <windows.h>
#include <stddef.h>
#include <excpt.h>

WINBASEAPI VOID WINAPI RtlUnwind(
    PVOID TargetFrame,
    PVOID TargetIp,
    PEXCEPTION_RECORD ExceptionRecord,
    PVOID ReturnValue);

#ifndef EH_EXCEPTION_NUMBER
#define EH_EXCEPTION_NUMBER ((DWORD)0xE0434F4DL)
#endif

#ifndef EXCEPTION_UNWINDING
#define EXCEPTION_UNWINDING 0x02
#endif
#ifndef EXCEPTION_EXIT_UNWIND
#define EXCEPTION_EXIT_UNWIND 0x04
#endif
#ifndef EXCEPTION_TARGET_UNWIND
#define EXCEPTION_TARGET_UNWIND 0x20
#endif
#ifndef EXCEPTION_COLLIDED_UNWIND
#define EXCEPTION_COLLIDED_UNWIND 0x40
#endif

#define EXCEPTION_UNWIND (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND | \
    EXCEPTION_TARGET_UNWIND | EXCEPTION_COLLIDED_UNWIND)

#define IS_DISPATCHING(Flag) (((Flag) & EXCEPTION_UNWIND) == 0)

#define NO_GS_COOKIE ((ULONG)-2)
#define TOPMOST_TRY_LEVEL ((ULONG)-2)

typedef LONG(__cdecl *PEXCEPTION_FILTER_X86)(void);
typedef void(__cdecl *PEXCEPTION_HANDLER_X86)(void);
typedef void(__fastcall *PTERMINATION_HANDLER_X86)(BOOL);

typedef void(__fastcall *PCOOKIE_CHECK)(UINT_PTR);

typedef struct _EH4_SCOPETABLE_RECORD
{
    ULONG EnclosingLevel;
    PEXCEPTION_FILTER_X86 FilterFunc;
    union
    {
        PEXCEPTION_HANDLER_X86 HandlerAddress;
        PTERMINATION_HANDLER_X86 FinallyFunc;
    } u;
} EH4_SCOPETABLE_RECORD, *PEH4_SCOPETABLE_RECORD;

typedef struct _EH4_SCOPETABLE
{
    ULONG GSCookieOffset;
    ULONG GSCookieXOROffset;
    ULONG EHCookieOffset;
    ULONG EHCookieXOROffset;
    EH4_SCOPETABLE_RECORD ScopeRecord[1];
} EH4_SCOPETABLE, *PEH4_SCOPETABLE;

/*
 * MSVC lays out EH4_EXCEPTION_REGISTRATION_RECORD with an embedded
 * EXCEPTION_REGISTRATION_RECORD at a fixed offset. We model SubRecord with
 * explicit fields so this TU does not depend on excpt.h/winnt.h ordering for
 * the EXCEPTION_REGISTRATION_RECORD typedef name.
 */
typedef struct _EH4_EXCEPTION_REGISTRATION_RECORD
{
    PVOID SavedESP;
    PEXCEPTION_POINTERS ExceptionPointers;
    struct
    {
        PVOID Next;
        PVOID Handler;
    } SubRecord;
    UINT_PTR EncodedScopeTable;
    ULONG TryLevel;
} EH4_EXCEPTION_REGISTRATION_RECORD, *PEH4_EXCEPTION_REGISTRATION_RECORD;

static void Eh4ValidateContextRecord(PCONTEXT ctx)
{
    (void)ctx;
}

static void ValidateLocalCookies(
    PCOOKIE_CHECK cookieCheckFunction,
    PEH4_SCOPETABLE scopeTable,
    PCHAR framePointer)
{
    UINT_PTR gsCookie;
    UINT_PTR ehCookie;

    if (scopeTable->GSCookieOffset != NO_GS_COOKIE)
    {
        gsCookie = *(PUINT_PTR)(framePointer + scopeTable->GSCookieOffset);
        gsCookie ^= (UINT_PTR)(framePointer + scopeTable->GSCookieXOROffset);
        if (cookieCheckFunction)
        {
            cookieCheckFunction(gsCookie);
        }
    }

    ehCookie = *(PUINT_PTR)(framePointer + scopeTable->EHCookieOffset);
    ehCookie ^= (UINT_PTR)(framePointer + scopeTable->EHCookieXOROffset);
    if (cookieCheckFunction)
    {
        cookieCheckFunction(ehCookie);
    }
}

static LONG Eh4CallFilter(PEXCEPTION_FILTER_X86 filter, PCHAR framePointer)
{
    LONG result;

    __asm
    {
        push ebp
        mov ebp, framePointer
        mov eax, filter
        call eax
        mov result, eax
        pop ebp
    }

    return result;
}

static void Eh4CallHandlerVoid(PEXCEPTION_HANDLER_X86 handler, PCHAR framePointer)
{
    __asm
    {
        push ebp
        push ebx
        push esi
        push edi
        mov ebp, framePointer
        mov eax, handler
        call eax
        pop edi
        pop esi
        pop ebx
        pop ebp
    }
}

enum { EH4_REGISTRATION_RECORD_BYTES = (int)sizeof(EH4_EXCEPTION_REGISTRATION_RECORD) };

static __declspec(noreturn) void Eh4TransferToHandler(PEXCEPTION_HANDLER_X86 handler, PCHAR framePointer)
{
    PEXCEPTION_HANDLER_X86 hSave = handler;
    PCHAR fpSave = framePointer;

    __asm
    {
        mov eax, hSave
        mov edx, fpSave
        mov ecx, edx
        sub ecx, EH4_REGISTRATION_RECORD_BYTES
        mov esp, dword ptr [ecx]
        mov ebp, edx
        jmp eax
    }
}

static void Eh4GlobalUnwind2(void *establisherSubRecord, PEXCEPTION_RECORD exceptionRecord)
{
    RtlUnwind(establisherSubRecord, NULL, exceptionRecord, NULL);
}

static void Eh4LocalUnwind(
    void *subRecord,
    ULONG targetTryLevel,
    PCHAR framePointer,
    PUINT_PTR cookiePointer)
{
    PEH4_EXCEPTION_REGISTRATION_RECORD registration;
    PEH4_SCOPETABLE scopeTable;
    ULONG curLevel;
    ULONG level;

    registration = (PEH4_EXCEPTION_REGISTRATION_RECORD)
        ((BYTE *)subRecord - offsetof(EH4_EXCEPTION_REGISTRATION_RECORD, SubRecord));
    scopeTable = (PEH4_SCOPETABLE)(registration->EncodedScopeTable ^ *cookiePointer);

    curLevel = registration->TryLevel;

    while (curLevel != TOPMOST_TRY_LEVEL && curLevel != targetTryLevel)
    {
        level = curLevel;
        curLevel = scopeTable->ScopeRecord[level].EnclosingLevel;
        registration->TryLevel = curLevel;

        if (scopeTable->ScopeRecord[level].FilterFunc == NULL)
        {
            Eh4CallHandlerVoid(scopeTable->ScopeRecord[level].u.HandlerAddress, framePointer);
        }
    }
}

/*
 * Public CRT entry: six __cdecl stack arguments, returns EXCEPTION_DISPOSITION.
 * Must match the symbol imported from msvcrt / msvcr* by VC-generated _except_handler4 stubs.
 */
EXCEPTION_DISPOSITION __cdecl _except_handler4_common(
    PUINT_PTR cookiePointer,
    PCOOKIE_CHECK cookieCheckFunction,
    PEXCEPTION_RECORD exceptionRecord,
    void *establisherFrame,
    PCONTEXT contextRecord,
    PVOID dispatcherContext)
{
    PEH4_EXCEPTION_REGISTRATION_RECORD registrationNode;
    PCHAR framePointer;
    PEH4_SCOPETABLE scopeTable;
    ULONG tryLevel;
    ULONG enclosingLevel;
    EXCEPTION_POINTERS exceptionPointers;
    PEH4_SCOPETABLE_RECORD scopeRecord;
    PEXCEPTION_FILTER_X86 filterFunc;
    LONG filterResult;
    BOOL revalidate;
    EXCEPTION_DISPOSITION disposition;

    UNREFERENCED_PARAMETER(dispatcherContext);

    disposition = ExceptionContinueSearch;
    revalidate = FALSE;

    registrationNode = (PEH4_EXCEPTION_REGISTRATION_RECORD)
        ((PCHAR)establisherFrame - offsetof(EH4_EXCEPTION_REGISTRATION_RECORD, SubRecord));

    framePointer = (PCHAR)(registrationNode + 1);

    scopeTable = (PEH4_SCOPETABLE)(registrationNode->EncodedScopeTable ^ *cookiePointer);

    ValidateLocalCookies(cookieCheckFunction, scopeTable, framePointer);
    Eh4ValidateContextRecord(contextRecord);

    if (IS_DISPATCHING(exceptionRecord->ExceptionFlags))
    {
        exceptionPointers.ExceptionRecord = exceptionRecord;
        exceptionPointers.ContextRecord = contextRecord;
        registrationNode->ExceptionPointers = &exceptionPointers;

        for (tryLevel = registrationNode->TryLevel;
             tryLevel != TOPMOST_TRY_LEVEL;
             tryLevel = enclosingLevel)
        {
            scopeRecord = &scopeTable->ScopeRecord[tryLevel];
            filterFunc = scopeRecord->FilterFunc;
            enclosingLevel = scopeRecord->EnclosingLevel;

            if (filterFunc != NULL)
            {
                filterResult = Eh4CallFilter(filterFunc, framePointer);
                revalidate = TRUE;

                if (filterResult < 0)
                {
                    disposition = ExceptionContinueExecution;
                    break;
                }

                if (filterResult > 0)
                {
                    Eh4GlobalUnwind2((void *)&registrationNode->SubRecord, exceptionRecord);

                    if (registrationNode->TryLevel != tryLevel)
                    {
                        Eh4LocalUnwind(
                            (void *)&registrationNode->SubRecord,
                            tryLevel,
                            framePointer,
                            cookiePointer);
                    }

                    registrationNode->TryLevel = enclosingLevel;

                    ValidateLocalCookies(cookieCheckFunction, scopeTable, framePointer);

                    Eh4TransferToHandler(scopeRecord->u.HandlerAddress, framePointer);
                }
            }
        }
    }
    else
    {
        if (registrationNode->TryLevel != TOPMOST_TRY_LEVEL)
        {
            Eh4LocalUnwind(
                (void *)&registrationNode->SubRecord,
                TOPMOST_TRY_LEVEL,
                framePointer,
                cookiePointer);
            revalidate = TRUE;
        }
    }

    if (revalidate)
    {
        ValidateLocalCookies(cookieCheckFunction, scopeTable, framePointer);
    }

    return disposition;
}

#endif /* _M_IX86 */
