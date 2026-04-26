# DismProgressCallback_Bridge_For_PECMD
让dismapi回调可用于PECMD 2012的中间层

此项目具体解决问题：
PECMD 2012脚本语言中的回调函数固定为：
※绑定回调函数： ENVI^ WndProc[1|2|3][C][,指针变量]  //C为C调用。
微软官方文档：
https://learn.microsoft.com/zh-cn/windows/win32/api/winuser/nc-winuser-wndproc
WNDPROC Wndproc;

LRESULT Wndproc(
  HWND unnamedParam1,
  UINT unnamedParam2,
  WPARAM unnamedParam3,
  LPARAM unnamedParam4
)
{...}
具体为4个参数。

而 dismapi 回调 DismProgressCallback
void
DismProgressCallback(
    _In_ UINT Current,
    _In_ UINT Total,
    _In_ PVOID UserData
    )

typedef void (*DISM_PROGRESS_CALLBACK)(UINT, UINT, PVOID)
具体为3个参数。

所以参数不对齐，调用崩溃。

此dll作为中间层转换，具体PECMD 2012调用代码如下：
CALL $--ret:&hDismBridge ,-LoadLibrary,DismBridge.dll                       // 加载dll获取句柄
ENVI^ WndProc1,&DismProgressCallback                                        // 绑定回调函数，获取函数地址，自动找 _SUB ONWndProc1 函数
CALL $--qd %&hDismBridge%,SetCallback,#%&DismProgressCallback%              // PECMD 内部 WndProc 指针传给 DLL 保存
CALL $--qd --16 --ret:&&GetDismCallbackRet %&hDismBridge%,GetDismCallback   // 获取指针，作为 DismAddPackage 等函数的参数使用
然后在
_SUB ONWndProc1
    ^MESS. %*@
_END
中可以弹窗显示接收到的回调函数获取到的参数
