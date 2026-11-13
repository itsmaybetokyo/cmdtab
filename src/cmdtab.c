#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define _CRTDBG_MAP_ALLOC
#define COBJMACROS

//#undef _DEBUG

#define NOGDICAPMASKS
#define NOMENUS
#define NOICONS
#define NOKEYSTATES
#define OEMRESOURCE
#define NOATOM
#define NOCLIPBOARD
#define NOCOLOR
#define NOKERNEL
#define NONLS
#define NOMEMMGR
#define NOMETAFILE
#define NOMINMAX
#define NOOPENFILE
#define NOSCROLL
#define NOSERVICE
#define NOSOUND
#define NOCOMM
#define NOKANJI
#define NOHELP
#define NOPROFILER
#define NODEFERWINDOWPOS
#define NOMCX

#include <windows.h>
#include <commctrl.h> // IMAGELISTDRAWPARAMS, IMAGEINFO for commoncontrols.h (missing under WIN32_LEAN_AND_MEAN)
#include "crtdbg.h"
#include "shellapi.h" // Only used by StringFileName for PathFindFileNameW?
#include "shlwapi.h"
#include "dwmapi.h"
#include "pathcch.h"
#include "strsafe.h"
#include <initguid.h>
#include "commoncontrols.h"
// appmodel.h fails to parse with this SDK/define set; only one function is used.
WINBASEAPI LONG WINAPI GetApplicationUserModelId(HANDLE hProcess, UINT32* applicationUserModelIdLength, PWSTR applicationUserModelId);
#include "propkey.h" // For PKEY_AppUserModel_ID
#include "propsys.h" // For IPropertyStore
#include "shobjidl.h" // For IShellItem, IShellItemImageFactory

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "msimg32.lib") // For AlphaBlend (pixel icons)
#pragma comment(lib, "shlwapi.lib") // Only used by StringFileName for PathFindFileNameW?
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "pathcch.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "propsys.lib") // For UWP property access

#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")

//==============================================================================
// Utility belt
//==============================================================================

#define countof(a) (ptrdiff_t)(sizeof(a)/sizeof(*a))
#define string(str) {str,countof(str)-1,true}

#define false 0
#define true 1
#define null NULL // WHY IS EVERYONE SCREAMING

typedef wchar_t             u16; // "Microsoft implements wchar_t as a two-byte unsigned value."
typedef unsigned char       u8;
typedef unsigned int        u32;
typedef unsigned long long  u64;
typedef signed int          i32;
typedef signed long long    i64;
typedef signed int         bool;
typedef ptrdiff_t          size;
typedef void* handle;
typedef struct string    string;

struct string {
	u16 text[MAX_PATH];
	size length;
	bool ok;
};

static const string UWPAppHostExe = string(L"ApplicationFrameHost.exe");
static const string UWPAppHostClass = string(L"ApplicationFrameWindow");
static const string UWPCoreWindowClass = string(L"Windows.UI.Core.CoreWindow");
static const string WinUI3WindowClass = string(L"WinUIDesktopWin32WindowClass");
static const string UWPAppsPath = string(L"C:\\Program Files\\WindowsApps");
static const string ExplorerExe = string(L"explorer");
static const string ExplorerCabinetClass = string(L"CabinetWClass");
static const string ExplorerExploreClass = string(L"ExploreWClass");

// Flock's app icon uses a 48px corner radius on a 256px canvas: 18.75% of
// its edge. The switcher reuses that same ratio so the dock, the selection
// tile and the label chip read as one shape family.
#define RADIUS_RATIO 0.1875f
#define LABEL_GAP       10
#define LABEL_PAD_H     14
#define LABEL_PAD_V     10
#define LABEL_FONT_SIZE 14
#define LABEL_AREA_HEIGHT 40

static bool StringsAreEqual(string* s1, string* s2)
{
	// Reverse compare strings
	// Compare in reverse since this function is mostly used to compare file
	// paths, which are often unique yet have long identical prefixes
	if (s1->length != s2->length) {
		return false;
	}
	for (int i = s1->length - 1; i >= 0; i--) {
		if (s1->text[i] != s2->text[i]) {
			return false;
		}
	}
	return true;
}

static bool StringEndsWith(string* s1, string* s2)
{
	return s1->length >= s2->length && !memcmp(s1->text + s1->length - s2->length, s2->text, s2->length);
}

static string StringFileName(string* filepath, bool extension)
{
	// aka. basename
	string name = { 0 };
	name.ok = SUCCEEDED(StringCchCopyNW(name.text, countof(name.text), PathFindFileNameW(filepath->text), countof(name.text)));
	if (!extension) {
		name.ok = name.ok && SUCCEEDED(PathCchRemoveExtension(name.text, countof(name.text)));
	}
	name.ok = name.ok && SUCCEEDED(StringCchLengthW(name.text, countof(name.text), &name.length));
	return name;
}

static i64 StartMeasuring(void)
{
	i64 start;
	QueryPerformanceCounter((LARGE_INTEGER*)&start);
	return start;
}

static i64 FinishMeasuring(i64 start)
{
	i64 end, frequency;
	QueryPerformanceCounter((LARGE_INTEGER*)&end);
	QueryPerformanceFrequency((LARGE_INTEGER*)&frequency);
	return ((end - start) * 1000) / frequency;
}

static void Debug(u16* fmt, ...)
{
#ifdef _DEBUG
	u16 buffer[2048];
	va_list args;
	va_start(args, fmt);
	StringCchVPrintfW(buffer, countof(buffer) - 1, fmt, args);
	va_end(args);
	OutputDebugStringW(buffer);
	__debugbreak();
#endif
}

static void Print(u16* fmt, ...)
{
#ifdef _DEBUG
	u16 buffer[2048];
	va_list args;
	va_start(args, fmt);
	StringCchVPrintfW(buffer, countof(buffer) - 1, fmt, args);
	va_end(args);
	OutputDebugStringW(buffer);
#endif
}

static void Log(u16* fmt, ...)
{
	u16 buffer[2048];
	va_list args;
	va_start(args, fmt);
	StringCchVPrintfW(buffer, countof(buffer) - 1, fmt, args);
	va_end(args);
	OutputDebugStringW(buffer);
}

static void NavLog(u16* fmt, ...)
{
	// DIAG: navigation trace for the skipped-selection bug.
	u16 buffer[512];
	va_list args;
	va_start(args, fmt);
	StringCchVPrintfW(buffer, countof(buffer) - 1, fmt, args);
	va_end(args);
	StringCchCatW(buffer, countof(buffer), L"\n");
	u16 path[MAX_PATH];
	GetTempPathW(countof(path), path);
	StringCchCatW(path, countof(path), L"cmdtab_nav.txt");
	FILE* f = _wfopen(path, L"a");
	if (f) { fputws(buffer, f); fclose(f); }
}

static void DbgLog(u16* fmt, ...)
{
	u16 buffer[1024];
	va_list args;
	va_start(args, fmt);
	StringCchVPrintfW(buffer, countof(buffer) - 1, fmt, args);
	va_end(args);
	StringCchCatW(buffer, countof(buffer), L"\n");
	u16 path[MAX_PATH];
	GetTempPathW(countof(path), path);
	StringCchCatW(path, countof(path), L"cmdtab_dbg.txt");
	FILE* f = _wfopen(path, L"a");
	if (f) { fputws(buffer, f); fclose(f); }
}

static void Error(handle hwnd, u16* fmt, ...)
{
	u16 buffer[2048];
	va_list args;
	va_start(args, fmt);
	StringCchVPrintfW(buffer, countof(buffer) - 1, fmt, args);
	va_end(args);
	OutputDebugStringW(buffer);
	SetForegroundWindow(hwnd);
	MessageBoxW(hwnd, buffer, L"cmdtab", MB_OK | MB_ICONERROR | MB_TASKMODAL);
}

static bool Ask(handle hwnd, u16* fmt, ...)
{
	u16 buffer[2048];
	va_list args;
	va_start(args, fmt);
	StringCchVPrintfW(buffer, countof(buffer) - 1, fmt, args);
	va_end(args);
	SetForegroundWindow(hwnd);
	return MessageBoxW(hwnd, buffer, L"cmdtab", MB_YESNO | MB_ICONQUESTION | MB_TASKMODAL) == IDYES;
}

static string GetWindowClass(handle hwnd)
{
	string class = { 0 };
	class.length = GetClassNameW(hwnd, class.text, countof(class.text));
	class.ok = (class.length > 0);
	return class;
}

static BOOL CALLBACK _GetCoreWindow(HWND child, LPARAM lparam)
{
	// EnumChildProc used by GetCoreWindow
	// Set inout 'lparam' to hosted core window
	string class = GetWindowClass(child);
	if (StringsAreEqual(&class, &UWPCoreWindowClass)) {
		*(handle*)lparam = child;
		return false;
	}
	else {
		return true; // Return true to continue EnumChildWindows
	}
}

static handle GetCoreWindow(handle hwnd)
{
	string class = GetWindowClass(hwnd);
	if (StringsAreEqual(&class, &UWPAppHostClass)) {
		handle hwnd2 = hwnd;
		EnumChildWindows(hwnd, _GetCoreWindow, (LPARAM)&hwnd2); // _GetCoreWindow sets 'hwnd2' to hosted core window, if any
		return hwnd2;
	}
	else {
		return hwnd;
	}
}

static handle GetAppHost(handle hwnd)
{
	string class = GetWindowClass(hwnd);
	if (StringsAreEqual(&class, &UWPCoreWindowClass)) {
		return GetAncestor(hwnd, GA_PARENT); // TODO Test
	}
	else {
		return hwnd;
	}
}

static bool IsUWPApp(handle hwnd)
{
	// Check if this is a modern packaged app (UWP or WinUI 3)
	string class = GetWindowClass(hwnd);
	// UWP apps use Windows.UI.Core.CoreWindow, WinUI 3 apps use WinUIDesktopWin32WindowClass
	return StringsAreEqual(&class, &UWPCoreWindowClass) || StringsAreEqual(&class, &WinUI3WindowClass);
}

static string GetUWPAppUserModelId(handle mainHwnd, handle secondaryHwnd)
{
	// Get the Application User Model ID for a modern packaged app (UWP/WinUI 3) using IPropertyStore
	// For UWP: mainHwnd is ApplicationFrameWindow, secondaryHwnd is CoreWindow
	// For WinUI 3: mainHwnd is the app window directly, secondaryHwnd is the same
	string aumid = { 0 };

	// Try the main window first
	IPropertyStore* propStore = NULL;
	HRESULT hr = SHGetPropertyStoreForWindow(mainHwnd, &IID_IPropertyStore, (void**)&propStore);
	Print(L"SHGetPropertyStoreForWindow (main) result: 0x%08X\n", hr);
	if (SUCCEEDED(hr)) {
		PROPVARIANT propVar;
		PropVariantInit(&propVar);

		hr = IPropertyStore_GetValue(propStore, &PKEY_AppUserModel_ID, &propVar);
		Print(L"IPropertyStore_GetValue result: 0x%08X\n", hr);
		if (SUCCEEDED(hr)) {
			if (propVar.vt == VT_LPWSTR && propVar.pwszVal) {
				StringCchCopyW(aumid.text, countof(aumid.text), propVar.pwszVal);
				aumid.length = wcslen(aumid.text);
				aumid.ok = (aumid.length > 0);
				Print(L"Got AUMID from main window: %s\n", aumid.text);
			}
			PropVariantClear(&propVar);
		}
		IPropertyStore_Release(propStore);

		if (aumid.ok) return aumid;
	}

	// If that failed and we have a different secondary window (UWP case), try it
	if (secondaryHwnd != mainHwnd) {
		hr = SHGetPropertyStoreForWindow(secondaryHwnd, &IID_IPropertyStore, (void**)&propStore);
		Print(L"SHGetPropertyStoreForWindow (secondary) result: 0x%08X\n", hr);
		if (SUCCEEDED(hr)) {
			PROPVARIANT propVar;
			PropVariantInit(&propVar);

			if (SUCCEEDED(IPropertyStore_GetValue(propStore, &PKEY_AppUserModel_ID, &propVar))) {
				if (propVar.vt == VT_LPWSTR && propVar.pwszVal) {
					StringCchCopyW(aumid.text, countof(aumid.text), propVar.pwszVal);
					aumid.length = wcslen(aumid.text);
					aumid.ok = (aumid.length > 0);
					Print(L"Got AUMID from secondary window: %s\n", aumid.text);
				}
				PropVariantClear(&propVar);
			}
			IPropertyStore_Release(propStore);

			if (aumid.ok) return aumid;
		}
	}

	// If property store failed, try GetApplicationUserModelId from the process (WinUI 3 apps)
	Print(L"Property store methods failed, trying GetApplicationUserModelId from process\n");

	u32 processId = 0;
	GetWindowThreadProcessId(mainHwnd, &processId);

	if (processId) {
		Print(L"Process ID: %u\n", processId);
		handle process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
		if (process) {
			u32 aumidLength = countof(aumid.text);
			LONG result = GetApplicationUserModelId(process, &aumidLength, aumid.text);
			Print(L"GetApplicationUserModelId result: %d, length: %u\n", result, aumidLength);

			if (result == ERROR_SUCCESS) {
				aumid.length = wcslen(aumid.text);
				aumid.ok = (aumid.length > 0);
				Print(L"Got AUMID from process: %s\n", aumid.text);
			}
			else if (result == ERROR_INSUFFICIENT_BUFFER) {
				Print(L"AUMID buffer too small (needed %u chars)\n", aumidLength);
			}
			else {
				Print(L"GetApplicationUserModelId failed with error: %d\n", result);
			}

			CloseHandle(process);
		}
		else {
			Print(L"Failed to open process, error: %d\n", GetLastError());
		}
	}

	if (!aumid.ok) {
		Print(L"Failed to get AUMID from all methods\n");
	}

	return aumid;
}

static string GetUWPAppName(string* aumid)
{
	// Extract a friendly name from the AUMID
	// AUMID format examples:
	//   UWP: CompanyName.AppName_hash_variant_suffix!App
	//   WinUI3: CompanyName.AppName_hash_variant_suffix!AppName.Root
	// We want to extract "AppName" part
	string name = { 0 };

	if (!aumid->ok || aumid->length == 0) {
		return name;
	}

	// Copy the AUMID
	StringCchCopyW(name.text, countof(name.text), aumid->text);

	// First, check if there's an exclamation mark (separates package from app ID)
	u16* exclamation = wcschr(name.text, L'!');
	if (exclamation) {
		// If there's something after !, try to use that
		u16* appPart = exclamation + 1;
		if (wcslen(appPart) > 0) {
			// Check if it's like "AppName.Root" - remove the .Root part
			u16* dotInAppPart = wcschr(appPart, L'.');
			if (dotInAppPart) {
				*dotInAppPart = L'\0';
			}
			// Use the app part if it's not just "App"
			if (wcscmp(appPart, L"App") != 0 && wcslen(appPart) > 0) {
				memmove(name.text, appPart, (wcslen(appPart) + 1) * sizeof(u16));
				name.length = wcslen(name.text);
				name.ok = true;
				return name;
			}
		}
		// If the app part is just "App", truncate at ! and continue with package name logic
		*exclamation = L'\0';
	}

	// Find the first dot (separates company from app name)
	u16* dot = wcschr(name.text, L'.');
	if (!dot) {
		// No dot found, just use what we have
		name.length = wcslen(name.text);
		name.ok = (name.length > 0);
		return name;
	}

	// Find the first underscore after the dot (separates app name from hash)
	u16* underscore = wcschr(dot + 1, L'_');
	if (underscore) {
		*underscore = L'\0'; // Truncate at underscore
	}

	// Move the string to remove the company prefix
	memmove(name.text, dot + 1, (wcslen(dot + 1) + 1) * sizeof(u16));
	name.length = wcslen(name.text);
	name.ok = (name.length > 0);

	return name;
}

#ifndef UWP_ICON_SIZE
#define UWP_ICON_SIZE 256
#endif
static bool IconCacheLookup(u16* key, handle* out);
static void IconCacheStore(u16* key, handle icon);
static handle GetWindowIcon(handle hwnd);
static int GetIconPixelWidth(handle icon);
static void PresentSwitcher(void);

static handle GetUWPAppIcon(string* aumid, handle hwnd)
{
	// Try multiple methods to get the UWP app icon
	if (!aumid->ok || aumid->length == 0) {
		return null;
	}

	HICON icon = null;
	HICON cached = null;
	if (IconCacheLookup(aumid->text, (handle*)&cached)) {
		return cached; // Caller owns this copy
	}

	u16 shellPath[MAX_PATH * 2];
	StringCchPrintfW(shellPath, countof(shellPath), L"shell:AppsFolder\\%s", aumid->text);

	// Method 1: SHDefExtractIcon handles UWP shell paths and returns a real
	// alpha-blended HICON directly (no lossy HBITMAP->HICON conversion).
	{
		HICON hBig = null, hSmall = null;
		if (SUCCEEDED(SHDefExtractIconW(shellPath, 0, 0, &hBig, &hSmall, UWP_ICON_SIZE))) {
			if (hSmall) DestroyIcon(hSmall);
			if (hBig) {
				Print(L"Got UWP icon via SHDefExtractIcon\n");
				IconCacheStore(aumid->text, hBig);
				return hBig;
			}
		}
	}

	// Method 2: IShellItemImageFactory at full size with a correct
	// HBITMAP->HICON conversion (old code reused the color bitmap as the
	// mask, which destroyed the alpha channel).
	IShellItem* shellItem = null;
	if (SUCCEEDED(SHCreateItemFromParsingName(shellPath, null, &IID_IShellItem, (void**)&shellItem))) {
		IShellItemImageFactory* imageFactory = null;
		if (SUCCEEDED(IShellItem_QueryInterface(shellItem, &IID_IShellItemImageFactory, (void**)&imageFactory))) {
			SIZE size = { UWP_ICON_SIZE, UWP_ICON_SIZE };
			HBITMAP hbmp = null;
			if (SUCCEEDED(IShellItemImageFactory_GetImage(imageFactory, size, SIIGBF_ICONONLY, &hbmp)) && hbmp) {
				BITMAP bm = { 0 };
				GetObjectW(hbmp, sizeof bm, &bm);
				// Monochrome mask: all-black = opaque, alpha in color bitmap wins.
				HBITMAP hbmMask = CreateBitmap(bm.bmWidth ? bm.bmWidth : UWP_ICON_SIZE, bm.bmHeight ? bm.bmHeight : UWP_ICON_SIZE, 1, 1, null);
				if (hbmMask) {
					ICONINFO iconInfo = { 0 };
					iconInfo.fIcon = TRUE;
					iconInfo.hbmColor = hbmp;
					iconInfo.hbmMask = hbmMask;
					icon = CreateIconIndirect(&iconInfo);
					DeleteObject(hbmMask);
				}
				DeleteObject(hbmp);
				if (icon) {
					Print(L"Got UWP icon via IShellItemImageFactory\n");
					IShellItemImageFactory_Release(imageFactory);
					IShellItem_Release(shellItem);
					IconCacheStore(aumid->text, icon);
					return icon;
				}
			}
			IShellItemImageFactory_Release(imageFactory);
		}
		IShellItem_Release(shellItem);
	}

	// Method 3: Try using shell:AppsFolder with ExtractIconEx
	HICON largeIcon = null, smallIcon = null;
	if (ExtractIconExW(shellPath, 0, &largeIcon, &smallIcon, 1) > 0) {
		if (smallIcon) DestroyIcon(smallIcon);
		if (largeIcon) {
			Print(L"Got UWP icon via ExtractIconEx\n");
			IconCacheStore(aumid->text, largeIcon);
			return largeIcon;
		}
	}

	// Method 4: Try getting icon from window property
	icon = GetWindowIcon(hwnd);
	if (icon) {
		Print(L"Got UWP icon from window messages\n");
		return icon; // Per-window: do not cache under AUMID
	}

	// Method 5: Use SHGetFileInfo with shell path
	IImageList* list = { 0 };
	if (SUCCEEDED(SHGetImageList(SHIL_JUMBO, &IID_IImageList, (void**)&list))) {
		SHFILEINFOW info = { 0 };
		if (SHGetFileInfoW(shellPath, 0, &info, sizeof info, SHGFI_SYSICONINDEX)) {
			IImageList_GetIcon(list, info.iIcon, ILD_TRANSPARENT, &icon);
			if (icon) {
				Print(L"Got UWP icon via SHGetFileInfo\n");
				IconCacheStore(aumid->text, icon);
			}
		}
		IImageList_Release(list);
	}

	return icon;
}

static bool IsAltTabWindow(handle hwnd)
{
	if (hwnd == GetShellWindow()) {
		return false;
	}
	if (!IsWindowVisible(hwnd)) {
		return false;
	}
	int cloaked = 0;
	DwmGetWindowAttribute(hwnd, DWMWA_CLOAKED, &cloaked, sizeof cloaked);
	if (cloaked) {
		return false;
	}
	if (GetWindowLongPtrW(hwnd, GWL_EXSTYLE) & WS_EX_APPWINDOW) {
		return true;
	}
	// Reject windows with WS_EX_NOACTIVATE (can't be activated)
	if (GetWindowLongPtrW(hwnd, GWL_EXSTYLE) & WS_EX_NOACTIVATE) {
		return false;
	}
	// Reject tool windows, EXCEPT if they have a valid title (some Qt apps use WS_EX_TOOLWINDOW for main windows)
	if (GetWindowLongPtrW(hwnd, GWL_EXSTYLE) & WS_EX_TOOLWINDOW) {
		// Check if window has a non-empty title - if so, it's likely a real application window
		u16 title[256] = { 0 };
		int titleLength = GetWindowTextW(hwnd, title, countof(title));
		if (titleLength > 0) {
			// Has a title, allow it (for Qt apps and similar)
			return true;
		}
		// No title, it's likely a system tray icon or other tool window
		return false;
	}
	// Skip untitled windows (prevents Explorer/shell host ghost entries)
	// while still allowing explicit app windows handled above.
	if (GetWindowTextLengthW(hwnd) == 0) {
		return false;
	}
	return true;
}

static bool IsRealExplorerFolderWindow(string* filename, string* windowClass)
{
	if (!StringsAreEqual(filename, &ExplorerExe)) {
		return true;
	}
	return StringsAreEqual(windowClass, &ExplorerCabinetClass) ||
		StringsAreEqual(windowClass, &ExplorerExploreClass);
}

static string GetExePath(handle hwnd)
{
	string path = { 0 };
	ULONG pid;
	GetWindowThreadProcessId(hwnd, &pid);
	handle process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
	if (!process || process == INVALID_HANDLE_VALUE) {
		Print(L"WARNING couldn't open process with pid: %u\n", pid);
		return path;
	}
	ULONG length = countof(path.text);
	path.ok = QueryFullProcessImageNameW(process, 0, path.text, &length);
	CloseHandle(process);
	if (!path.ok) {
		Print(L"WARNING couldn't get exe path for process with pid: %u\n", pid);
		return path;
	}
	path.length = length;
	return path;
}

static string GetWindowTitle(handle hwnd)
{
	string title = { 0 };
	title.length = GetWindowTextW(hwnd, title.text, countof(title.text));
	title.ok = (title.length > 0);
	return title;
}

static void PrintWindowX(handle hwnd) // PrintWindow already taken
{
#ifdef _DEBUG
	if (hwnd) {
		string filepath = GetExePath(hwnd);
		if (!filepath.ok) return;
		string filename = StringFileName(&filepath, false);
		string class = GetWindowClass(hwnd);
		string title = GetWindowTitle(hwnd);
		u16* wsShowState = (GetWindowLongPtrW(hwnd, GWL_STYLE) & WS_MINIMIZE) ? L" (minimized) " :
			(GetWindowLongPtrW(hwnd, GWL_STYLE) & WS_MAXIMIZE) ? L" (maximized) " : L" ";
		u16* wsChild = (GetWindowLongPtrW(hwnd, GWL_STYLE) & WS_CHILD) ? L"child" : L"parent";
		u16* wsVisible = (GetWindowLongPtrW(hwnd, GWL_STYLE) & WS_VISIBLE) ? L", visible" : L", hidden";
		u16* exAppWindow = (GetWindowLongPtrW(hwnd, GWL_EXSTYLE) & WS_EX_APPWINDOW) ? L", appwindow" : L"";
		u16* exNoActivate = (GetWindowLongPtrW(hwnd, GWL_EXSTYLE) & WS_EX_NOACTIVATE) ? L", noactivate" : L"";
		u16* exToolWindow = (GetWindowLongPtrW(hwnd, GWL_EXSTYLE) & WS_EX_TOOLWINDOW) ? L", toolwindow" : L"";
		u16* exTopMost = (GetWindowLongPtrW(hwnd, GWL_EXSTYLE) & WS_EX_TOPMOST) ? L", topmost" : L"";
		u16* wsDisabled = (GetWindowLongPtrW(hwnd, GWL_STYLE) & WS_DISABLED) ? L", disabled" : L", enabled";
		u16* wsPopup = (GetWindowLongPtrW(hwnd, GWL_STYLE) & WS_POPUP) ? L", popup" : L"";
		u16* wsOverlapped = (GetWindowLongPtrW(hwnd, GWL_STYLE) & WS_OVERLAPPED) ? L", tiled/overlapped" : L"";
		u16* wsDlgFrame = (GetWindowLongPtrW(hwnd, GWL_STYLE) & WS_DLGFRAME) ? L", dlgframe" : L"";
		u16* exDlgModalFrame = (GetWindowLongPtrW(hwnd, GWL_EXSTYLE) & WS_EX_DLGMODALFRAME) ? L", dlgmodalframe" : L"";
		u16* exLayered = (GetWindowLongPtrW(hwnd, GWL_EXSTYLE) & WS_EX_LAYERED) ? L", layered" : L"";
		u16* exComposited = (GetWindowLongPtrW(hwnd, GWL_EXSTYLE) & WS_EX_COMPOSITED) ? L", composited" : L"";
		u16* exPaletteWindow = (GetWindowLongPtrW(hwnd, GWL_EXSTYLE) & WS_EX_PALETTEWINDOW) ? L", palettewindow" : L"";
		u16* exOverlappedWindow = (GetWindowLongPtrW(hwnd, GWL_EXSTYLE) & WS_EX_OVERLAPPEDWINDOW) ? L", exoverlappedwindow" : L"";
		Print(L"%p { %s, %s }%s\"%.32s\"", hwnd, filename.text, class.text, wsShowState, title.text);
		Print(L" (%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s)\n",
			wsChild, wsVisible, exAppWindow, exNoActivate, exToolWindow, exTopMost,
			wsDisabled, wsPopup, wsOverlapped, wsDlgFrame, exDlgModalFrame, exLayered, exComposited, exPaletteWindow, exOverlappedWindow);
	}
	else {
		Print(L"null hwnd\n");
	}
#else
	Print(L"%p\n", hwnd);
#endif
}

static string GetAppName(string* filepath)
{
	// Query version info for pretty application name. See cmdtab's own res/cmdtab.rc file for an idea of the data that is queried.

	string name = { 0 };

	struct {
		void* data;
		u32 size;
	} versionInfo;

	if (!(versionInfo.size = GetFileVersionInfoSizeW(filepath->text, null))) {
		goto abort;
	}
	if (!(versionInfo.data = malloc(versionInfo.size))) {
		goto abort;
	}
	if (!GetFileVersionInfoW(filepath->text, 0, versionInfo.size, versionInfo.data)) {
		goto free;
	}

	struct {
		u16 language;
		u16 codepage;
	} *translation;

	if (!VerQueryValueW(versionInfo.data, L"\\VarFileInfo\\Translation", (void*)&translation, null)) {
		goto free;
	}

	u16 key[MAX_PATH];

	struct {
		u16* text;
		u32 length;
	} value;

	// Prefer the pretty application name in the "FileDescription" field
	StringCchPrintfW(key, countof(key), L"\\StringFileInfo\\%04x%04x\\FileDescription", translation[0].language, translation[0].codepage);

	if (VerQueryValueW(versionInfo.data, key, (void*)&value.text, &value.length) && wcslen(value.text) > 0) {
		goto success;
	}

	// Fall back to "ProductName" if "FileDescription" is empty. Example: Github Desktop
	StringCchPrintfW(key, countof(key), L"\\StringFileInfo\\%04x%04x\\ProductName", translation[0].language, translation[0].codepage);

	if (VerQueryValueW(versionInfo.data, key, (void*)&value.text, &value.length) && wcslen(value.text) > 0) {
		goto success;
	}

	// Fall back to base filename if "ProductName" is empty
	name = StringFileName(filepath, false);
	goto free;

success:
	name.length = value.length < countof(name.text) ? value.length : countof(name.text);
	name.ok = SUCCEEDED(StringCchCopyNW(name.text, countof(name.text) - 1, value.text, countof(name.text) - 1));
free:
	free(versionInfo.data);
abort:
	return name;
}

#define ICON_CACHE_SIZE 128

struct iconCacheEntry {
	u16 key[MAX_PATH * 2];
	handle icon; // master copy owned by cache
	bool used;
};

static struct iconCacheEntry IconCache[ICON_CACHE_SIZE];
static size IconCacheNext; // round-robin eviction index

static bool IconCacheLookup(u16* key, handle* out)
{
	for (size i = 0; i < countof(IconCache); i++) {
		if (IconCache[i].used && wcscmp(IconCache[i].key, key) == 0) {
			handle copy = CopyIcon(IconCache[i].icon);
			if (copy) {
				*out = copy;
				return true;
			}
			return false;
		}
	}
	return false;
}

static void IconCacheStore(u16* key, handle icon)
{
	if (!icon) return;
	for (size i = 0; i < countof(IconCache); i++) {
		if (IconCache[i].used && wcscmp(IconCache[i].key, key) == 0) {
			DestroyIcon(IconCache[i].icon);
			IconCache[i].icon = CopyIcon(icon);
			return;
		}
	}
	// Evict round-robin when full
	size slot = IconCacheNext % countof(IconCache);
	IconCacheNext++;
	if (IconCache[slot].used) {
		DestroyIcon(IconCache[slot].icon);
	}
	StringCchCopyW(IconCache[slot].key, countof(IconCache[slot].key), key);
	IconCache[slot].icon = CopyIcon(icon);
	IconCache[slot].used = IconCache[slot].icon != null;
}

static handle GetWindowIcon(handle hwnd)
{
	// Per-window icon first: covers Explorer folders, browsers, Electron, etc.
	// where every window shares the same exe but has its own icon.
	handle icon = (handle)SendMessageW(hwnd, WM_GETICON, ICON_BIG, 0);
	if (!icon) {
		icon = (handle)SendMessageW(hwnd, WM_GETICON, ICON_SMALL2, 0);
	}
	if (!icon) {
		icon = (handle)GetClassLongPtrW(hwnd, GCLP_HICON);
	}
	if (!icon) {
		icon = (handle)GetClassLongPtrW(hwnd, GCLP_HICONSM);
	}
	if (!icon) {
		return null;
	}
	return CopyIcon(icon);
}

static int GetIconPixelWidth(handle icon)
{
	// Native width of an HICON's color bitmap; 0 if unknown.
	ICONINFO info = { 0 };
	BITMAP bm = { 0 };
	int width = 0;
	if (!GetIconInfo(icon, &info)) {
		return 0;
	}
	if (info.hbmColor && GetObjectW(info.hbmColor, sizeof bm, &bm)) {
		width = bm.bmWidth;
	}
	if (info.hbmColor) DeleteObject(info.hbmColor);
	if (info.hbmMask) DeleteObject(info.hbmMask);
	return width;
}

#define ICON_SOURCE_MAX 512

static double CubicWeight(double t)
{
	// Catmull-Rom kernel (a = -0.5): smooth upscaling without the ringing
	// that a wider Lanczos kernel can produce on app icons.
	t = fabs(t);
	if (t <= 1.0) return 1.5 * t * t * t - 2.5 * t * t + 1.0;
	if (t < 2.0) return -0.5 * t * t * t + 2.5 * t * t - 4.0 * t + 2.0;
	return 0.0;
}

static u32 PackBgra(u32 b, u32 g, u32 r, u32 a)
{
	return (a << 24) | (r << 16) | (g << 8) | b;
}

static int ClampInt(int value, int min, int max)
{
	return value < min ? min : value > max ? max : value;
}

static void ResampleIconPixels(u32* dst, const u32* src, int srcSize, int dstSize)
{
	// Filter premultiplied BGRA directly so transparent edges composite
	// correctly. Shrinking uses area averaging (no aliasing when a 256px icon
	// is drawn at ~125px); growing uses Catmull-Rom bicubic so 32px sources
	// scale smoothly instead of turning into chunky pixels.
	if (dstSize == srcSize) {
		memcpy(dst, src, (size_t)srcSize * (size_t)srcSize * sizeof(u32));
		return;
	}
	for (int y = 0; y < dstSize; y++) {
		u32* row = dst + (size_t)y * (size_t)dstSize;
		if (dstSize < srcSize) {
			int sy0 = (int)((i64)y * srcSize / dstSize);
			int sy1 = (int)(((i64)y + 1) * srcSize / dstSize);
			if (sy1 <= sy0) sy1 = sy0 + 1;
			for (int x = 0; x < dstSize; x++) {
				int sx0 = (int)((i64)x * srcSize / dstSize);
				int sx1 = (int)(((i64)x + 1) * srcSize / dstSize);
				if (sx1 <= sx0) sx1 = sx0 + 1;
				u64 a = 0, r = 0, g = 0, b = 0;
				u32 n = 0;
				for (int sy = sy0; sy < sy1; sy++) {
					const u32* srcRow = src + (size_t)sy * (size_t)srcSize;
					for (int sx = sx0; sx < sx1; sx++) {
						u32 p = srcRow[sx];
						b += p & 0xFF;
						g += (p >> 8) & 0xFF;
						r += (p >> 16) & 0xFF;
						a += p >> 24;
						n++;
					}
				}
				row[x] = PackBgra((u32)((b + n / 2) / n), (u32)((g + n / 2) / n),
					(u32)((r + n / 2) / n), (u32)((a + n / 2) / n));
			}
			continue;
		}
		double cy = ((double)y + 0.5) * srcSize / dstSize - 0.5;
		int iy = (int)floor(cy);
		double wy[4];
		double sumY = 0;
		for (int j = 0; j < 4; j++) {
			wy[j] = CubicWeight(cy - (iy - 1 + j));
			sumY += wy[j];
		}
		for (int x = 0; x < dstSize; x++) {
			double cx = ((double)x + 0.5) * srcSize / dstSize - 0.5;
			int ix = (int)floor(cx);
			double wx[4];
			double sumX = 0;
			for (int i = 0; i < 4; i++) {
				wx[i] = CubicWeight(cx - (ix - 1 + i));
				sumX += wx[i];
			}
			double accB = 0, accG = 0, accR = 0, accA = 0;
			for (int j = 0; j < 4; j++) {
				int sy = ClampInt(iy - 1 + j, 0, srcSize - 1);
				const u32* srcRow = src + (size_t)sy * (size_t)srcSize;
				for (int i = 0; i < 4; i++) {
					int sx = ClampInt(ix - 1 + i, 0, srcSize - 1);
					double w = wx[i] * wy[j];
					u32 p = srcRow[sx];
					accB += w * (p & 0xFF);
					accG += w * ((p >> 8) & 0xFF);
					accR += w * ((p >> 16) & 0xFF);
					accA += w * (p >> 24);
				}
			}
			double total = sumX * sumY;
			if (total <= 0) total = 1;
			row[x] = PackBgra(
				(u32)ClampInt((int)(accB / total + 0.5), 0, 255),
				(u32)ClampInt((int)(accG / total + 0.5), 0, 255),
				(u32)ClampInt((int)(accR / total + 0.5), 0, 255),
				(u32)ClampInt((int)(accA / total + 0.5), 0, 255));
		}
	}
}

static handle ScaleIconBitmapEx(handle icon, int targetSize, u32** outBits)
{
	// Render the icon once at its best native resolution, then resample to
	// exactly the size it will be drawn at. Every icon therefore goes through
	// the same high-quality path: small sources are smoothly interpolated,
	// big sources are area-averaged instead of point-sampled.
	if (!icon || targetSize <= 0) {
		return null;
	}
	if (targetSize > ICON_SOURCE_MAX) targetSize = ICON_SOURCE_MAX;
	int srcSize = GetIconPixelWidth(icon);
	if (srcSize <= 0) srcSize = 256; // Let DrawIconEx pick the best frame.
	if (srcSize > ICON_SOURCE_MAX) srcSize = ICON_SOURCE_MAX;

	handle screen = GetDC(null);
	BITMAPINFO bmi = { 0 };
	bmi.bmiHeader.biSize = sizeof(bmi.bmiHeader);
	bmi.bmiHeader.biWidth = srcSize;
	bmi.bmiHeader.biHeight = -srcSize; // Top-down
	bmi.bmiHeader.biPlanes = 1;
	bmi.bmiHeader.biBitCount = 32;
	bmi.bmiHeader.biCompression = BI_RGB;
	void* bitsSrc = null;
	HBITMAP hbmpSrc = CreateDIBSection(screen, &bmi, DIB_RGB_COLORS, &bitsSrc, null, 0);
	bmi.bmiHeader.biWidth = targetSize;
	bmi.bmiHeader.biHeight = -targetSize;
	void* bitsDst = null;
	HBITMAP hbmpDst = CreateDIBSection(screen, &bmi, DIB_RGB_COLORS, &bitsDst, null, 0);
	handle dc = CreateCompatibleDC(screen);
	ReleaseDC(null, screen);
	if (!hbmpSrc || !hbmpDst || !bitsSrc || !bitsDst || !dc) {
		if (hbmpSrc) DeleteObject(hbmpSrc);
		if (hbmpDst) DeleteObject(hbmpDst);
		if (dc) DeleteDC(dc);
		return null;
	}
	memset(bitsSrc, 0, (size_t)srcSize * (size_t)srcSize * sizeof(u32));
	handle oldBitmap = SelectObject(dc, hbmpSrc);
	DrawIconEx(dc, 0, 0, icon, srcSize, srcSize, 0, null, DI_NORMAL);
	GdiFlush();
	ResampleIconPixels((u32*)bitsDst, (u32*)bitsSrc, srcSize, targetSize);
	SelectObject(dc, oldBitmap);
	DeleteDC(dc);
	DeleteObject(hbmpSrc);
	if (outBits) *outBits = (u32*)bitsDst;
	return hbmpDst; // Caller deletes with DeleteObject
}

static handle ScaleIconBitmap(handle icon, int targetSize)
{
	return ScaleIconBitmapEx(icon, targetSize, null);
}

static bool IconsLookAlike(handle a, handle b)
{
	// Two windows of the same app can expose the same artwork at different
	// resolutions (a 32px WM_GETICON icon vs. a 256px exe icon). Compare tiny
	// renders so we only swap in the sharper source when it is actually the
	// same icon; per-window icons (Explorer folders, game launchers) keep
	// their identity.
	if (!a || !b) return false;
	u32* pa = null, * pb = null;
	handle ha = ScaleIconBitmapEx(a, 16, &pa);
	handle hb = ScaleIconBitmapEx(b, 16, &pb);
	bool same = false;
	if (ha && hb && pa && pb) {
		u64 diff = 0;
		u64 total = 0;
		for (int i = 0; i < 16 * 16; i++) {
			u32 p = pa[i], q = pb[i];
			diff += (u64)abs((int)(p >> 24) - (int)(q >> 24));
			diff += (u64)abs((int)(p & 0xFF) - (int)(q & 0xFF));
			diff += (u64)abs((int)((p >> 8) & 0xFF) - (int)((q >> 8) & 0xFF));
			diff += (u64)abs((int)((p >> 16) & 0xFF) - (int)((q >> 16) & 0xFF));
			total += 4 * 255;
		}
		same = diff * 100 <= total * 15; // Mean channel difference <= 15%.
	}
	if (ha) DeleteObject(ha);
	if (hb) DeleteObject(hb);
	return same;
}

static handle GetAppIcon(string* filepath)
{
	//IsImmersiveProcess();
	//GetApplicationUserModelId(); // appmodel.h

	// From Raymond Chen: https://stackoverflow.com/a/12429114/659310
	//
	// Requires the following:
	//
	// #define COBJMACROS
	// #include "commoncontrols.h"
	//
	// SHGetFileInfoW docs:
	//   "You should call this function from a background thread. Failure to do
	//    so could cause the UI to stop responding." (docs)
	//   "If SHGetFileInfo returns an icon handle in the hIcon member of the
	//    SHFILEINFO structure pointed to by psfi, you are responsible for
	//    freeing it with DestroyIcon when you no longer need it." (docs)
	//   "You must initialize Component Object Model (COM) with CoInitialize or
	//    OleInitialize prior to calling SHGetFileInfo." (docs)
	//
	// NOTE: Can also check out SHDefExtractIcon
	//       https://devblogs.microsoft.com/oldnewthing/20140501-00/?p=1103

	//if (FAILED(CoInitialize(null))) {
	//	return null;
	//}
	HICON cached = { 0 };
	if (IconCacheLookup(filepath->text, (handle*)&cached)) {
		return cached; // Caller owns this copy
	}
	// Prefer a full-resolution extraction: picks the best embedded image
	// and scales cleanly to the requested size.
	{
		HICON hBig = null, hSmall = null;
		if (SUCCEEDED(SHDefExtractIconW(filepath->text, 0, 0, &hBig, &hSmall, UWP_ICON_SIZE))) {
			if (hSmall) DestroyIcon(hSmall);
			if (hBig) {
				IconCacheStore(filepath->text, hBig);
				return hBig;
			}
		}
	}
	IImageList* list = { 0 };
	if (FAILED(SHGetImageList(SHIL_JUMBO, &IID_IImageList, (void**)&list))) {
		return null;
	}
	SHFILEINFOW info = { 0 };
	if (!SHGetFileInfoW(filepath->text, 0, &info, sizeof info, SHGFI_SYSICONINDEX)) { // 2nd arg: -1, 0 or FILE_ATTRIBUTE_NORMAL
		Debug(L"suspicious SHGetFileInfoW return"); // SHGetFileInfoW has special return with SHGFI_SYSICONINDEX flag, which I think should never fail (docs unclear?)
		return null;
	}
	HICON icon = { 0 };
	IImageList_GetIcon(list, info.iIcon, ILD_TRANSPARENT, &icon);
	IImageList_Release(list);
	if (icon) {
		IconCacheStore(filepath->text, icon);
	}
	return icon; // Caller is responsible for calling DestroyIcon
}

static handle ChooseWindowIcon(handle hwnd, string* filepath, bool isExplorerFolder)
{
	// Prefer the sharpest icon that still identifies the window. Window-owned
	// icons win when they are already high-res; otherwise check the executable
	// for a larger copy of the same artwork. Explorer folder windows keep their
	// per-folder icon even at 32px, since the exe icon is a different image.
	handle windowIcon = GetWindowIcon(hwnd);
	int windowSize = windowIcon ? GetIconPixelWidth(windowIcon) : 0;
	if (windowIcon && windowSize >= 64) {
		return windowIcon;
	}

	handle appIcon = GetAppIcon(filepath);
	int appSize = appIcon ? GetIconPixelWidth(appIcon) : 0;
	if (appIcon && appSize > windowSize) {
		bool keepWindowIcon = isExplorerFolder ||
			(windowIcon && !IconsLookAlike(windowIcon, appIcon));
		if (!keepWindowIcon) {
			if (windowIcon) DestroyIcon(windowIcon);
			return appIcon;
		}
	}
	if (appIcon) DestroyIcon(appIcon);
	return windowIcon;
}

static bool IsDarkModeEnabled(void)
{
	ULONG value;
	ULONG size = sizeof value;
	if (!RegGetValueW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize", L"AppsUsesLightTheme", RRF_RT_DWORD, null, &value, &size)) {
		return !value; // 'value' is true for light mode
	}
	else {
		return true; // Default to dark mode
	}
}

static u32 GetAccentColor(void)
{
	ULONG value;
	ULONG size = sizeof value;
	if (!RegGetValueW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\DWM\\", L"AccentColor", RRF_RT_DWORD, null, &value, &size)) {
		return value;
	}
	else {
		//       AABBGGRR
		return 0xFFFFC24C; // Default to aqua color, sampled from Windows 11 Alt-Tab
	}
}

static void SetAutorun(bool enabled, u16* keyname, u16* args)
{
	string filepath;
	string target;
	filepath.length = GetModuleFileNameW(null, filepath.text, countof(filepath.text) - 1); // Get filepath of current module
	StringCchPrintfW(target.text, countof(target.text) - 1, L"\"%s\" %s", filepath.text, args);
	target.length = wcslen(target.text);
	HKEY regkey;
	i32 success; // BUG Not checking 'success' below
	if (enabled) {
		success = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, null, 0, KEY_SET_VALUE, null, &regkey, null);
		success = RegSetValueExW(regkey, keyname, 0, REG_SZ, (UCHAR*)target.text, target.length * sizeof * target.text); // TODO Oof, that's a nasty cast
		success = RegCloseKey(regkey);
	}
	else {
		success = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS, &regkey);
		success = RegDeleteValueW(regkey, keyname);
		success = RegCloseKey(regkey);
	}
}

static bool IsKeyDown(u32 key)
{
	return (bool)(GetAsyncKeyState(key) & 0x8000);
}



static int ReportWindowHandle(handle hwnd, handle target)
{
	// Tell user the executable name and class so they can add it to the blacklist
	string class = GetWindowClass(target);
	string path = GetExePath(target);
	string name = StringFileName(&path, false);

	u16 buffer[2048];
	StringCchPrintfW(buffer, countof(buffer) - 1, L"Add to blacklist?\n\nName:\t%s\nClass:\t%s\n\nPress Ctrl+C to copy this message.\n\nNote: Blacklist not working yet, it does nothing, TODO!", name.text, class.text);
	SetForegroundWindow(hwnd);
	return MessageBoxW(hwnd, buffer, L"cmdtab", MB_OK | MB_ICONASTERISK | MB_TASKMODAL) == IDYES;
}

static void ReceiveLastInputEvent(void)
{
	// Oh my, the fucking rabbit hole...
	// This is a hack (one of many flavors) to bypass the restrictions on setting the foreground window
	// https://github.com/microsoft/PowerToys/blob/7d0304fd06939d9f552e75be9c830db22f8ff9e2/src/modules/fancyzones/FancyZonesLib/util.cpp#L376
	//
	// There is also a subtle issue with the Alt-key functionality of windows with menus, where
	// the menu selection will get stuck until the window gets an AltUp event. It doesn't seem
	// to help to send the AltUp event globally; I think the window must receive it to reset its
	// menu selection. But this differs from Windows' normal AltTab widget, which somehow bypasses
	// this issue. I've confirmed that the AltTab window does something different because there are
	// subtle observable behavior differences in the menu selection when Windows' normal AltTab is
	// invoked vs. cmdtab. In the end, I figured out that instead of sending an AltUp event, if I
	// just steal focus as quickly as possible upon activation, the menu selection does not get stuck,
	// and the behavior exhibited perfectly matches Windows' normal AltTab. Success!
	SendInput(1, &(INPUT){.type = INPUT_KEYBOARD}, sizeof(INPUT));
}

static void ShowWindowX(handle hwnd) // ShowWindow already taken
{
	if (GetForegroundWindow() != hwnd) {
		if (IsIconic(hwnd)) {
			ShowWindow(hwnd, SW_RESTORE);
		}
		else {
			ShowWindow(hwnd, SW_SHOWNA);
		}
		if (SetForegroundWindow(GetAppHost(hwnd))) {
			Print(L"switch to ");
			PrintWindowX(hwnd);
		}
		else {
			Print(L"couldn't switch to ");
			PrintWindowX(hwnd);
		}
	}
	else {
		Print(L"switch to: already foreground\n");
	}
}

static void PreviewWindow(handle hwnd)
{
	//typedef HRESULT (__stdcall *DwmpActivateLivePreview)(bool peekOn, handle hPeekWindow, handle hTopmostWindow, u32 peekType1or3, i64 newForWin10);
	//DwmpActivateLivePreview(true, hwnd, gui, 3, 0);

	// TODO "perviewing" not implemented yet. Have to find a way to show windows without changing their Z-Order (i.e. "previewing" them)

	// NOT IMPLEMENTED YET, FALLBACK TO SHOW
	ShowWindowX(hwnd);
}

static void HideWindow(handle hwnd)
{
	// WARNING Can't use this because we filter out hidden windows
	ShowWindow(hwnd, SW_HIDE); // Yes, call ShowWindow to hide window...
}

static void MinimizeWindow(handle hwnd)
{
	PostMessageW(hwnd, WM_SYSCOMMAND, SC_MINIMIZE, 0);
}

static void CloseWindowX(handle hwnd) // CloseWindow already taken
{
	Print(L"close window ");
	PrintWindowX(hwnd);
	PostMessageW(hwnd, WM_CLOSE, 0, 0);
}

static void TerminateWindowProcess(handle hwnd)
{
	ULONG pid;
	GetWindowThreadProcessId(hwnd, &pid);
	handle process = OpenProcess(PROCESS_TERMINATE, false, pid); // NOTE See GetProcessHandleFromHwnd
	if (!process || process == INVALID_HANDLE_VALUE || !TerminateProcess(process, 0)) {
		Print(L"ERROR couldn't terminate process with pid: %u\n", pid);
	}
	if (process) CloseHandle(process);
}

//==============================================================================
// cmdtab impl
//==============================================================================

struct config {
	// Hotkeys
	struct { u32 mod, key; } hotkeyForApps;
	struct { u32 mod, key; } hotkeyForWindows;
	// Behavior
	bool switchApps;
	bool switchWindows;
	bool fastSwitchingForApps; // TODO
	bool fastSwitchingForWindows;
	bool showSwitcherForApps;
	bool showSwitcherForWindows;
	bool wrapbump;
	bool restoreOnCancel;
	// Appearance
	bool darkmode;
	bool hideTaskbar;
	u32 switcherHeight;
	u32 switcherHorzMargin;
	u32 switcherVertMargin;
	u32 iconWidth;
	u32 iconHorzPadding;
	// Blacklist
	struct identifier {
		u16* filename;          // Filename without file extension, ex. "explorer". Can be null.
		u16* windowClass;       // Window class name. Can be null.
	} blacklist[32];
};

struct app {
	string path;                // Full path of app executable.
	string name;                // Window title, or app name as fallback.
	handle icon;                // Big app icon.
	handle iconBmp;             // High-quality scaled copy of 'icon' (null = draw icon directly).
	u32 iconBmpSize;            // Edge length of 'iconBmp' in pixels.
	handle window;              // The specific window handle for this entry.
	string windowTitle;         // Full window title for display.
};

static struct app Apps[128];    // Apps that are displayed in switcher.
static size AppsCount;          // Number of elements in 'Apps' array.
static struct app* SelectedApp; // Pointer to one of the elements in 'Apps' array. The app for the 'SelectedWindow'.
static handle SelectedWindow;   // Currently selected window in switcher. Non-NULL indicates switcher is active.
static handle RestorableWindow; // Whatever window was foreground when switcher was activated. Does not need to be in filtered 'Apps' array.
static handle History[128];     // Window activation history from Windows events. Deduplicated, so prior activations are moved to the front.
static size HistoryCount;       // Number of elements in 'History' array.
static handle Switcher;         // Handle for main window (i.e. switcher).
static handle DrawingContext;   // Drawing context for double-buffered drawing of main window.
static handle DrawingBitmap;    // Off-screen bitmap used for double-buffered drawing of main window.
static void* DrawingBits;       // Pixel buffer of DrawingBitmap (32-bit DIB section).
static RECT DrawingRect;        // Size of the off-screen bitmap.
// Live layered glass when transparency effects are on (decided at startup);
// otherwise the window stays opaque and RedrawSwitcher paints software blur.
static bool UseLayeredGlass = false;
static u16 Keyboard[16];        // 256 bits to track key repeat for low-level keyboard hook.
static i32 MouseX, MouseY;      // Mouse position, for highlighting and clicking app icons.

static struct config Config = { // cmdtab settings
	// Hotkeys
	.hotkeyForApps = { 0x38, 0x0F }, // Alt-Tab in scancodes, must be updated during runtime, see InitConfig
	.hotkeyForWindows = { 0x38, 0x29 }, // Alt-Tilde/Backquote in scancodes, must be updated during runtime, see InitConfig
	// Behavior
	.switchApps = true,
	.switchWindows = true,
	.fastSwitchingForApps = false,
	.fastSwitchingForWindows = true,
	.showSwitcherForApps = true,
	.showSwitcherForWindows = false,
	.wrapbump = true,
	.restoreOnCancel = false,
	// Appearance
	.darkmode = false,
	.hideTaskbar = true,
	.switcherHeight = 280,
	.switcherHorzMargin = 48,
	.switcherVertMargin = 48,
	.iconWidth = 156,
	.iconHorzPadding = 12,
	// Blacklist
	.blacklist = {
		{ null,                       L"ApplicationFrameWindow" },
		{ L"SearchHost",              L"Windows.UI.Core.CoreWindow" },
		{ L"StartMenuExperienceHost", L"Windows.UI.Core.CoreWindow" },
		{ L"Wispr Flow Helper",       null },
		{ L"Wispr Flow",              null },
		{ L"Raycast",          null },
	},
};

static void InitConfig(void)
{
	// Initialize runtime-dependent settings, like those dependent on user's current kbd layout
	// The default key2 is scan code 0x29 (hex) / 41 (decimal)
	// This is the key that is physically below Esc, left of 1 and above Tab
	Config.hotkeyForApps.mod = MapVirtualKeyW(Config.hotkeyForApps.mod, MAPVK_VSC_TO_VK_EX);
	Config.hotkeyForApps.key = MapVirtualKeyW(Config.hotkeyForApps.key, MAPVK_VSC_TO_VK_EX);
	Config.hotkeyForWindows.mod = MapVirtualKeyW(Config.hotkeyForWindows.mod, MAPVK_VSC_TO_VK_EX);
	Config.hotkeyForWindows.key = MapVirtualKeyW(Config.hotkeyForWindows.key, MAPVK_VSC_TO_VK_EX);
	Config.darkmode = IsDarkModeEnabled();
	Print(L"darkmode %s\n", Config.darkmode ? L"YES" : L"NO");
}

static void HideTaskbar(void)
{
	if (!Config.hideTaskbar) return;

	HWND taskbar = FindWindowW(L"Shell_TrayWnd", NULL);
	if (taskbar) {
		ShowWindow(taskbar, SW_HIDE);
	}

	// También ocultar la barra de tareas secundaria en sistemas multi-monitor
	HWND secondaryTaskbar = FindWindowW(L"Shell_SecondaryTrayWnd", NULL);
	while (secondaryTaskbar) {
		ShowWindow(secondaryTaskbar, SW_HIDE);
		secondaryTaskbar = FindWindowExW(NULL, secondaryTaskbar, L"Shell_SecondaryTrayWnd", NULL);
	}
}

static void ShowTaskbar(void)
{
	HWND taskbar = FindWindowW(L"Shell_TrayWnd", NULL);
	if (taskbar) {
		ShowWindow(taskbar, SW_SHOW);
	}

	// También mostrar la barra de tareas secundaria en sistemas multi-monitor
	HWND secondaryTaskbar = FindWindowW(L"Shell_SecondaryTrayWnd", NULL);
	while (secondaryTaskbar) {
		ShowWindow(secondaryTaskbar, SW_SHOW);
		secondaryTaskbar = FindWindowExW(NULL, secondaryTaskbar, L"Shell_SecondaryTrayWnd", NULL);
	}
}

static void PrintApps(void)
{
	int windowsCount = 0;
	for (int i = 0; i < AppsCount; i++) {
		Print(L"%i ", i);
		struct app* app = &Apps[i];
		PrintWindowX(app->window);
		windowsCount += 1;
	}
	Print(L"%i apps %i windows, %i history:\n", AppsCount, windowsCount, HistoryCount);
	// And print History
	for (int i = 0; i < HistoryCount; i++) {
		Print(L"%i ", i);
		PrintWindowX(History[i]);
	}
}

static bool WindowIsBlacklisted(string* filename, string* windowClass)
{
#define wcseq(str1, str2) (wcscmp(str1, str2) == 0)

	// Iterate blacklist. I allow three kinds of entries in the black list:
	// 1) {name,class} both name and class are specified and both must match
	// 2) {name,null}  only name is specified and must match
	// 3) {null,class} only class is specified and must match
	// 4) {null,null}  terminates array
	for (size i = 0; i < countof(Config.blacklist); i++) {
		struct identifier ignored = Config.blacklist[i];
		if (ignored.filename && ignored.windowClass) {
			if (wcseq(ignored.filename, filename->text) &&
				wcseq(ignored.windowClass, windowClass->text)) {
				return true;
			}
		}
		else if (ignored.filename && !ignored.windowClass && wcseq(ignored.filename, filename->text)) {
			return true;
		}
		else if (!ignored.filename && ignored.windowClass && wcseq(ignored.windowClass, windowClass->text)) {
			return true;
		}
		else if (!ignored.filename && !ignored.windowClass) {
			break;
		}
	}
	return false;
}

static void AddToHistory(handle hwnd) {
	// Get hosted window in case of UWP host
	hwnd = GetCoreWindow(hwnd);
	// 
	if (History[0] == hwnd) {
		Print(L"(already first in history) ");
		Print(L"activate window %s", GetAppHost(hwnd) != hwnd ? L"(uwp) " : L"");
		PrintWindowX(hwnd);
		return;
	}
	// Potentially find 'hwnd' in activation list and shift other hwnds down to position of 'hwnd' and then put 'hwnd' first
	for (int i = 1; i < HistoryCount; i++) {
		if (History[i] == hwnd) {
			memmove(&History[1], &History[0], sizeof History[0] * i);
			History[0] = hwnd;
			return;
		}
	}

	// 'hwnd' doesn't already exist in activation list; so validate and add it

	// Basic checks for eligibility in Alt-Tab
	if (!IsAltTabWindow(hwnd)) {
		Print(L"(ignored) ");
		Print(L"activate window %s", GetAppHost(hwnd) != hwnd ? L"(uwp) " : L"");
		PrintWindowX(hwnd);
		return;
	}
	// Get module filepath, abort if failed (most likely access denied)
	string filepath = GetExePath(hwnd);
	if (!filepath.ok) {
		return; // Don't have to print error, since GetFilepath already does that
	}
	// Check window against user-defined blacklist
	string filename = StringFileName(&filepath, false);
	string class = GetWindowClass(hwnd);
	if (WindowIsBlacklisted(&filename, &class)) {
		Print(L"(blacklisted) ");
		Print(L"activate window %s", GetAppHost(hwnd) != hwnd ? L"(uwp) " : L"");
		PrintWindowX(hwnd);
		return;
	}
	if (!IsRealExplorerFolderWindow(&filename, &class)) {
		Print(L"(explorer shell) ");
		Print(L"activate window %s", GetAppHost(hwnd) != hwnd ? L"(uwp) " : L"");
		PrintWindowX(hwnd);
		return;
	}

	// 'hwnd' is valid and should be added

	// Shift all hwnds down one position and then put 'hwnd' first
	if (HistoryCount < countof(History)) {
		memmove(&History[1], &History[0], sizeof History[0] * ++HistoryCount);
	}
	else {
		memmove(&History[1], &History[0], sizeof History[0] * HistoryCount);
	}
	History[0] = hwnd;
	Print(L"activate window %s", GetAppHost(hwnd) != hwnd ? L"(uwp) " : L"");
	PrintWindowX(hwnd);
}

static void AddToSwitcher(handle hwnd)
{
	// 1. Get hosted window in case of UWP host
	handle originalHwnd = hwnd;
	hwnd = GetCoreWindow(hwnd);
	// 2. Basic checks for eligibility in Alt-Tab
	if (!IsAltTabWindow(hwnd)) {
		Print(L"(ignored) ");
		Print(L"add window %s", GetAppHost(hwnd) != hwnd ? L"(uwp) " : L"");
		PrintWindowX(hwnd);
		return;
	}
	// 3. Get module filepath, abort if failed (most likely access denied)
	string filepath = GetExePath(hwnd);
	if (!filepath.ok) {
		return; // Don't have to print error, since GetFilepath already does that
	}
	// 4. Check window against user-defined blacklist
	string filename = StringFileName(&filepath, false);
	string class = GetWindowClass(hwnd);
	if (WindowIsBlacklisted(&filename, &class)) {
		Print(L"(blacklisted) ");
		Print(L"add window %s", GetAppHost(hwnd) != hwnd ? L"(uwp) " : L"");
		PrintWindowX(hwnd);
		return;
	}
	// Explorer hosts many invisible shell windows; only real folder windows belong in the switcher
	if (!IsRealExplorerFolderWindow(&filename, &class)) {
		Print(L"(explorer shell) ");
		Print(L"add window %s", GetAppHost(hwnd) != hwnd ? L"(uwp) " : L"");
		PrintWindowX(hwnd);
		return;
	}

	// 5. Create individual entry for each window (no grouping)
	if (AppsCount >= countof(Apps)) {
		Error(Switcher, L"ERROR reached max. windows\n");
		return;
	}

	struct app* app = &Apps[AppsCount++];
	if (app->icon) DestroyIcon(app->icon); // Cleanup previous icon if reusing slot
	if (app->iconBmp) DeleteObject(app->iconBmp); // Same for the scaled bitmap
	app->iconBmp = null;
	app->iconBmpSize = 0;

	// Set basic app info
	app->path = filepath;
	app->window = hwnd;

	// Check if this is a UWP app and handle it specially
	bool isUWP = IsUWPApp(hwnd);
	if (isUWP) {
		Print(L"Detected UWP app, attempting to get AUMID...\n");

		// For UWP apps, get the Application User Model ID
		// originalHwnd is the ApplicationFrameWindow (if coming from EnumWindows)
		// hwnd is the CoreWindow (after GetCoreWindow)
		string aumid = GetUWPAppUserModelId(originalHwnd, hwnd);

		if (aumid.ok) {
			Print(L"Got AUMID: %s\n", aumid.text);

			// Try to get UWP-specific icon and name
			app->icon = GetUWPAppIcon(&aumid, originalHwnd);
			app->name = GetUWPAppName(&aumid);

			if (app->icon) {
				Print(L"Successfully got UWP icon\n");
			}
			if (app->name.ok) {
				Print(L"Successfully got UWP name: %s\n", app->name.text);
			}
		}
		else {
			Print(L"Failed to get AUMID, trying fallbacks\n");
		}

		// Fallback: Try to get icon from the window itself
		if (!app->icon) {
			Print(L"Trying to get icon from window messages...\n");
			HICON icon = (HICON)SendMessageW(originalHwnd, WM_GETICON, ICON_BIG, 0);
			if (!icon) icon = (HICON)SendMessageW(originalHwnd, WM_GETICON, ICON_SMALL2, 0);
			if (!icon) icon = (HICON)GetClassLongPtrW(originalHwnd, GCLP_HICON);
			if (icon) {
				app->icon = CopyIcon(icon);
				Print(L"Got icon from window\n");
			}
		}

		// Final fallback: use default icon
		if (!app->icon) {
			Print(L"Using fallback icon from filepath\n");
			app->icon = GetAppIcon(&filepath);
		}

		// Fallback for name: try window title
		if (!app->name.ok) {
			Print(L"Trying to get name from window title...\n");
			app->name = GetWindowTitle(originalHwnd);
			if (app->name.ok) {
				Print(L"Got name from window title: %s\n", app->name.text);
			}
		}

		// If still no name, try the CoreWindow title
		if (!app->name.ok && hwnd != originalHwnd) {
			Print(L"Trying to get name from core window title...\n");
			app->name = GetWindowTitle(hwnd);
			if (app->name.ok) {
				Print(L"Got name from core window: %s\n", app->name.text);
			}
		}

		// Last resort: use AUMID as name
		if (!app->name.ok && aumid.ok) {
			Print(L"Using AUMID as name\n");
			app->name = aumid;
		}

		// Absolute last resort: use filename
		if (!app->name.ok) {
			Print(L"Using filename as name\n");
			app->name = StringFileName(&filepath, false);
		}
	}
	else {
		// Regular Win32 app: use the sharpest available source while keeping
		// the window's identity. A 32px WM_GETICON icon is soft at dock size,
		// so the exe's 256px icon is used when it shows the same artwork;
		// per-window icons (Explorer folders, launchers) are preserved.
		bool isExplorerFolder = StringsAreEqual(&filename, &ExplorerExe) &&
			(StringsAreEqual(&class, &ExplorerCabinetClass) ||
				StringsAreEqual(&class, &ExplorerExploreClass));
		app->icon = ChooseWindowIcon(hwnd, &filepath, isExplorerFolder);
		app->name = GetAppName(&filepath);
	}

	// Never leave an invisible hole: ultimate fallback is the stock app icon.
	// (IDI_APPLICATION = 32512; the IDI_* macros are excluded by NOICONS.)
	if (!app->icon) {
		Print(L"Using stock icon fallback\n");
		app->icon = CopyIcon(LoadIconW(null, MAKEINTRESOURCEW(32512)));
	}

	// Icons are scaled lazily in RedrawSwitcher, once the final on-screen
	// size is known (it depends on the monitor and the number of apps).

	// Store window title for potential future use
	app->windowTitle = GetWindowTitle(hwnd);

	Print(L"add window %s", isUWP ? L"(uwp) " : L"");
	PrintWindowX(hwnd);
}

static void ActivateWindow(handle hwnd)
{
	// Find the specific window entry and move it to front
	struct app* targetApp = null;
	int targetIndex = -1;

	for (int i = 0; i < AppsCount; i++) {
		if (Apps[i].window == hwnd) {
			targetApp = &Apps[i];
			targetIndex = i;
			break;
		}
	}

	// Move window to front of list if found and not already first
	if (targetApp && targetIndex > 0) {
		struct app temp = *targetApp;
		memmove(&Apps[1], &Apps[0], sizeof(Apps[0]) * targetIndex);
		Apps[0] = temp;
	}
}

static BOOL CALLBACK _AddToSwitcher(HWND hwnd, LPARAM lparam)
{
	// EnumWindowsProc used by UpdateApps: Call AddToSwitcher with every top-level window enumerated by EnumWindows
	(*((int*)lparam))++; // Increment window counter arg
	AddToSwitcher(hwnd);
	return true; // Return true to continue EnumWindows
}

static void UpdateApps(void)
{
	// Rebuild the whole window list and measure how long it takes
	i64 start = StartMeasuring();
	int windowsCount = 0;
	AppsCount = 0;
	EnumWindows(_AddToSwitcher, (LPARAM)&windowsCount); // _AddToSwitcher calls AddToSwitcher with every top-level window enumerated by EnumWindows
	AddToHistory(GetForegroundWindow()); // "Activate" foreground window to record it in window activation history
	for (int i = HistoryCount - 1; i >= 0; i--) {
		ActivateWindow(History[i]);
	}
	Log(L"%i windows, %llims elapsed\n", windowsCount, FinishMeasuring(start));
	PrintApps();
}

static void SelectFirstWindow(void)
{
	if (AppsCount > 0) {
		SelectedApp = &Apps[0];
		SelectedWindow = Apps[0].window; // Point directly to the window handle
		RestorableWindow = GetForegroundWindow();
	}
	else {
		Print(L"nothing to select\n");
	}
}

static i32 GetAppIconLeft(int index, u32 iconWidth, u32 iconPad, u32 horzPad)
{
	i32 left0 = index == 0 ? (i32)iconPad : 0;
	i32 right0 = index != 0 ? (i32)iconPad : 0;
	i32 icons = (iconPad + iconWidth + iconPad) * index;
	return horzPad + left0 + icons + right0;
}

static u32 GetDockRadius(void)
{
	// Concentric with the selection tile: outer radius = tile radius + the gap
	// between tile and dock edge. A plain ratio of the dock height leaves the
	// corner gap wider along the diagonal than along the straight edges.
	u32 iconW = Config.iconWidth;
	u32 iconInset = max(4, (u32)(iconW * 0.06f));
	u32 selectedInset = max(6, (u32)(iconW * 0.08f));
	u32 iconSize = iconW - iconInset;
	u32 selectedRadius = (u32)(iconSize * RADIUS_RATIO + 0.5f) + selectedInset + iconInset / 2;
	u32 gap = Config.switcherVertMargin > selectedInset ? Config.switcherVertMargin - selectedInset : 0;
	return selectedRadius + gap;
}

static HRGN MakeRoundedRgn(RECT rc, int r)
{
	// Same geometry as FillRoundedSilhouette: pixel-center test, exclusive
	// right/bottom. CreateRoundRectRgn has an off-by-one on right/bottom and
	// stretches the right corners, so the region is built from scanlines.
	int w = rc.right - rc.left;
	int h = rc.bottom - rc.top;
	if (w <= 0 || h <= 0) return CreateRectRgn(0, 0, 0, 0);
	if (r > w / 2) r = w / 2;
	if (r > h / 2) r = h / 2;
	if (r < 0) r = 0;

	int maxRects = 2 * r + 1;
	size_t bytes = sizeof(RGNDATAHEADER) + sizeof(RECT) * (size_t)maxRects;
	RGNDATA* data = (RGNDATA*)malloc(bytes);
	if (!data) return CreateRectRgn(rc.left, rc.top, rc.right, rc.bottom);
	RECT* rects = (RECT*)data->Buffer;
	int n = 0;

	// Top rows, ascending y
	for (int y = 0; y < r; y++) {
		float d = (float)r - ((float)y + 0.5f);
		float inset = (float)r - sqrtf((float)(r * r) - d * d);
		int x0 = (int)ceilf(inset - 0.5f);
		if (x0 < 0) x0 = 0;
		rects[n++] = (RECT){ rc.left + x0, rc.top + y, rc.right - x0, rc.top + y + 1 };
	}
	// Middle
	if (h > 2 * r) {
		rects[n++] = (RECT){ rc.left, rc.top + r, rc.right, rc.bottom - r };
	}
	// Bottom rows, ascending y (mirror of top)
	for (int y = r - 1; y >= 0; y--) {
		float d = (float)r - ((float)y + 0.5f);
		float inset = (float)r - sqrtf((float)(r * r) - d * d);
		int x0 = (int)ceilf(inset - 0.5f);
		if (x0 < 0) x0 = 0;
		rects[n++] = (RECT){ rc.left + x0, rc.bottom - 1 - y, rc.right - x0, rc.bottom - y };
	}

	data->rdh.dwSize = sizeof(RGNDATAHEADER);
	data->rdh.iType = RDH_RECTANGLES;
	data->rdh.nCount = n;
	data->rdh.nRgnSize = n * sizeof(RECT);
	data->rdh.rcBound = rc;
	HRGN rgn = ExtCreateRegion(null, (DWORD)bytes, data);
	free(data);
	return rgn;
}

static handle MakeDockLabelRegion(u32 width, u32 dockHeight, RECT* labelRect, bool hasLabel)
{
	// Union of dock panel and label pill (caller owns the result). Radii match
	// the alpha silhouette drawn in RedrawSwitcher exactly.
	RECT dockRect = { 0, 0, (i32)width, (i32)dockHeight };
	HRGN windowRegion = MakeRoundedRgn(dockRect, (int)GetDockRadius());
	if (hasLabel) {
		int labelW = labelRect->right - labelRect->left;
		int labelH = labelRect->bottom - labelRect->top;
		HRGN labelRegion = MakeRoundedRgn(*labelRect, min(labelW, labelH) / 2);
		CombineRgn(windowRegion, windowRegion, labelRegion, RGN_OR);
		DeleteObject(labelRegion);
	}
	return windowRegion;
}

static void UpdateSwitcherWindowRegion(u32 width, u32 dockHeight, RECT* labelRect, bool hasLabel)
{
	// SetWindowRgn takes ownership of the region, so don't delete it.
	SetWindowRgn(Switcher, MakeDockLabelRegion(width, dockHeight, labelRect, hasLabel), TRUE);
}

static void SelectNextWindow(bool applevel, bool reverse, bool wrap)
{
	if (!SelectedApp) {
		Error(Switcher, L"invalid state: no SelectedApp");
		Debug(L"invalid state: no SelectedApp");
		return;
	}

	// Since each entry is now a single window, navigation is always at "app level"
	struct app* firstApp = &Apps[0];
	struct app* lastApp = &Apps[AppsCount - 1];

	if (reverse) {
		if (SelectedApp > firstApp) {
			SelectedApp--;
		}
		else if (wrap) {
			SelectedApp = lastApp;
		}
	}
	else {
		if (SelectedApp < lastApp) {
			SelectedApp++;
		}
		else if (wrap) {
			SelectedApp = firstApp;
		}
	}

	SelectedWindow = SelectedApp->window;
	NavLog(L"step sel=%d count=%d", (int)(SelectedApp - Apps), (int)AppsCount);

	Print(L"select ");
	PrintWindowX(SelectedWindow);
}

static void ResizeSwitcher(void)
{
	// Use the monitor where the mouse pointer is currently placed (#5)
	POINT mousePos = { 0 };
	GetCursorPos(&mousePos);
	MONITORINFO mi = { .cbSize = sizeof(MONITORINFO) };
	GetMonitorInfoW(MonitorFromPoint(mousePos, MONITOR_DEFAULTTONEAREST), &mi);

	// Calculate available screen width
	u32 screenWidth = mi.rcMonitor.right - mi.rcMonitor.left;
	u32 screenHeight = mi.rcMonitor.bottom - mi.rcMonitor.top;

	// Base metrics
	const u32 maxIconWidth = 132;
	const u32 minIconWidth = 48;
	const u32 basePadding = 26;
	const u32 sideGutter = 34;      // Always keep side breathing room (Apple-like)

	u32 iconWidth = maxIconWidth;
	u32 iconPadding = 12;
	u32 padding = basePadding; // vertical padding (top/bottom of icons)
	u32 horzPad = 14;          // side padding; + iconPadding = 26, matches vertical

	u32 w = 0;
	u32 usableWidth = screenWidth > sideGutter * 2 ? screenWidth - sideGutter * 2 : screenWidth;
	u32 marginWidth = 2 * horzPad;
	u32 requiredWidth = (AppsCount * iconWidth) + (AppsCount * iconPadding * 2) + marginWidth;

	// Keep natural size whenever possible; only shrink when it doesn't fit.
	if (requiredWidth <= usableWidth) {
		w = requiredWidth;
	}
	else {
		w = usableWidth;
		u32 availableWidth = w - marginWidth - (AppsCount * iconPadding * 2);
		if (AppsCount > 0) {
			iconWidth = max(minIconWidth, availableWidth / AppsCount);
		}
	}

	// Dock height (icons) plus space below for the app-name label pill
	u32 dockHeight = (u32)(padding + iconWidth + padding);
	u32 maxDockHeight = min((u32)300, (u32)(screenHeight * 0.90f));
	if (dockHeight > maxDockHeight) {
		dockHeight = maxDockHeight;
	}

	u32 h = dockHeight + LABEL_GAP + LABEL_AREA_HEIGHT;
	i32 x = mi.rcMonitor.left + (screenWidth - w) / 2;
	i32 y = mi.rcMonitor.top + (mi.rcMonitor.bottom - mi.rcMonitor.top - h) / 2;

	// Update Config so RedrawSwitcher uses the scaled metrics
	Config.iconWidth = iconWidth;
	Config.switcherHeight = dockHeight;
	Config.switcherHorzMargin = horzPad;
	Config.switcherVertMargin = padding;

	MoveWindow(Switcher, x, y, w, h, false); // Yes, "MoveWindow" means "ResizeWindow"

	// Resize off-screen double-buffering bitmap
	RECT resized = { x, y, x + w, y + h };
	if (!EqualRect(&DrawingRect, &resized)) {
		handle context = GetDC(Switcher);
		DeleteObject(DrawingBitmap);
		DeleteDC(DrawingContext);
		DrawingRect = resized;
		DrawingContext = CreateCompatibleDC(context);
		{
			// 32-bit top-down DIB: CPU-writable (translucent fill) and
			// alpha-correct for UpdateLayeredWindow.
			i32 bw = DrawingRect.right - DrawingRect.left;
			i32 bh = DrawingRect.bottom - DrawingRect.top;
			BITMAPINFO dbmi = { 0 };
			dbmi.bmiHeader.biSize = sizeof(dbmi.bmiHeader);
			dbmi.bmiHeader.biWidth = bw;
			dbmi.bmiHeader.biHeight = -bh;
			dbmi.bmiHeader.biPlanes = 1;
			dbmi.bmiHeader.biBitCount = 32;
			dbmi.bmiHeader.biCompression = BI_RGB;
			DrawingBitmap = CreateDIBSection(context, &dbmi, DIB_RGB_COLORS, &DrawingBits, null, 0);
		}
		DbgLog(L"dib bmp=%p bits=%p %dx%d gle=%u", DrawingBitmap, DrawingBits, (int)(DrawingRect.right - DrawingRect.left), (int)(DrawingRect.bottom - DrawingRect.top), GetLastError());
		if (DrawingBitmap) {
			handle oldBitmap = (handle)SelectObject(DrawingContext, DrawingBitmap);
			DeleteObject(oldBitmap);
		}
		ReleaseDC(Switcher, context);
	}
}

static handle BackdropSmall = null; // Downscaled blurred snapshot of what's behind the switcher (32-bit DIB section)
static void* BackdropBits = null; // Pixel buffer of BackdropSmall
static i32 BackdropSmallW, BackdropSmallH;
static i32 BackdropW, BackdropH;
static bool BackdropValid = false;

static void FreeBackdrop(void)
{
	if (BackdropSmall) { DeleteObject(BackdropSmall); BackdropSmall = null; BackdropBits = null; }
	BackdropSmallW = BackdropSmallH = 0;
	BackdropW = BackdropH = 0;
	BackdropValid = false;
}

static void CaptureBackdrop(void)
{
	// Snapshot the screen behind the switcher (it is still hidden at this
	// point) and shrink it to 1/8: downscaling IS the blur (frosted glass).
	// Works whether or not Windows transparency effects are enabled.
	i32 w = (i32)(DrawingRect.right - DrawingRect.left);
	i32 h = (i32)(DrawingRect.bottom - DrawingRect.top);
	if (w <= 0 || h <= 0) return;
	i32 sw = max(1, w / 8);
	i32 sh = max(1, h / 8);
	handle screen0 = GetDC(null);
	if (!BackdropSmall) {
		BITMAPINFO bmi = { 0 };
		bmi.bmiHeader.biSize = sizeof(bmi.bmiHeader);
		bmi.bmiHeader.biWidth = sw;
		bmi.bmiHeader.biHeight = -sh; // Top-down
		bmi.bmiHeader.biPlanes = 1;
		bmi.bmiHeader.biBitCount = 32;
		bmi.bmiHeader.biCompression = BI_RGB;
		BackdropSmall = CreateDIBSection(screen0, &bmi, DIB_RGB_COLORS, &BackdropBits, null, 0);
		if (!BackdropSmall || !BackdropBits) { BackdropSmall = null; BackdropBits = null; ReleaseDC(null, screen0); return; }
		BackdropSmallW = sw;
		BackdropSmallH = sh;
	}
	ReleaseDC(null, screen0);
	handle screen = GetDC(null);
	handle tmpContext = CreateCompatibleDC(screen);
	handle fullBmp = CreateCompatibleBitmap(screen, w, h);
	handle oldTmp = (handle)SelectObject(tmpContext, fullBmp);
	BitBlt(tmpContext, 0, 0, w, h, screen, DrawingRect.left, DrawingRect.top, SRCCOPY);
	handle smallContext = CreateCompatibleDC(screen);
	handle oldSmall = (handle)SelectObject(smallContext, BackdropSmall);
	SetStretchBltMode(smallContext, HALFTONE);
	SetBrushOrgEx(smallContext, 0, 0, null);
	StretchBlt(smallContext, 0, 0, sw, sh, tmpContext, 0, 0, w, h, SRCCOPY);
	// Second pass for extra softness: up and down again.
	SetStretchBltMode(tmpContext, HALFTONE);
	SetBrushOrgEx(tmpContext, 0, 0, null);
	StretchBlt(tmpContext, 0, 0, w, h, smallContext, 0, 0, sw, sh, SRCCOPY);
	StretchBlt(smallContext, 0, 0, sw, sh, tmpContext, 0, 0, w, h, SRCCOPY);
	// Darken to dark-glass level with a deterministic software multiply
	// (no dependence on AlphaBlend/DWM state).
	GdiFlush();
	if (BackdropBits) {
		u32* pixels = (u32*)BackdropBits;
		i32 count = sw * sh;
		for (i32 i = 0; i < count; i++) {
			u32 p = pixels[i];
			u32 b = (p & 0xFF) * 77 / 256;
			u32 g = ((p >> 8) & 0xFF) * 77 / 256;
			u32 r = ((p >> 16) & 0xFF) * 77 / 256;
			pixels[i] = (p & 0xFF000000) | (r << 16) | (g << 8) | b;
		}
	}
	SelectObject(smallContext, oldSmall);
	SelectObject(tmpContext, oldTmp);
	DeleteDC(smallContext);
	DeleteDC(tmpContext);
	DeleteObject(fullBmp);
	ReleaseDC(null, screen);
	BackdropW = w;
	BackdropH = h;
	BackdropValid = true;
}

static void PaintBackdropGlass(void)
{
	// Frosted glass: stretch the blurred snapshot over the buffer, then
	// darken it with a translucent black layer for the dark-glass look.
	i32 w = (i32)(DrawingRect.right - DrawingRect.left);
	i32 h = (i32)(DrawingRect.bottom - DrawingRect.top);
	if (w <= 0 || h <= 0) return;
	if (!BackdropValid || !BackdropSmall || w != BackdropW || h != BackdropH) {
		FreeBackdrop();
		CaptureBackdrop();
	}
	if (!BackdropValid || !BackdropSmall) {
		HBRUSH fallback = CreateSolidBrush(RGB(0, 0, 0));
		RECT full = { 0, 0, w, h };
		FillRect(DrawingContext, &full, fallback);
		DeleteObject(fallback);
		return;
	}
	handle screen = GetDC(null);
	handle smallContext = CreateCompatibleDC(screen);
	handle oldSmall = (handle)SelectObject(smallContext, BackdropSmall);
	SetStretchBltMode(DrawingContext, HALFTONE);
	SetBrushOrgEx(DrawingContext, 0, 0, null);
	StretchBlt(DrawingContext, 0, 0, w, h, smallContext, 0, 0, BackdropSmallW, BackdropSmallH, SRCCOPY);
	SelectObject(smallContext, oldSmall);
	DeleteDC(smallContext);
	ReleaseDC(null, screen);
}

static void ClearDrawingBuffer(void)
{
	// Every frame starts fully transparent: in layered mode the pixel alpha is
	// what shapes the window, so nothing may linger from the previous frame.
	i32 w = DrawingRect.right - DrawingRect.left;
	i32 h = DrawingRect.bottom - DrawingRect.top;
	if (!DrawingBits || w <= 0 || h <= 0) return;
	memset(DrawingBits, 0, (size_t)w * (size_t)h * 4);
	GdiFlush();
}

static void FillRoundedSilhouette(RECT rect, u32 cornerRadius, u32 alpha)
{
	// Anti-aliased rounded-rect fill with premultiplied alpha. Used for the
	// shapes that are part of the layered window's silhouette (dock panel and
	// app-name pill): a window region can only clip on whole pixels, which
	// leaves the pill's arcs visibly stair-stepped, so the edges come from the
	// pixel alpha instead.
	i32 w = DrawingRect.right - DrawingRect.left;
	i32 h = DrawingRect.bottom - DrawingRect.top;
	if (!DrawingBits || w <= 0 || h <= 0 || alpha == 0) return;
	i32 left = max(rect.left, 0);
	i32 top = max(rect.top, 0);
	i32 right = min(rect.right, w);
	i32 bottom = min(rect.bottom, h);
	if (right <= left || bottom <= top) return;
	i32 r = (i32)cornerRadius;
	if (r > (right - left) / 2) r = (right - left) / 2;
	if (r > (bottom - top) / 2) r = (bottom - top) / 2;

	// 4x4 subsamples per pixel: exact enough for a 1px edge, and pixels that
	// lie fully inside the shape (all but a strip one radius wide) skip the
	// sampling entirely.
	const i32 samples = 4;
	const i32 cells = samples * samples;
	float step = 1.0f / (float)samples;
	float r2 = (float)r * (float)r;
	i32 shapeWidth = right - left;
	i32 shapeHeight = bottom - top;
	u32* pixels = (u32*)DrawingBits;
	for (i32 y = top; y < bottom; y++) {
		for (i32 x = left; x < right; x++) {
			i32 rx = x - left;
			i32 ry = y - top;
			i32 inside;
			if (r <= 0) {
				inside = cells;
			}
			else if (rx >= r && rx < shapeWidth - r) {
				inside = cells; // Clear of both left and right arcs
			}
			else if (ry >= r && ry < shapeHeight - r) {
				inside = cells; // Clear of both top and bottom arcs
			}
			else {
				inside = 0;
				for (i32 sy = 0; sy < samples; sy++) {
					for (i32 sx = 0; sx < samples; sx++) {
						float px = (float)rx + ((float)sx + 0.5f) * step;
						float py = (float)ry + ((float)sy + 0.5f) * step;
						float cx = px, cy = py;
						if (px < (float)r) cx = (float)r;
						else if (px > (float)(shapeWidth - r)) cx = (float)(shapeWidth - r);
						if (py < (float)r) cy = (float)r;
						else if (py > (float)(shapeHeight - r)) cy = (float)(shapeHeight - r);
						float dx = px - cx, dy = py - cy;
						if (dx * dx + dy * dy <= r2) inside++;
					}
				}
			}
			if (!inside) continue;
			u32 coverage = (u32)((u64)alpha * (u64)inside / (u64)cells);
			pixels[(size_t)y * (size_t)w + x] = coverage << 24; // Premultiplied black
		}
	}
	GdiFlush();
}

static void FillRoundedHighlight(RECT rect, u32 cornerRadius, u32 color, u32 alpha)
{
	// Source-over fill of a rounded rect in the 32-bit backbuffer. GDI fills
	// leave alpha at zero, which would punch a transparent hole in a layered
	// window — so the highlight is composited on the CPU instead, and the
	// corner radius matches the rest of the switcher's radius scale.
	i32 w = DrawingRect.right - DrawingRect.left;
	if (!DrawingBits || w <= 0 || alpha == 0) return;
	i32 left = max(rect.left, 0);
	i32 top = max(rect.top, 0);
	i32 right = min(rect.right, w);
	i32 bottom = min(rect.bottom, DrawingRect.bottom - DrawingRect.top);
	i32 r = (i32)cornerRadius;
	if (r < 0) r = 0;
	u32 sr = ((color >> 16) & 0xFF) * alpha / 255;
	u32 sg = ((color >> 8) & 0xFF) * alpha / 255;
	u32 sb = (color & 0xFF) * alpha / 255;
	u32 inv = 255 - alpha;
	u32* pixels = (u32*)DrawingBits;
	for (i32 y = top; y < bottom; y++) {
		for (i32 x = left; x < right; x++) {
			if (r > 0) {
				i32 dx = 0, dy = 0;
				if (x < left + r) dx = left + r - x;
				else if (x >= right - r) dx = x - (right - r - 1);
				if (y < top + r) dy = top + r - y;
				else if (y >= bottom - r) dy = y - (bottom - r - 1);
				if (dx * dx + dy * dy > r * r) continue;
			}
			u32* p = pixels + (size_t)y * (size_t)w + x;
			u32 d = *p;
			u32 b = sb + (d & 0xFF) * inv / 255;
			u32 g = sg + ((d >> 8) & 0xFF) * inv / 255;
			u32 rr = sr + ((d >> 16) & 0xFF) * inv / 255;
			u32 a = alpha + (d >> 24) * inv / 255;
			*p = (a << 24) | (rr << 16) | (g << 8) | b;
		}
	}
	GdiFlush();
}

typedef struct {
	u8* coverage;   // mw*mh grayscale glyph coverage (caller frees)
	i32 mw, mh;     // Mask size
	i32 inkL, inkR; // First/last column with ink (inkR exclusive); inkR<=inkL if empty
} label_mask;

static bool RasterizeLabel(label_mask* out, u16* text, int length, HFONT font)
{
	// Rasterises the label white-on-black into a scratch surface and measures
	// the *real* ink extent. GetTextExtentPoint32W / DrawText(DT_CENTER) use
	// advance widths (bearings, hinting), so centring by them leaves visibly
	// uneven padding. Centring the ink itself is exact.
	memset(out, 0, sizeof * out);
	HFONT oldMeasure = (HFONT)SelectObject(DrawingContext, font);
	TEXTMETRICW tm = { 0 };
	SIZE extent = { 0 };
	GetTextMetricsW(DrawingContext, &tm);
	GetTextExtentPoint32W(DrawingContext, text, length, &extent);
	SelectObject(DrawingContext, oldMeasure);

	const i32 margin = 16;
	i32 mw = extent.cx + margin * 2;
	i32 mh = tm.tmHeight;
	if (mw <= 0 || mh <= 0) return false;

	BITMAPINFO bmi = { 0 };
	bmi.bmiHeader.biSize = sizeof(bmi.bmiHeader);
	bmi.bmiHeader.biWidth = mw;
	bmi.bmiHeader.biHeight = -mh; // Top-down
	bmi.bmiHeader.biPlanes = 1;
	bmi.bmiHeader.biBitCount = 32;
	bmi.bmiHeader.biCompression = BI_RGB;
	void* maskBits = null;
	handle maskBitmap = CreateDIBSection(DrawingContext, &bmi, DIB_RGB_COLORS, &maskBits, null, 0);
	if (!maskBitmap || !maskBits) {
		if (maskBitmap) DeleteObject(maskBitmap);
		return false;
	}
	handle maskContext = CreateCompatibleDC(DrawingContext);
	handle oldMask = (handle)SelectObject(maskContext, maskBitmap);

	RECT maskRect = { 0, 0, mw, mh };
	HBRUSH black = CreateSolidBrush(RGB(0, 0, 0));
	FillRect(maskContext, &maskRect, black);
	DeleteObject(black);

	HFONT oldFont = (HFONT)SelectObject(maskContext, font);
	SetBkMode(maskContext, TRANSPARENT);
	SetTextColor(maskContext, RGB(255, 255, 255));
	RECT drawRect = { margin, 0, mw - margin, mh };
	DrawTextW(maskContext, text, length, &drawRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_NOCLIP);
	SelectObject(maskContext, oldFont);
	GdiFlush();

	u8* coverage = (u8*)malloc((size_t)mw * (size_t)mh);
	if (coverage) {
		u32* mask = (u32*)maskBits;
		i32 inkL = mw, inkR = 0;
		for (i32 y = 0; y < mh; y++) {
			for (i32 x = 0; x < mw; x++) {
				u8 c = (u8)(mask[(size_t)y * (size_t)mw + x] & 0xFF);
				coverage[(size_t)y * (size_t)mw + x] = c;
				if (c > 24) {
					if (x < inkL) inkL = x;
					if (x + 1 > inkR) inkR = x + 1;
				}
			}
		}
		out->coverage = coverage;
		out->mw = mw;
		out->mh = mh;
		out->inkL = inkL;
		out->inkR = inkR;
	}

	SelectObject(maskContext, oldMask);
	DeleteObject(maskBitmap);
	DeleteDC(maskContext);
	return coverage != null;
}

static i32 MeasureLabelInkWidth(u16* text, int length, HFONT font)
{
	label_mask m;
	if (!RasterizeLabel(&m, text, length, font)) return 0;
	i32 width = m.inkR > m.inkL ? m.inkR - m.inkL : 0;
	free(m.coverage);
	return width;
}

static void DrawLabelText(u32 color, RECT textRect, u16* text, int length, HFONT font)
{
	// Crisp label text on a layered window. GDI text writes RGB only and
	// leaves alpha alone, so the glyphs are rasterised to a coverage mask
	// (RasterizeLabel) and composited source-over with premultiplied alpha.
	// The ink is centred inside 'textRect' both ways.
	i32 windowWidth = DrawingRect.right - DrawingRect.left;
	i32 windowHeight = DrawingRect.bottom - DrawingRect.top;
	if (!DrawingBits || !text) return;

	label_mask m;
	if (!RasterizeLabel(&m, text, length, font)) return;
	i32 inkW = m.inkR - m.inkL;
	if (inkW <= 0) { free(m.coverage); return; }

	i32 boxW = textRect.right - textRect.left;
	i32 boxH = textRect.bottom - textRect.top;
	i32 dstX0 = textRect.left + (boxW - inkW) / 2 - m.inkL; // Mask x -> window x
	i32 dstY0 = textRect.top + (boxH - m.mh) / 2;

	u32 sr = (color >> 16) & 0xFF;
	u32 sg = (color >> 8) & 0xFF;
	u32 sb = color & 0xFF;
	u32* pixels = (u32*)DrawingBits;
	for (i32 y = 0; y < m.mh; y++) {
		i32 wy = dstY0 + y;
		if (wy < 0 || wy >= windowHeight) continue;
		for (i32 x = m.inkL; x < m.inkR; x++) {
			i32 wx = dstX0 + x;
			if (wx < 0 || wx >= windowWidth) continue;
			u32 coverage = m.coverage[(size_t)y * (size_t)m.mw + x];
			if (!coverage) continue;
			u32 inv = 255 - coverage;
			u32* p = pixels + (size_t)wy * (size_t)windowWidth + wx;
			u32 d = *p;
			u32 a = coverage + (d >> 24) * inv / 255;
			u32 r = sr * coverage / 255 + ((d >> 16) & 0xFF) * inv / 255;
			u32 g = sg * coverage / 255 + ((d >> 8) & 0xFF) * inv / 255;
			u32 b = sb * coverage / 255 + (d & 0xFF) * inv / 255;
			*p = (a << 24) | (r << 16) | (g << 8) | b;
		}
	}
	GdiFlush();
	free(m.coverage);
}

static void RedrawSwitcher(void)
{
	// TODO Use 'Config.style'
#define PANEL_BG       RGB(0, 0, 0)
#define SELECTED_BG    RGB(150, 150, 150)
#define LABEL_BG       RGB(0, 0, 0)
#define LABEL_TEXT     RGB(255, 255, 255)

	u32 ICON_WIDTH = Config.iconWidth;
	u32 ICON_PAD = Config.iconHorzPadding;
	u32 HORZ_PAD = Config.switcherHorzMargin;
	u32 VERT_PAD = Config.switcherVertMargin;
	u32 DOCK_HEIGHT = Config.switcherHeight;

	u32 iconInset = max(4, (u32)(ICON_WIDTH * 0.06f));
	u32 selectedInset = max(6, (u32)(ICON_WIDTH * 0.08f));
	// Concentric with the icon: the outer highlight radius equals the drawn
	// icon's Flock-style radius plus the gap between icon and highlight.
	u32 iconSize = ICON_WIDTH - iconInset;
	u32 selectedRadius = (u32)(iconSize * RADIUS_RATIO + 0.5f) + selectedInset + iconInset / 2;

	RECT rect = { 0 };
	GetClientRect(Switcher, &rect);

	RedrawWindow(Switcher, null, null, RDW_INVALIDATE | RDW_ERASE);

	// Background: translucent tint over live DWM blur, or painted software
	// glass when transparency effects are off. In layered mode the pixel alpha
	// carries the shapes (anti-aliased), otherwise the window region clips them.
	DbgLog(L"bg glass=%d apps=%d", (int)UseLayeredGlass, (int)AppsCount);
	if (UseLayeredGlass) {
		ClearDrawingBuffer();
		RECT dockShape = { 0, 0, (i32)rect.right, (i32)DOCK_HEIGHT };
		FillRoundedSilhouette(dockShape, GetDockRadius(), 200);
	}
	else {
		PaintBackdropGlass();
	}

	SelectObject(DrawingContext, GetStockObject(NULL_PEN));

	// Center the icon row: with an exact-fit width this is a no-op, but it
	// guarantees equal side margins whenever width and row disagree.
	i32 rowWidth = (i32)AppsCount * ((i32)ICON_WIDTH + (i32)ICON_PAD * 2);
	i32 rowOffset = ((i32)rect.right - (i32)HORZ_PAD * 2 - rowWidth) / 2;
	if (rowOffset < 0) rowOffset = 0;
	for (int i = 0; i < AppsCount; i++) {
		struct app* app = &Apps[i];

		i32   left = GetAppIconLeft(i, ICON_WIDTH, ICON_PAD, HORZ_PAD) + rowOffset;
		i32    top = VERT_PAD;
		i32  width = ICON_WIDTH;
		i32 height = ICON_WIDTH;
		i32  right = left + width;
		i32 bottom = top + height;

		if (app == SelectedApp) {
			RECT selectedRect = {
				left - (i32)selectedInset,
				top - (i32)selectedInset,
				right + (i32)selectedInset,
				bottom + (i32)selectedInset
			};
			FillRoundedHighlight(selectedRect, selectedRadius, SELECTED_BG, 90);
		}

		i32 drawLeft = left + (i32)iconInset / 2;
		i32 drawTop = top + (i32)iconInset / 2;
		i32 drawSize = width - (i32)iconInset;
		// Build the scaled bitmap once per icon/size. The target size depends
		// on the monitor and app count, so it cannot be known in AddToSwitcher.
		if (app->icon && (app->iconBmpSize != (u32)drawSize || !app->iconBmp)) {
			if (app->iconBmp) DeleteObject(app->iconBmp);
			app->iconBmp = ScaleIconBitmap(app->icon, drawSize);
			app->iconBmpSize = app->iconBmp ? (u32)drawSize : 0;
		}
		if (app->iconBmp) {
			// High-quality pre-scaled bitmap with per-pixel alpha.
			handle srcContext = CreateCompatibleDC(DrawingContext);
			handle oldSrc = (handle)SelectObject(srcContext, app->iconBmp);
			BLENDFUNCTION bf = { AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
			AlphaBlend(DrawingContext, drawLeft, drawTop, drawSize, drawSize, srcContext, 0, 0, (int)app->iconBmpSize, (int)app->iconBmpSize, bf);
			SelectObject(srcContext, oldSrc);
			DeleteDC(srcContext);
		}
		else {
			DrawIconEx(
				DrawingContext,
				drawLeft,
				drawTop,
				app->icon,
				drawSize,
				drawSize,
				0, NULL, DI_NORMAL
			);
		}
	}

	RECT labelRect = { 0 };
	bool hasLabel = false;

	if (SelectedApp && SelectedApp->name.ok && SelectedApp->name.length > 0) {
		HFONT labelFont = CreateFontW(
			-LABEL_FONT_SIZE, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
			DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
			ANTIALIASED_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI"
		);
		HFONT oldFont = (HFONT)SelectObject(DrawingContext, labelFont);
		SetBkMode(DrawingContext, TRANSPARENT);
		SetTextColor(DrawingContext, LABEL_TEXT);

		TEXTMETRICW textMetrics = { 0 };
		GetTextMetricsW(DrawingContext, &textMetrics);

		i32 labelWidth = MeasureLabelInkWidth(SelectedApp->name.text, (int)SelectedApp->name.length, labelFont) + LABEL_PAD_H * 2;
		i32 labelHeight = textMetrics.tmHeight + LABEL_PAD_V * 2;
		i32 labelLeft = rect.right / 2 - labelWidth / 2;
		i32 labelTop = (i32)DOCK_HEIGHT + LABEL_GAP;

		labelRect = (RECT){ labelLeft, labelTop, labelLeft + labelWidth, labelTop + labelHeight };
		hasLabel = true;

		// The pill is part of the window silhouette. In layered mode it is
		// painted into the alpha channel with an anti-aliased outline; the
		// software-glass fallback is clipped by the window region instead.
		if (UseLayeredGlass) {
			FillRoundedSilhouette(labelRect, (u32)min(labelWidth, labelHeight) / 2, 200);
		}

		// No pill fill: the label text floats directly on the glass. The text
		// itself is composited with per-pixel alpha so it stays sharp and fully
		// opaque instead of inheriting the glass tint.
		RECT textRect = {
			labelRect.left + LABEL_PAD_H,
			labelRect.top + LABEL_PAD_V,
			labelRect.right - LABEL_PAD_H,
			labelRect.bottom - LABEL_PAD_V
		};
		DrawLabelText(LABEL_TEXT, textRect, SelectedApp->name.text, (int)SelectedApp->name.length, labelFont);

		SelectObject(DrawingContext, oldFont);
		DeleteObject(labelFont);
	}

	// The region shapes the software-glass fallback and keeps hit-testing tight.
	// With layered glass the pixels already carry the anti-aliased outline, so
	// the region is padded just enough not to shave those edge pixels off.
	UpdateSwitcherWindowRegion((u32)rect.right, DOCK_HEIGHT, &labelRect, hasLabel);

	if (UseLayeredGlass) {
		// Live blur behind the dock + label shapes (DWM copies the region).
		HRGN blurRegion = MakeDockLabelRegion((u32)rect.right, DOCK_HEIGHT, &labelRect, hasLabel);
		if (blurRegion) {
			DWM_BLURBEHIND bb = { 0 };
			bb.dwFlags = DWM_BB_ENABLE | DWM_BB_BLURREGION;
			bb.fEnable = TRUE;
			bb.hRgnBlur = blurRegion;
			DwmEnableBlurBehindWindow(Switcher, &bb);
			DeleteObject(blurRegion);
		}
	}
}

static void ShowSwitcher(void)
{
	//ReceiveLastInputEvent();
	PresentSwitcher(); // No stale first frame: present before showing
	ShowWindow(Switcher, SW_SHOWNA);
	if (SetForegroundWindow(Switcher)) {
		LockSetForegroundWindow(LSFW_LOCK);
	}
}

static void CancelSwitcher(bool restore)
{
	Print(L"cancel/close\n");
	HideWindow(Switcher);
	LockSetForegroundWindow(LSFW_UNLOCK);
	FreeBackdrop();
	if (restore) {
		// TODO Check that the restore window is not the second most recently
		//      activated window (after my own switcher window), so that I
		//      don't needlessly switch to the window that will naturally
		//      become activated once my switcher window hides
		ShowWindowX(RestorableWindow);
	}
	// Reset selection
	SelectedApp = null;
	SelectedWindow = null;
	RestorableWindow = null;
}

//static void CloseWindows(handle hwnd) // Alternative to TerminateWindowProcess
//{
//	if (AppsCount <= 0) {
//		return;
//	}
//	struct app *app = null;
//	handle *window = null;
//	for (int i = 0; i < AppsCount; i++) {
//		app = &Apps[i];
//		for (int j = 0; j < app->windowsCount; j++) {
//			if (app->windows[j] == hwnd) {
//				Print(L"quit app %s\n", app->name);
//				for (int k = 0; k < app->windowsCount; k++) {
//					CloseWindowX(app->windows[k]);
//				}
//				return;
//			}
//		}
//	}
//}

static bool SetKey(u32 key, bool down)
{
#ifndef CHAR_BIT
#define CHAR_BIT 8
#endif

	bool wasdown = Keyboard[key / CHAR_BIT] & (1 << (key % CHAR_BIT)); // getbit
	if (down) {
		Keyboard[key / CHAR_BIT] |= (1 << (key % CHAR_BIT)); // setbit1
	}
	else {
		Keyboard[key / CHAR_BIT] &= ~(1 << (key % CHAR_BIT)); // setbit0
	}
	return wasdown && down; // Return true if this was a key repeat
}

static LRESULT CALLBACK KeyboardHookProcedure(int code, WPARAM wparam, LPARAM lparam)
{
	if (code < 0) { // "If code is less than zero, the hook procedure must pass the message to..." blah blah blah read the docs
		return CallNextHookEx(null, code, wparam, lparam);
	}

	KBDLLHOOKSTRUCT* kbd = (KBDLLHOOKSTRUCT*)lparam;
	u32 keyCode = kbd->vkCode;
	bool keyDown = !(bool)(kbd->flags & LLKHF_UP);

#ifdef _DEBUG
	if ((kbd->flags & LLKHF_INJECTED) == LLKHF_INJECTED) {
		u16 keyName[32] = { 0 };
		int length = GetKeyNameTextW(kbd->scanCode << 16, keyName, countof(keyName));
		Log(L"skip INJECTED INPUT %s %s\n", keyCode ? keyName : L"", keyCode ? keyDown ? L"down" : L"up" : L"");
		goto passMessage;
	}
#endif

	if (!SelectedWindow) {

		bool keyRepeat = SetKey(keyCode, keyDown); // Manually track key repeat
		bool shiftHeld = IsKeyDown(VK_LSHIFT) || IsKeyDown(VK_RSHIFT) || IsKeyDown(VK_SHIFT);

		// ========================================
		// Activation
		// ========================================

		bool key1Down = keyCode == Config.hotkeyForApps.key && keyDown;
		bool key2Down = keyCode == Config.hotkeyForWindows.key && keyDown;
		bool mod1Held = IsKeyDown(Config.hotkeyForApps.mod);
		bool mod2Held = IsKeyDown(Config.hotkeyForWindows.mod);

		// First Alt-Tab
		if (key1Down && mod1Held && Config.switchApps) {
			UpdateApps();
			if (AppsCount <= 0) {
				Print(L"no apps\n");
				goto passMessage;
			}
			ReceiveLastInputEvent();
			SelectFirstWindow(); // Initialize selection
			// Si la ventana seleccionada está minimizada o es el escritorio, saltar a la siguiente app
			handle hwnd = SelectedWindow;
			if ((GetWindowLongPtrW(hwnd, GWL_STYLE) & WS_MINIMIZE) || hwnd == GetShellWindow()) {
				SelectNextWindow(true, shiftHeld, !Config.wrapbump || !keyRepeat);
			}
			SelectNextWindow(true, shiftHeld, !Config.wrapbump || !keyRepeat); // Siempre seleccionar la siguiente app
			NavLog(L"activate count=%d sel=%d", (int)AppsCount, SelectedApp ? (int)(SelectedApp - Apps) : -1);
			if (Config.showSwitcherForApps) {
				ResizeSwitcher(); // NOTE Must call ResizeSwitcher after UpdateApps, before RedrawSwitcher & before ShowSwitcher
				RedrawSwitcher();
				ShowSwitcher();
			}
			if (Config.fastSwitchingForApps) {
				ShowWindowX(SelectedWindow);
			}
			// Since I "own" this hotkey system-wide, I consume this message unconditionally
			// This will consume the key1Down event. Windows will not know that key1 was pressed
			goto consumeMessage;
		}
		// First Alt-Tilde/Backquote
		if (key2Down && mod2Held && Config.switchWindows) {
			UpdateApps();
			if (AppsCount <= 0) {
				Print(L"no apps\n");
				goto passMessage;
			}
			ReceiveLastInputEvent();
			SelectFirstWindow(); // Initialize selection
			SelectNextWindow(false, shiftHeld, !Config.wrapbump || !keyRepeat);
			if (Config.showSwitcherForWindows) {
				ResizeSwitcher(); // NOTE Must call ResizeSwitcher after UpdateApps, before RedrawSwitcher & before ShowSwitcher
				RedrawSwitcher();
				ShowSwitcher();
			}
			if (Config.fastSwitchingForWindows) {
				ShowWindowX(SelectedWindow);
			}
			// Since I "own" this hotkey system-wide, I consume this message unconditionally
			// This will consume the key2Down event. Windows will not know that key2 was pressed
			goto consumeMessage;
		}

	}
	else { // if (SelectedWindow) {

		// ========================================
		// Deactivation
		// ========================================

		bool mod1Up = keyCode == Config.hotkeyForApps.mod && !keyDown;
		bool mod2Up = keyCode == Config.hotkeyForWindows.mod && !keyDown;

		if (mod1Up || mod2Up) {
			// Alt keyup - switch to selected window
			// Always pass/never consume mod key up, because:
			// 1) cmdtab never hooks mod keydowns
			// 2) cmdtab hooks mod keyups, but always passes it through on pain of getting a stuck Alt key because of point 1
			ReceiveLastInputEvent();
			ShowWindowX(SelectedWindow);
			CancelSwitcher(false);
			goto passMessage; // See note above on "Alt keyup" on why I don't consume this message
		}
		else {

			bool keyRepeat = SetKey(keyCode, keyDown); // Manually track key repeat
			bool shiftHeld = IsKeyDown(VK_LSHIFT) || IsKeyDown(VK_RSHIFT) || IsKeyDown(VK_SHIFT);

			// ========================================
			// Navigation
			// ========================================

			bool key1Down = keyCode == Config.hotkeyForApps.key && keyDown;
			bool key2Down = keyCode == Config.hotkeyForWindows.key && keyDown;
			bool prevDown = (keyCode == VK_UP || keyCode == VK_LEFT) && keyDown;
			bool nextDown = (keyCode == VK_DOWN || keyCode == VK_RIGHT) && keyDown;

			// Subsequent Alt-Tab - next app (hold Shift for previous)
			// Also arrow keys, left and right
			if (key1Down || (nextDown || prevDown)) {
				SelectNextWindow(true, shiftHeld || prevDown, !Config.wrapbump || !keyRepeat);
				if (Config.showSwitcherForApps) {
					ResizeSwitcher(); // NOTE Must call ResizeSwitcher after UpdateApps, before RedrawSwitcher & before ShowSwitcher
					RedrawSwitcher();
					ShowSwitcher();
				}
				if (Config.fastSwitchingForApps) {
					PreviewWindow(SelectedWindow);
				}
				// Since I "own" this hotkey system-wide, I consume this message unconditionally
				// This will consume the key1Down event. Windows will not know that key1 was pressed
				goto consumeMessage;
			}

			// Subsequent Alt-Tilde/Backquote - next window (hold Shift for previous)
			// TODO Also arrow keys, up and down
			if (key2Down) {
				SelectNextWindow(false, shiftHeld, !Config.wrapbump || !keyRepeat);
				if (Config.showSwitcherForWindows) {
					ResizeSwitcher(); // NOTE Must call ResizeSwitcher after UpdateApps, before RedrawSwitcher & before ShowSwitcher
					RedrawSwitcher();
					ShowSwitcher();
				}
				if (Config.fastSwitchingForWindows) {
					PreviewWindow(SelectedWindow);
				}
				// Since I "own" this hotkey system-wide, I consume this message unconditionally
				// This will consume the key2Down event. Windows will not know that key2 was pressed
				goto consumeMessage;
			}

			// ========================================
			// Deactivation
			// ========================================

			bool escDown = keyCode == VK_ESCAPE && keyDown;
			bool enterDown = keyCode == VK_RETURN && keyDown;

			// Alt-Enter - switch to selected window
			if (enterDown) {
				ShowWindowX(SelectedWindow);
				CancelSwitcher(false);
				// Since our swicher is active, I "own" this hotkey, so I consume this message
				// This will consume the enterDown event. Windows will not know that Enter was pressed
				goto consumeMessage;
			}
			// Alt-Esc - cancel switching and restore initial window
			if (escDown) { // BUG There's a bug here if mod1Held and mod2Held aren't both the same key. In that case I'll still pass through the key event, even though I should own it since it's not Alt-Esc
				CancelSwitcher(Config.restoreOnCancel);
				// Since our swicher is active, I "own" this hotkey, so I consume this message
				// This will consume the escDown event. Windows will not know that Escape was pressed
				goto consumeMessage;
			}

			// ========================================
			// Extended window management
			// ========================================

			bool keyF4Down = keyCode == VK_F4 && keyDown;
			bool keyQDown = keyCode == 'Q' && keyDown;
			bool keyWDown = keyCode == 'W' && keyDown;
			bool deleteDown = keyCode == VK_DELETE && keyDown;
			bool keyMDown = keyCode == 'M' && keyDown;
			bool keyHDown = keyCode == 'H' && keyDown;
			bool keyBDown = keyCode == 'B' && keyDown;

			// Alt-F4 - quit cmdtab
			if (keyF4Down) {
				CloseWindowX(Switcher);
				goto consumeMessage;
			}
			// Alt-Q - close all windows of selected application
			if (keyQDown) {
				//CloseWindows(SelectedWindow);
				TerminateWindowProcess(SelectedWindow);
				if (SelectedApp == &Apps[AppsCount - 1] && AppsCount > 1) {
					SelectedApp--;
				}
				UpdateApps();
				ResizeSwitcher(); // NOTE Must call ResizeSwitcher after UpdateApps, before RedrawSwitcher & before ShowSwitcher
				RedrawSwitcher();
				goto consumeMessage;
			}
			// Alt-W or Alt-Delete - close selected window
			if (keyWDown || deleteDown) {
				CloseWindowX(SelectedWindow);
				UpdateApps();
				ResizeSwitcher(); // NOTE Must call ResizeSwitcher after UpdateApps, before RedrawSwitcher & before ShowSwitcher
				RedrawSwitcher();
				goto consumeMessage;
			}
			// Alt-M - minimize selected window
			if (keyMDown) {
				MinimizeWindow(SelectedWindow);
				goto consumeMessage;
			}
			// Alt-H - hide selected window
			if (keyHDown) {
				//HideWindow(SelectedWindow); // WARNING Can't use this because we filter out hidden windows
				goto consumeMessage;
			}
			// Alt-B - display app name and window class to user, to add in blacklist
			if (keyBDown) {
				handle selectedWindow = SelectedWindow; // CancelSwitcher resets SelectedWindow
				CancelSwitcher(false);
				ReportWindowHandle(Switcher, selectedWindow);
				goto consumeMessage;
			}

			// ========================================
			// Debug
			// ========================================

			bool keyF11Down = keyCode == VK_F11 && keyDown;
			bool keyF12Down = keyCode == VK_F12 && keyDown;

			if (keyF12Down) {
				Debug(L"debug hotkey");
			}
			if (keyF11Down) {
				PrintApps();
			}

			// ========================================
			// Hook management
			// ========================================

			// Pass through modifiers so they don't get stuck
			if (keyCode == VK_CONTROL || keyCode == VK_LCONTROL || keyCode == VK_RCONTROL ||
				keyCode == VK_MENU || keyCode == VK_LMENU || keyCode == VK_RMENU ||
				keyCode == VK_SHIFT || keyCode == VK_LSHIFT || keyCode == VK_RSHIFT ||
				keyCode == VK_CAPITAL) {
				Print(L"modifier passthrough\n");
				goto passMessage;
			}
			// Other passthrough
			if (keyCode == VK_SNAPSHOT) {
				goto passMessage;
			}
			// Input sink - consume keystrokes when activated
			if (true) {
				u16 keyName[32] = { 0 };
				int length = GetKeyNameTextW(kbd->scanCode << 16, keyName, countof(keyName));
				Print(L"input sink %s %s\n", keyName, keyDown ? L"down" : L"up");
				goto consumeMessage;
			}
		}
	}

passMessage:
	//print(L"allow next hook\n");
	return CallNextHookEx(null, code, wparam, lparam);
consumeMessage:
	// By returning a non-zero value from the hook procedure, the message
	// is consumed and does not get passed to the target window
	//print(L"block key event\n");
	return 1;
}

static void OnWindowCreate(void)
{
	// Make the codepath hot to prevent kbd hook from timing out on first use
	UpdateApps();
}

static void PresentSwitcher(void)
{
	// Push the backbuffer to screen. Called from OnWindowPaint AND
	// synchronously before ShowSwitcher, so the first visible frame can
	// never be a stale one from the previous session.
	if (UseLayeredGlass) {
		POINT pos = { DrawingRect.left, DrawingRect.top };
		SIZE size = { DrawingRect.right - DrawingRect.left, DrawingRect.bottom - DrawingRect.top };
		POINT src = { 0, 0 };
		BLENDFUNCTION bf = { AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
		GdiFlush();
		UpdateLayeredWindow(Switcher, null, &pos, &size, DrawingContext, &src, 0, &bf, ULW_ALPHA);
	}
	else {
		handle context = GetDC(Switcher);
		if (context) {
			BitBlt(context, 0, 0, DrawingRect.right - DrawingRect.left, DrawingRect.bottom - DrawingRect.top, DrawingContext, 0, 0, SRCCOPY);
			ReleaseDC(Switcher, context);
		}
	}
}

static void OnWindowPaint(void)
{
	// Double buffered drawing:
	// I draw off-screen in-memory to 'DrawingContext' whenever changes occur,
	// and whenever I get the WM_PAINT message I just blit the
	// off-screen buffer to screen ("screen" means the 'hdc' returned by
	// BeginPaint passed our 'hwnd')
	PAINTSTRUCT ps = { 0 };
	BeginPaint(Switcher, &ps);
	PresentSwitcher();
	EndPaint(Switcher, &ps);
}

static void OnWindowFocusChange(bool focused)
{
	// Cancel on mouse clicking outside window
	if (focused) {
		Print(L"switcher got focus\n");
		//return 0;
		//synckeys();
	}
	else {
		// This rarely happens atm with the current implementation
		// because I don't set the switcher as foreground window when
		// showing! I just show the window and rely on being topmost.
		// But the user can click the switcher window and make it the
		// foreground window, in which case it will get this message
		// when the foreground window changes again.
		// I'm not sure if the implementation will remain like this
		// (i.e. not becoming foreground)--it's a little unorthodox.
		// But for now that's how it is.
		Print(L"switcher lost focus\n");
		//return 1; // Nu-uh!
		//cancel(false); // NOTE See comments in cancel
	}
}

static void OnWindowMouseMove(int x, int y)
{
	MouseX = x; // GetMessagePos
	MouseY = y;
	//print(L"x%i y%i\n", MouseX, MouseY);
}

static void OnWindowMouseLeave(void)
{
	MouseX = 0;
	MouseY = 0;
	//print(L"x%i y%i\n", MouseX, MouseY);
}

static void OnWindowClose(void)
{
	CancelSwitcher(false);
	if (Ask(Switcher, L"Quit cmdtab?")) {
		ShowTaskbar(); // Restore taskbar before closing
		DestroyWindow(Switcher);//return DefWindowProcW(hwnd, message, wparam, lparam); // Calls DestroyWindow
	}
}

static void OnShellWindowActivated(handle hwnd)
{
	AddToHistory(hwnd);
}

static i64 WindowProcedure(handle hwnd, u32 message, u64 wparam, i64 lparam)
{
	switch (message) {
	case WM_CREATE:
		OnWindowCreate();
		break;
	case WM_PAINT:
		OnWindowPaint();
		break;
	case WM_ACTIVATEAPP:
		OnWindowFocusChange(wparam != WA_INACTIVE);
		break;
	case WM_MOUSEMOVE:
		OnWindowMouseMove(LOWORD(lparam), HIWORD(lparam));
		TrackMouseEvent(&(TRACKMOUSEEVENT) { .cbSize = sizeof(TRACKMOUSEEVENT), .dwFlags = TME_LEAVE, .hwndTrack = hwnd });
		break;
	case WM_MOUSELEAVE:
		OnWindowMouseLeave();
		break;
	case WM_CLOSE:
		OnWindowClose();
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default: {
		return DefWindowProcW(hwnd, message, wparam, lparam);
	}
	}
	return 0;
}

static VOID CALLBACK EventHookProcedure(HWINEVENTHOOK hook, ULONG event, HWND hwnd, LONG objectid, LONG childid, ULONG threadid, ULONG timestamp)
{
	switch (event) {
	case EVENT_SYSTEM_FOREGROUND:
		Print(L"FOREGROUND WINDOW EVENT\n");
		OnShellWindowActivated(hwnd);
		break;
	case EVENT_OBJECT_UNCLOAKED:
		Print(L"UNCLOAKED WINDOW EVENT\n");
		OnShellWindowActivated(hwnd);
		break;
	}
}

static bool HasAutorunLaunchArgument(u16* args)
{
	return !wcscmp(args, L"--autorun");
}

static bool IsAutorunAlreadyConfigured(void)
{
	HKEY regkey;
	bool exists = false;
	if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_READ, &regkey) == ERROR_SUCCESS) {
		u16 buffer[MAX_PATH];
		DWORD size = sizeof(buffer);
		exists = (RegQueryValueExW(regkey, L"cmdtab", null, null, (LPBYTE)buffer, &size) == ERROR_SUCCESS);
		RegCloseKey(regkey);
	}
	return exists;
}

static void AskAutorun(void)
{
#ifndef _DEBUG // Can't be bothered to be asked about this every single debug run
	// Solo preguntar si no está configurado el autorun previamente
	if (!IsAutorunAlreadyConfigured()) {
		SetAutorun(Ask(Switcher, L"Start cmdtab automatically?\nRelaunch cmdtab.exe to change your mind."), L"cmdtab", L"--autorun");
	}
#endif
}

static bool AlreadyRunning(handle* mutex)
{
	*mutex = CreateMutexW(null, true, L"cmdtabMutex");
	return GetLastError() == ERROR_ALREADY_EXISTS;
}

static void QuitSecondInstance(void)
{
	MessageBoxW(null, L"cmdtab is already running.", L"cmdtab", MB_OK | MB_ICONINFORMATION | MB_TASKMODAL);
	ExitProcess(0);
}

static int RunCmdTab(handle instance, u16* args)
{
	handle mutex;
	//handle mainWindow; // Switcher
	handle keyboardHook, eventHook1, eventHook2;

	if (!HasAutorunLaunchArgument(args)) {
		AskAutorun();
	}
	if (AlreadyRunning(&mutex)) {
		QuitSecondInstance();
	}

	//
	i32 _ = CoInitialize(null);

	// Enable DPI awareness for better rendering on high-DPI displays
	SetProcessDPIAware();

	// Initialize runtime-dependent settings, for example dependent on user's current kbd layout
	InitConfig();
	// Layered live glass needs Windows transparency effects; otherwise the
	// window stays opaque and RedrawSwitcher paints the software blur.
	// (Decided here because the window style depends on it below.)
	{
		ULONG glass = 0;
		ULONG glassSize = sizeof glass;
		if (!RegGetValueW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize", L"EnableTransparency", RRF_RT_DWORD, null, &glass, &glassSize) && glass) {
			UseLayeredGlass = true;
		}
	}

	// Hide taskbar if enabled
	HideTaskbar();

	// Create switcher window
	WNDCLASSEXW wcex = { 0 };
	wcex.cbSize = sizeof wcex;
	wcex.lpfnWndProc = (WNDPROC)WindowProcedure;
	wcex.hInstance = instance;
	wcex.hCursor = LoadCursor(instance, IDC_ARROW);
	wcex.lpszClassName = L"cmdtabSwitcher";
	// Toolwindow + topmost; no WS_EX_LAYERED so the surface itself is fully opaque,
	// and only the DWM blur effect provides the \"glass\" feel.
	DWORD exStyle = WS_EX_TOOLWINDOW | WS_EX_TOPMOST;
	if (UseLayeredGlass) {
		exStyle |= WS_EX_LAYERED; // Per-pixel alpha for live DWM glass
	}
	Switcher = CreateWindowExW(exStyle,
		MAKEINTATOM(RegisterClassExW(&wcex)),
		null, 0, 0, 0, 0, 0, null, null, instance, null);
	// Clear all window styles for very plain window
	SetWindowLongW(Switcher, GWL_STYLE, 0);
	// Disable DWM window corners since we're drawing our own
	DWM_WINDOW_CORNER_PREFERENCE corners = DWMWCP_DONOTROUND;
	DwmSetWindowAttribute(Switcher, DWMWA_WINDOW_CORNER_PREFERENCE, &corners, sizeof corners);

	// With layered live glass the blur is applied per-shape in RedrawSwitcher;
	// without it the window stays fully opaque and DWM must not blend it.
	if (!UseLayeredGlass) {
		DWM_BLURBEHIND bb = { 0 };
		bb.dwFlags = DWM_BB_ENABLE;
		bb.fEnable = FALSE;
		bb.hRgnBlur = NULL;
		DwmEnableBlurBehindWindow(Switcher, &bb);
	}

	// Install keyboard hook and event hooks for foreground window changes. Raymond Chen: https://devblogs.microsoft.com/oldnewthing/20130930-00/?p=3083
	keyboardHook = SetWindowsHookExW(WH_KEYBOARD_LL, (HOOKPROC)KeyboardHookProcedure, null, 0);
	eventHook1 = SetWinEventHook(EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND, null, EventHookProcedure, 0, 0, WINEVENT_OUTOFCONTEXT);
	eventHook2 = SetWinEventHook(EVENT_OBJECT_UNCLOAKED, EVENT_OBJECT_UNCLOAKED, null, EventHookProcedure, 0, 0, WINEVENT_OUTOFCONTEXT);

	// Run message loop
	for (MSG msg; GetMessageW(&msg, Switcher, 0, 0) > 0;) DispatchMessageW(&msg); // Not handling -1 errors. Whatever

	// Uninstall keyboard & event hooks
	UnhookWindowsHookEx(keyboardHook);
	UnhookWinEvent(eventHook1);
	UnhookWinEvent(eventHook2);

	// Restore taskbar before exiting
	ShowTaskbar();

	CoUninitialize();

	if (mutex) {
		ReleaseMutex(mutex);
		//CloseHandle(hMutex);
	}
	Print(L"cmdtab quit\n");
	bool hasLeaks = _CrtDumpMemoryLeaks();
	return hasLeaks;
}

int WINAPI wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nShowCmd)
{
	//#ifdef _DEBUG
	//FILE *conout = null;
	//AllocConsole();
	//freopen_s(&conout, "CONOUT$", "w", stdout);
	//#endif
	return RunCmdTab(hInstance, lpCmdLine);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
	return RunCmdTab(hInstance, GetCommandLineW());
}