#include "bd_common.h"

typedef struct {
    const wchar_t* title; const wchar_t* text;
    int type, result, countdown;
    int width, textH;
    HWND hwnd, hProgress;
    HWND hBtn1, hBtn2, hBtn3;
} UI_DATA;

static CRITICAL_SECTION g_ui_cs;
static BOOL g_bIsPopupOpen = FALSE;
static DWORD g_uiStartTick = 0;

/* 启动后的前 30 秒不弹任何防护弹窗，避免开机时被系统/驱动动作误报打扰 */
BOOL bd_popup_grace_active(void)
{
    return g_uiStartTick != 0 && (GetTickCount() - g_uiStartTick) < BD_STARTUP_GRACE_MS;
}

LRESULT CALLBACK PopupWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    UI_DATA* data = (UI_DATA*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    switch (msg) {
        case WM_CREATE:
            data = (UI_DATA*)((CREATESTRUCTW*)lParam)->lpCreateParams;
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)data);
            data->hwnd = hwnd;

            int textW = data->width - 40;
            int btnY  = 42 + data->textH + 28;

            CreateWindowW(L"STATIC", data->title, WS_CHILD|WS_VISIBLE|SS_LEFT, 20, 12, textW, 25, hwnd, NULL, NULL, NULL);
            CreateWindowW(L"STATIC", data->text, WS_CHILD|WS_VISIBLE|SS_LEFT, 20, 42, textW, data->textH, hwnd, NULL, NULL, NULL);

            // 动态生成按钮
            if (data->type == 1) { // 文件/注册表 告警 (同意、回滚、急停)
                data->hBtn1 = CreateWindowW(L"BUTTON", L"同意", WS_CHILD|WS_VISIBLE, 20, btnY, 100, 30, hwnd, (HMENU)IDYES, NULL, NULL);
                data->hBtn2 = CreateWindowW(L"BUTTON", L"回滚 (默认)", WS_CHILD|WS_VISIBLE, 140, btnY, 100, 30, hwnd, (HMENU)IDNO, NULL, NULL);
                data->hBtn3 = CreateWindowW(L"BUTTON", L"急停", WS_CHILD|WS_VISIBLE, 260, btnY, 100, 30, hwnd, (HMENU)IDCANCEL, NULL, NULL);
            } else if (data->type == 2) { // MBR 告警 (同意、覆写并急停)
                data->hBtn1 = CreateWindowW(L"BUTTON", L"同意", WS_CHILD|WS_VISIBLE, 50, btnY, 120, 30, hwnd, (HMENU)IDYES, NULL, NULL);
                data->hBtn2 = CreateWindowW(L"BUTTON", L"覆写并急停", WS_CHILD|WS_VISIBLE, 210, btnY, 120, 30, hwnd, (HMENU)IDNO, NULL, NULL);
            } else if (data->type == 3) { // 网络告警 (同意联网、禁止联网、禁用程序)
                data->hBtn1 = CreateWindowW(L"BUTTON", L"同意联网", WS_CHILD|WS_VISIBLE, 20, btnY, 100, 30, hwnd, (HMENU)IDYES, NULL, NULL);
                data->hBtn2 = CreateWindowW(L"BUTTON", L"禁止联网", WS_CHILD|WS_VISIBLE, 140, btnY, 100, 30, hwnd, (HMENU)IDNO, NULL, NULL);
                data->hBtn3 = CreateWindowW(L"BUTTON", L"禁用程序", WS_CHILD|WS_VISIBLE, 260, btnY, 100, 30, hwnd, (HMENU)IDIGNORE, NULL, NULL);
            } else if (data->type == 5) { // 云端病毒库命中 (拦截运行、同意运行)
                data->hBtn1 = CreateWindowW(L"BUTTON", L"拦截运行 (默认)", WS_CHILD|WS_VISIBLE, 40, btnY, 140, 30, hwnd, (HMENU)IDYES, NULL, NULL);
                data->hBtn2 = CreateWindowW(L"BUTTON", L"同意运行", WS_CHILD|WS_VISIBLE, 210, btnY, 120, 30, hwnd, (HMENU)IDNO, NULL, NULL);
            } else if (data->type == 6) { // 单按钮提示
                data->hBtn1 = CreateWindowW(L"BUTTON", L"确定", WS_CHILD|WS_VISIBLE, 150, btnY, 100, 30, hwnd, (HMENU)IDOK, NULL, NULL);
            }
            // type 4：无按钮的静默提示（例如进程注入拦截）

            data->hProgress = CreateWindowW(L"STATIC", L"", WS_CHILD|WS_VISIBLE|SS_LEFT, 20, 42 + data->textH + 4, textW, 20, hwnd, NULL, NULL, NULL);

            if (data->countdown > 0) SetTimer(hwnd, 1, 1000, NULL);
            else if (data->type == 6) SetWindowTextW(data->hProgress, L"");
            else if (data->type == 4) SetWindowTextW(data->hProgress, L"");
            else SetWindowTextW(data->hProgress, L"【无超时，必须手动选择】");

            return 0;

        case WM_TIMER:
            if (data->countdown > 0) {
                data->countdown--;
                if (data->countdown > 0 && (data->type == 1 || data->type == 2 || data->type == 3 || data->type == 5)) {
                    wchar_t t[64]; swprintf(t, 64, L"剩余操作时间: %d 秒 (超时执行默认)", data->countdown);
                    SetWindowTextW(data->hProgress, t);
                }
            }
            if (data->countdown <= 0) {
                if (data->type == 4 || data->type == 6) data->result = IDOK;
                else if (data->type == 5) data->result = IDYES; /* 云端病毒库：超时默认拦截 */
                else if (data->type == 2) data->result = IDOK;  /* MBR：超时只恢复，不蓝屏 */
                else data->result = IDNO;
                DestroyWindow(hwnd);
            }
            return 0;

        case WM_CTLCOLORSTATIC:
            SetBkMode((HDC)wParam, TRANSPARENT);
            SetTextColor((HDC)wParam, RGB(0, 0, 0));
            return (LRESULT)GetStockObject(WHITE_BRUSH);

        case WM_COMMAND:
            data->result = LOWORD(wParam);
            DestroyWindow(hwnd);
            return 0;

        case WM_DESTROY:
            KillTimer(hwnd, 1);
            g_bIsPopupOpen = FALSE;
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

void bd_ui_init() {
    InitializeCriticalSection(&g_ui_cs);
    g_uiStartTick = GetTickCount();
}

int bd_show_popup(const wchar_t* title, const wchar_t* text, int type, int timeoutSec) {
    /* 启动静默期：不弹窗。返回专用值，让调用方既不放行也不拦截，只在后台记录。 */
    if (bd_popup_grace_active()) return BD_POPUP_SUPPRESSED;

    EnterCriticalSection(&g_ui_cs);
    /* 病毒拦截、MBR、文件/注册表告警以及到期提示都必须让用户看到，
       遇到已打开的弹窗时等待其关闭，避免把“弹窗被占用”误当成用户的默认选择。
       最多等 60 秒，超过后按各自的安全默认值处理，防止扫描线程被永久卡住。 */
    DWORD waitStart = GetTickCount();
    while (g_bIsPopupOpen && (type == 1 || type == 2 || type == 5 || type == 6) &&
           GetTickCount() - waitStart < 60000) {
        LeaveCriticalSection(&g_ui_cs);
        Sleep(300);
        EnterCriticalSection(&g_ui_cs);
    }
    if (g_bIsPopupOpen) {
        LeaveCriticalSection(&g_ui_cs);
        /* 仍被占用：按“安全优先”的默认结果返回——
           疑似/确认病毒、MBR 告警一律不放行，避免静默放行恶意程序。 */
        if (type == 4 || type == 6 || type == 2) return IDOK;
        if (type == 5) return IDYES;   /* 云端病毒库：默认拦截运行 */
        return IDNO;
    }
    g_bIsPopupOpen = TRUE;

    int width = 420;
    /* 按正文实际高度计算窗口大小，避免长路径/多行统计被截断 */
    int textW = width - 40;
    int textH = 74;
    HDC hdc = GetDC(NULL);
    if (hdc) {
        RECT rc = { 0, 0, textW, 2000 };
        HFONT old = (HFONT)SelectObject(hdc, GetStockObject(DEFAULT_GUI_FONT));
        DrawTextW(hdc, text, -1, &rc, DT_CALCRECT | DT_WORDBREAK);
        SelectObject(hdc, old);
        ReleaseDC(NULL, hdc);
        int h = rc.bottom - rc.top + 6;
        if (h < 74) h = 74;
        if (h > 320) h = 320;
        textH = h;
    }

    int height = textH + 112;           /* 标题 + 正文 + 倒计时 + 按钮 */
    if (type == 4) height = textH + 66; /* 无按钮 */

    UI_DATA data = { title, text, type, IDNO, timeoutSec, width, textH,
                     NULL, NULL, NULL, NULL, NULL };
    WNDCLASSEXW wc = {0}; wc.cbSize = sizeof(wc); wc.lpfnWndProc = PopupWndProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.lpszClassName = L"BDPopupClass";
    RegisterClassExW(&wc);

    int screenW = GetSystemMetrics(SM_CXSCREEN), screenH = GetSystemMetrics(SM_CYSCREEN);
    int posY = screenH - height - 60;
    if (posY < 0) posY = 0;
    HWND hwnd = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, L"BDPopupClass", L"BDProtect",
        WS_POPUP | WS_BORDER, screenW - width - 20, posY,
        width, height, NULL, NULL, wc.hInstance, &data);

    ShowWindow(hwnd, SW_SHOW);
    SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
    UpdateWindow(hwnd);

    MSG msg;
    while (IsWindow(hwnd)) {
        if (GetMessageW(&msg, NULL, 0, 0) <= 0) break;
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    LeaveCriticalSection(&g_ui_cs);
    return data.result;
}
