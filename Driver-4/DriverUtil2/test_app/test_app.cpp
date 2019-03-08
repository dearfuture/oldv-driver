// test_app.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <windows.h>

int main()
{
	auto h_event = OpenEvent(EVENT_ALL_ACCESS,FALSE, _T("Global\\test_event_a"));
	if (h_event)
	{
		SetEvent(h_event);
		CloseHandle(h_event);
	}

	while (1)
	{
		Sleep(1);
	}
    return 0;
}

