// build - Unicode
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <string.h>

int wmain(){
	// L"\\\\localhost"
	HANDLE hEventLog = OpenEventLog(NULL, L"System");

	// 자동, 비신호
	HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	
	BYTE Buffer[0x1000],
		*pBuffer = NULL;

	DWORD ret = 0,
		  dwRead = 0,
		  dwNeeded = 0,
		  LastRecordNumber = 0;
	
	BOOL bTrue = ReadEventLog(hEventLog, EVENTLOG_SEQUENTIAL_READ | EVENTLOG_BACKWARDS_READ, 0, Buffer, sizeof(Buffer), &dwRead, &dwNeeded);
	if(bTrue){ LastRecordNumber = ((EVENTLOGRECORD*)Buffer)->RecordNumber; }

	printf(L"Monitoring Event Log Changes\n");
	while(1){
		if(!NotifyChangeEventLog(hEventLog, hEvent)){
			printf("Listening Failed: %d\n", GetLastError());
			break;
		}

		ret = WaitForSingleObject(hEvent, INFINITE);
		if(ret == WAIT_OBJECT_0){
			printf("New Event Log Detected\n");
			// Read Log
		}else{
			printf("Wait Failed: %d", GetLastError());
		}
	}

	CloseEventLog(hEventLog);
}
