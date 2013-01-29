#include <ntifs.h>
#include <ntstrsafe.h>
#include "vulnwindrv.h"

NTSTATUS __declspec(dllexport) DumbDrvFunc(UCHAR *stream, UINT32 len);
static int ExceptionFilter();
void DumbSubFunc1();
void DumbSubFunc2();
void DumbSubFunc3();
void DumbSubFunc4();

#pragma alloc_text(PAGE, VulnWinDrvHandleIoctlDumbFunc) 
#pragma alloc_text(PAGE, DumbDrvFunc)
#pragma alloc_text(PAGE, ExceptionFilter)
#pragma alloc_text(PAGE, DumbSubFunc1)
#pragma alloc_text(PAGE, DumbSubFunc2)
#pragma alloc_text(PAGE, DumbSubFunc3)
#pragma alloc_text(PAGE, DumbSubFunc4)

#pragma auto_inline(off)

static int ExceptionFilter()
{
  PAGED_CODE();
  return EXCEPTION_EXECUTE_HANDLER;
}

void DumbSubFunc1()
{
  PAGED_CODE();
  DbgPrint("[VulnWinDrv] 1. function called via jump table");
  return;
}

void DumbSubFunc2()
{
  PAGED_CODE();
  DbgPrint("[VulnWinDrv] 2. function called via jump table");
  return;
}

void DumbSubFunc3()
{
  PAGED_CODE();
  DbgPrint("[VulnWinDrv] 3. function called via jump table");
  return;
}

void DumbSubFunc4()
{
  PAGED_CODE();
  DbgPrint("[VulnWinDrv] 4. function called via jump table");
  return;
}

#define LOCAL_BUFF_SIZE 10
NTSTATUS __declspec(dllexport) DumbDrvFunc(UCHAR *stream, UINT32 len)
{
  long buff[LOCAL_BUFF_SIZE];
  void (*fpointers[4])() = { &DumbSubFunc1, &DumbSubFunc2, &DumbSubFunc3, &DumbSubFunc4 };
  NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
  int subCallCode;

  PAGED_CODE();	 
  __try 
  {
    ProbeForRead(stream, len, TYPE_ALIGNMENT(long));
    RtlCopyMemory(buff, stream, len);
  } 
  __except(ExceptionFilter())
  {
    NtStatus = GetExceptionCode();
    return NtStatus;
  }
  
  if (buff[0] == 0x0badf00d) {
    subCallCode = buff[1];
    (*fpointers[subCallCode])();
    
    DbgPrint("[VulnWinDrv] Here comes some magic on the buffer, if I will have time to implement it :)");
    
    NtStatus = STATUS_SUCCESS;
  } else {
    DbgPrint("[VulnWinDrv] No magic key found on the buffer");
  }

  return NtStatus;                                      
}  

NTSTATUS __declspec(dllexport) VulnWinDrvHandleIoctlDumbFunc(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp) 
{ 
  PCHAR pInputBuffer;
  UINT32 pInputLen;
  NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
   
  PAGED_CODE();
  pInputBuffer = pIoStackIrp->Parameters.DeviceIoControl.Type3InputBuffer;
  pInputLen    = pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength;

  if(pInputBuffer) {
    NtStatus = DumbDrvFunc(pInputBuffer, pInputLen);
  }
  return NtStatus;
}

#pragma auto_inline()
