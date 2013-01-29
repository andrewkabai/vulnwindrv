#ifndef __VulnWinDrv_H__
#define __VulnWinDrv_H__

typedef char * PCHAR;

#define __USER

#define DEVICEIO_VulnWinDrv_DUMBFUNC		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_READ_DATA | FILE_WRITE_DATA) 

NTSTATUS DriverEntry(PDRIVER_OBJECT  pDriverObject, PUNICODE_STRING  pRegistryPath);

DRIVER_UNLOAD VulnWinDrvUnload;
VOID     VulnWinDrvUnload(PDRIVER_OBJECT  DriverObject);

__drv_dispatchType(IRP_MJ_CREATE)           DRIVER_DISPATCH  VulnWinDrvCreate;
__drv_dispatchType(IRP_MJ_CLOSE)            DRIVER_DISPATCH  VulnWinDrvClose;
__drv_dispatchType(IRP_MJ_DEVICE_CONTROL)   DRIVER_DISPATCH  VulnWinDrvDeviceControl;
DRIVER_DISPATCH  VulnWinDrvNotSupported;

NTSTATUS  __declspec(dllexport) VulnWinDrvHandleIoctlDumbFunc(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp);

#endif
