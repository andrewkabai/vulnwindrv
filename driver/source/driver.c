#include <ntifs.h>
#include <ntstrsafe.h>
#include "vulnwindrv.h"

#pragma warning(disable:4116)

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, VulnWinDrvNotSupported)
#pragma alloc_text(PAGE, VulnWinDrvCreate) 
#pragma alloc_text(PAGE, VulnWinDrvClose) 
#pragma alloc_text(PAGE, VulnWinDrvUnload)
#pragma alloc_text(PAGE, VulnWinDrvDeviceControl) 

NTSTATUS VulnWinDrvNotSupported(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  NTSTATUS NtStatus = STATUS_NOT_SUPPORTED;
  
  PAGED_CODE(); 
  return NtStatus;
}

NTSTATUS VulnWinDrvCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  PAGED_CODE(); 
  //DbgPrint("[VulnWinDrv] Device created");
  return STATUS_SUCCESS;
}

NTSTATUS VulnWinDrvClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  PAGED_CODE(); 
  //DbgPrint("[VulnWinDrv] Device closed");
  return STATUS_SUCCESS;
}

VOID VulnWinDrvUnload(PDRIVER_OBJECT  DriverObject)
{
  UNICODE_STRING usDosDeviceName; 

  PAGED_CODE();    
  //DbgPrint("[VulnWinDrv] Unloading driver");
  RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\VulnWinDrv");
  IoDeleteSymbolicLink(&usDosDeviceName);
  IoDeleteDevice(DriverObject->DeviceObject);
  //DbgPrint("[VulnWinDrv] Driver unloaded");
}

NTSTATUS VulnWinDrvDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
  NTSTATUS NtStatus = STATUS_NOT_SUPPORTED;
  PIO_STACK_LOCATION pIoStackIrp = NULL;

  PAGED_CODE();
  pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);

  //DbgPrint("[VulnWinDrv] Processing IOCTL request");
  
  if(pIoStackIrp)
  {
      switch(pIoStackIrp->Parameters.DeviceIoControl.IoControlCode)
      {
        case DEVICEIO_VulnWinDrv_DUMBFUNC:
          //DbgPrint("[VulnWinDrv] Calling IOCTL VulnWinDrv_STACKOVERFLOW");
          NtStatus = VulnWinDrvHandleIoctlDumbFunc(Irp, pIoStackIrp);
          break;
      }
  }

  Irp->IoStatus.Status = NtStatus;
  Irp->IoStatus.Information = 0;

  IoCompleteRequest(Irp, IO_NO_INCREMENT);
  return NtStatus;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT  pDriverObject, PUNICODE_STRING  pRegistryPath)
{
  PDEVICE_OBJECT pDeviceObject; 
  NTSTATUS NtStatus = STATUS_SUCCESS;
  UNICODE_STRING usDriverName, usDosDeviceName;
  UINT32 i;

  PAGED_CODE();
  RtlInitUnicodeString(&usDriverName, L"\\Device\\VulnWinDrv");
  RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\VulnWinDrv"); 
  NtStatus = IoCreateDevice(pDriverObject, 0, &usDriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);

  if(NtStatus != STATUS_SUCCESS)
  {
    DbgPrint("[VulnWinDrv] Error during driver initializtaion");
    return NtStatus;
  }
    
  for(i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
    pDriverObject->MajorFunction[i] = VulnWinDrvNotSupported;
    
  pDriverObject->MajorFunction[IRP_MJ_CREATE]            = VulnWinDrvCreate;
  pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]    = VulnWinDrvDeviceControl;
  pDriverObject->MajorFunction[IRP_MJ_CLOSE]             = VulnWinDrvClose;

  pDriverObject->DriverUnload =  VulnWinDrvUnload;
  pDeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);
  IoCreateSymbolicLink(&usDosDeviceName, &usDriverName);

  //DbgPrint("[VulnWinDrv] Driver Loaded");

  return NtStatus;
}
