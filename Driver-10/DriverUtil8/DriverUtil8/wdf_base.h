#pragma once
#include "Base.h"
#include <wdf.h>
#include <initguid.h>
#include <devguid.h>

#include "wdf_ioctrl.h"

typedef struct _CONTROL_DEVICE_EXTENSION {

	HANDLE   FileHandle; // Store your control data here

} CONTROL_DEVICE_EXTENSION, *PCONTROL_DEVICE_EXTENSION;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(CONTROL_DEVICE_EXTENSION,
	ControlGetData)

	//
	// Following request context is used only for the method-neither ioctl case.
	//
	typedef struct _REQUEST_CONTEXT {

	WDFMEMORY InputMemoryBuffer;
	WDFMEMORY OutputMemoryBuffer;

} REQUEST_CONTEXT, *PREQUEST_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(REQUEST_CONTEXT, GetRequestContext)

void
OnUnload(
	__in DRIVER_OBJECT* driverObject
	);

namespace ddk
{
	namespace wdf
	{
		static const auto WDF_NOPNP = DWORD(0);
		static const auto WDF_FILTER_OR_DEVICE = DWORD(1);
		static auto SYMBOLIC_NAME_STRING = L"\\DosDevices\\NONPNP";
		static auto NTDEVICE_NAME_STRING = L"\\Device\\NONPNP";
		static const auto POOL_TAG = 'ELIF';
		static void WdfNoPnpUnload(WDFDRIVER Driver)
		{
			//WDF的DriverUnload!!!!
			OnUnload(nullptr);
		}

		static VOID
			NonPnpEvtDriverContextCleanup(
				IN WDFOBJECT Driver
				)
			/*++
			Routine Description:

			Called when the driver object is deleted during driver unload.
			You can free all the resources created in DriverEntry that are
			not automatically freed by the framework.

			Arguments:

			Driver - Handle to a framework driver object created in DriverEntry

			Return Value:

			NTSTATUS

			--*/
		{
			//卸载前的CleanUp阶段，一般用unload的驱动不用cleanup
		}

		static VOID
			NonPnpEvtDeviceFileCreate(
				IN WDFDEVICE            Device,
				IN WDFREQUEST Request,
				IN WDFFILEOBJECT        FileObject
				)
			/*++

			Routine Description:

			The framework calls a driver's EvtDeviceFileCreate callback
			when it receives an IRP_MJ_CREATE request.
			The system sends this request when a user application opens the
			device to perform an I/O operation, such as reading or writing a file.
			This callback is called synchronously, in the context of the thread
			that created the IRP_MJ_CREATE request.

			Arguments:

			Device - Handle to a framework device object.
			FileObject - Pointer to fileobject that represents the open handle.
			CreateParams - Parameters of IO_STACK_LOCATION for create

			Return Value:

			NT status code

			--*/
		{
			PUNICODE_STRING             fileName;
			UNICODE_STRING              absFileName, directory;
			OBJECT_ATTRIBUTES           fileAttributes;
			IO_STATUS_BLOCK             ioStatus;
			PCONTROL_DEVICE_EXTENSION   devExt;
			NTSTATUS                    status;
			USHORT                      length = 0;


			UNREFERENCED_PARAMETER(FileObject);

			PAGED_CODE();

			devExt = ControlGetData(Device);

			//其实一般直接
			//WdfRequestComplete(Request, STATUS_SUCCESS);
			//return;

			//下面纯属sample炫技
			
			//
			// Assume the directory is a temp directory under %windir%
			//
			RtlInitUnicodeString(&directory, L"\\SystemRoot\\temp");

			//
			// Parsed filename has "\" in the begining. The object manager strips
			// of all "\", except one, after the device name.
			//
			fileName = WdfFileObjectGetFileName(FileObject);



			//
			// Find the total length of the directory + filename
			//
			length = directory.Length + fileName->Length;

			absFileName.Buffer = reinterpret_cast<PWCH>(ExAllocatePoolWithTag(PagedPool, length, POOL_TAG));
			if (absFileName.Buffer == NULL) {
				status = STATUS_INSUFFICIENT_RESOURCES;

				goto End;
			}
			absFileName.Length = 0;
			absFileName.MaximumLength = length;

			status = RtlAppendUnicodeStringToString(&absFileName, &directory);
			if (!NT_SUCCESS(status)) {

				goto End;
			}

			status = RtlAppendUnicodeStringToString(&absFileName, fileName);
			if (!NT_SUCCESS(status)) {

				goto End;
			}

			InitializeObjectAttributes(&fileAttributes,
				&absFileName,
				OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				NULL, // RootDirectory
				NULL // SecurityDescriptor
				);

			status = ZwCreateFile(
				&devExt->FileHandle,
				SYNCHRONIZE | GENERIC_WRITE | GENERIC_READ,
				&fileAttributes,
				&ioStatus,
				NULL,// alloc size = none
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_READ,
				FILE_OPEN_IF,
				FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
				NULL,// eabuffer
				0// ealength
				);

			if (!NT_SUCCESS(status)) {

				devExt->FileHandle = NULL;
			}

		End:
			if (absFileName.Buffer != NULL) {
				ExFreePool(absFileName.Buffer);
			}

			WdfRequestComplete(Request, status);

			return;
		}

		static VOID
			NonPnpEvtFileClose(
				IN WDFFILEOBJECT    FileObject
				)

			/*++

			Routine Description:

			EvtFileClose is called when all the handles represented by the FileObject
			is closed and all the references to FileObject is removed. This callback
			may get called in an arbitrary thread context instead of the thread that
			called CloseHandle. If you want to delete any per FileObject context that
			must be done in the context of the user thread that made the Create call,
			you should do that in the EvtDeviceCleanp callback.

			Arguments:

			FileObject - Pointer to fileobject that represents the open handle.

			Return Value:

			VOID

			--*/
		{
			PCONTROL_DEVICE_EXTENSION devExt;

			PAGED_CODE();

			devExt = ControlGetData(WdfFileObjectGetDevice(FileObject));

			if (devExt->FileHandle) {

				ZwClose(devExt->FileHandle);
			}

			return;
		}

		static VOID
			FileEvtIoRead(
				IN WDFQUEUE         Queue,
				IN WDFREQUEST       Request,
				IN size_t            Length
				)
			/*++

			Routine Description:

			This event is called when the framework receives IRP_MJ_READ requests.
			We will just read the file.

			Arguments:

			Queue -  Handle to the framework queue object that is associated with the
			I/O request.
			Request - Handle to a framework request object.

			Length  - number of bytes to be read.
			Queue is by default configured to fail zero length read & write requests.

			Return Value:

			None.

			--*/
		{
			NTSTATUS                   status = STATUS_SUCCESS;
			PVOID                       outBuf;
			IO_STATUS_BLOCK             ioStatus;
			PCONTROL_DEVICE_EXTENSION   devExt;
			FILE_POSITION_INFORMATION   position;
			ULONG_PTR                   bytesRead = 0;
			size_t  bufLength;


			PAGED_CODE();

			//
			// Get the request buffer. Since the device is set to do buffered
			// I/O, this function will retrieve Irp->AssociatedIrp.SystemBuffer.
			//
			status = WdfRequestRetrieveOutputBuffer(Request, 0, &outBuf, &bufLength);
			if (!NT_SUCCESS(status)) {
				WdfRequestComplete(Request, status);
				return;

			}

			devExt = ControlGetData(WdfIoQueueGetDevice(Queue));

			if (devExt->FileHandle) {

				//
				// Set the file position to the beginning of the file.
				//
				position.CurrentByteOffset.QuadPart = 0;
				status = ZwSetInformationFile(devExt->FileHandle,
					&ioStatus,
					&position,
					sizeof(FILE_POSITION_INFORMATION),
					FilePositionInformation);
				if (NT_SUCCESS(status)) {

					status = ZwReadFile(devExt->FileHandle,
						NULL,//   Event,
						NULL,// PIO_APC_ROUTINE  ApcRoutine
						NULL,// PVOID  ApcContext
						&ioStatus,
						outBuf,
						(ULONG)Length,
						0, // ByteOffset
						NULL // Key
						);

					if (!NT_SUCCESS(status)) {


					}

					status = ioStatus.Status;
					bytesRead = ioStatus.Information;
				}
			}

			WdfRequestCompleteWithInformation(Request, status, bytesRead);

		}

		static
			VOID
			FileEvtIoWrite(
				IN WDFQUEUE         Queue,
				IN WDFREQUEST       Request,
				IN size_t            Length
				)
			/*++

			Routine Description:

			This event is called when the framework receives IRP_MJ_WRITE requests.

			Arguments:

			Queue -  Handle to the framework queue object that is associated with the
			I/O request.
			Request - Handle to a framework request object.

			Length  - number of bytes to be written.
			Queue is by default configured to fail zero length read & write requests.


			Return Value:

			None
			--*/
		{
			NTSTATUS                   status = STATUS_SUCCESS;
			PVOID                       inBuf;
			IO_STATUS_BLOCK             ioStatus;
			PCONTROL_DEVICE_EXTENSION   devExt;
			FILE_POSITION_INFORMATION   position;
			ULONG_PTR                   bytesWritten = 0;
			size_t      bufLength;


			PAGED_CODE();

			//
			// Get the request buffer. Since the device is set to do buffered
			// I/O, this function will retrieve Irp->AssociatedIrp.SystemBuffer.
			//
			status = WdfRequestRetrieveInputBuffer(Request, 0, &inBuf, &bufLength);
			if (!NT_SUCCESS(status)) {
				WdfRequestComplete(Request, status);
				return;

			}

			devExt = ControlGetData(WdfIoQueueGetDevice(Queue));

			if (devExt->FileHandle) {

				//
				// Set the file position to the beginning of the file.
				//
				position.CurrentByteOffset.QuadPart = 0;

				status = ZwSetInformationFile(devExt->FileHandle,
					&ioStatus,
					&position,
					sizeof(FILE_POSITION_INFORMATION),
					FilePositionInformation);
				if (NT_SUCCESS(status))
				{

					status = ZwWriteFile(devExt->FileHandle,
						NULL,//   Event,
						NULL,// PIO_APC_ROUTINE  ApcRoutine
						NULL,// PVOID  ApcContext
						&ioStatus,
						inBuf,
						(ULONG)Length,
						0, // ByteOffset
						NULL // Key
						);
					if (!NT_SUCCESS(status))
					{

					}

					status = ioStatus.Status;
					bytesWritten = ioStatus.Information;
				}
			}

			WdfRequestCompleteWithInformation(Request, status, bytesWritten);

		}

		static
			VOID
			NonPnpShutdown(
				WDFDEVICE Device
				)
			/*++

			Routine Description:
			Callback invoked when the machine is shutting down.  If you register for
			a last chance shutdown notification you cannot do the following:
			o Call any pageable routines
			o Access pageable memory
			o Perform any file I/O operations

			If you register for a normal shutdown notification, all of these are
			available to you.

			This function implementation does nothing, but if you had any outstanding
			file handles open, this is where you would close them.

			Arguments:
			Device - The device which registered the notification during init

			Return Value:
			None

			--*/

		{
			UNREFERENCED_PARAMETER(Device);
			return;
		}

		VOID
			NonPnpEvtDeviceIoInCallerContext(
				IN WDFDEVICE  Device,
				IN WDFREQUEST Request
				)
			/*++
			Routine Description:

			This I/O in-process callback is called in the calling threads context/address
			space before the request is subjected to any framework locking or queueing
			scheme based on the device pnp/power or locking attributes set by the
			driver. The process context of the calling app is guaranteed as long as
			this driver is a top-level driver and no other filter driver is attached
			to it.

			This callback is only required if you are handling method-neither IOCTLs,
			or want to process requests in the context of the calling process.

			Driver developers should avoid defining neither IOCTLs and access user
			buffers, and use much safer I/O tranfer methods such as buffered I/O
			or direct I/O.

			Arguments:

			Device - Handle to a framework device object.

			Request - Handle to a framework request object. Framework calls
			PreProcess callback only for Read/Write/ioctls and internal
			ioctl requests.

			Return Value:

			VOID

			--*/
		{
			NTSTATUS                   status = STATUS_SUCCESS;
			PREQUEST_CONTEXT            reqContext = NULL;
			WDF_OBJECT_ATTRIBUTES           attributes;
			WDF_REQUEST_PARAMETERS  params;
			size_t              inBufLen, outBufLen;
			PVOID              inBuf, outBuf;

			PAGED_CODE();

			WDF_REQUEST_PARAMETERS_INIT(&params);

			WdfRequestGetParameters(Request, &params);

			//
			// Check to see whether we have recevied a METHOD_NEITHER IOCTL. if not
			// just send the request back to framework because we aren't doing
			// any pre-processing in the context of the calling thread process.
			//
			if (!(params.Type == WdfRequestTypeDeviceControl &&
				METHOD_FROM_CTL_CODE(params.Parameters.DeviceIoControl.IoControlCode) ==
				METHOD_NEITHER))
			{
				//
				// Forward it for processing by the I/O package
				//
				status = WdfDeviceEnqueueRequest(Device, Request);
				if (!NT_SUCCESS(status)) {
					goto End;
				}

				return;
			}

			//
			// In this type of transfer, the I/O manager assigns the user input
			// to Type3InputBuffer and the output buffer to UserBuffer of the Irp.
			// The I/O manager doesn't copy or map the buffers to the kernel
			// buffers.
			//
			status = WdfRequestRetrieveUnsafeUserInputBuffer(Request, 0, &inBuf, &inBufLen);
			if (!NT_SUCCESS(status)) {
				goto End;
			}

			status = WdfRequestRetrieveUnsafeUserOutputBuffer(Request, 0, &outBuf, &outBufLen);
			if (!NT_SUCCESS(status)) {
				goto End;
			}

			//
			// Allocate a context for this request so that we can store the memory
			// objects created for input and output buffer.
			//
			WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, REQUEST_CONTEXT);

			status = WdfObjectAllocateContext(Request, &attributes, (PVOID *)&reqContext);
			if (!NT_SUCCESS(status)) {
				goto End;
			}

			//
			// WdfRequestProbleAndLockForRead/Write function checks to see
			// whether the caller in the right thread context, creates an MDL,
			// probe and locks the pages, and map the MDL to system address
			// space and finally creates a WDFMEMORY object representing this
			// system buffer address. This memory object is associated with the
			// request. So it will be freed when the request is completed. If we
			// are accessing this memory buffer else where, we should store these
			// pointers in the request context.
			//

#pragma prefast(suppress:6387, "If inBuf==NULL at this point, then inBufLen==0")    
			status = WdfRequestProbeAndLockUserBufferForRead(Request,
				inBuf,
				inBufLen,
				&reqContext->InputMemoryBuffer);

			if (!NT_SUCCESS(status)) {
				goto End;
			}

#pragma prefast(suppress:6387, "If outBuf==NULL at this point, then outBufLen==0") 
			status = WdfRequestProbeAndLockUserBufferForWrite(Request,
				outBuf,
				outBufLen,
				&reqContext->OutputMemoryBuffer);
			if (!NT_SUCCESS(status)) {
				goto End;
			}

			//
			// Finally forward it for processing by the I/O package
			//
			status = WdfDeviceEnqueueRequest(Device, Request);
			if (!NT_SUCCESS(status)) {
				goto End;
			}

			return;

		End:
			WdfRequestComplete(Request, status);
			return;
		}
		static VOID
			PrintChars(
				_In_reads_(CountChars) PCHAR BufferAddress,
				_In_ size_t CountChars
				)
		{
			if (CountChars) {

				while (CountChars--) {

					if (*BufferAddress > 31
						&& *BufferAddress != 127) {

						DBG_PRINT("%c", *BufferAddress);

					}
					else {

						DBG_PRINT(".");

					}
					BufferAddress++;
				}
				DBG_PRINT("\r\n");
			}
			return;
		}
		static
			VOID
			FileEvtIoDeviceControl(
				IN WDFQUEUE         Queue,
				IN WDFREQUEST       Request,
				IN size_t            OutputBufferLength,
				IN size_t            InputBufferLength,
				IN ULONG            IoControlCode
				)
			/*++
			Routine Description:

			This event is called when the framework receives IRP_MJ_DEVICE_CONTROL
			requests from the system.

			Arguments:

			Queue - Handle to the framework queue object that is associated
			with the I/O request.
			Request - Handle to a framework request object.

			OutputBufferLength - length of the request's output buffer,
			if an output buffer is available.
			InputBufferLength - length of the request's input buffer,
			if an input buffer is available.

			IoControlCode - the driver-defined or system-defined I/O control code
			(IOCTL) that is associated with the request.

			Return Value:

			VOID

			--*/
		{
			NTSTATUS            status = STATUS_SUCCESS;// Assume success
			PCHAR               inBuf = NULL, outBuf = NULL; // pointer to Input and output buffer
			PCHAR               data = "this String is from Device Driver !!!";
			ULONG               datalen = (ULONG)strlen(data) + 1;//Length of data including null
			PCHAR               buffer = NULL;
			PREQUEST_CONTEXT    reqContext = NULL;
			size_t               bufSize;

			UNREFERENCED_PARAMETER(Queue);

			PAGED_CODE();

			if (!OutputBufferLength || !InputBufferLength)
			{
				WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
				return;
			}

			//
			// Determine which I/O control code was specified.
			//

			switch (IoControlCode)
			{
			case IOCTL_NONPNP_METHOD_BUFFERED:
				//
				// For bufffered ioctls WdfRequestRetrieveInputBuffer &
				// WdfRequestRetrieveOutputBuffer return the same buffer
				// pointer (Irp->AssociatedIrp.SystemBuffer), so read the
				// content of the buffer before writing to it.
				//
				status = WdfRequestRetrieveInputBuffer(Request, 0, (PVOID *)&inBuf, &bufSize);
				if (!NT_SUCCESS(status)) {
					status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}

				ASSERT(bufSize == InputBufferLength);

				//
				// Read the input buffer content.
				// We are using the following function to print characters instead
				// TraceEvents with %s format because the string we get may or
				// may not be null terminated. The buffer may contain non-printable
				// characters also.
				//
				PrintChars(inBuf, InputBufferLength);


				status = WdfRequestRetrieveOutputBuffer(Request, 0, (PVOID*)&outBuf, &bufSize);
				if (!NT_SUCCESS(status)) {
					status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}

				ASSERT(bufSize == OutputBufferLength);

				//
				// Writing to the buffer over-writes the input buffer content
				//

				RtlCopyMemory(outBuf, data, OutputBufferLength);

				PrintChars(outBuf, datalen);

				//
				// Assign the length of the data copied to IoStatus.Information
				// of the request and complete the request.
				//
				WdfRequestSetInformation(Request,
					OutputBufferLength < datalen ? OutputBufferLength : datalen);

				//
				// When the request is completed the content of the SystemBuffer
				// is copied to the User output buffer and the SystemBuffer is
				// is freed.
				//

				break;


			case IOCTL_NONPNP_METHOD_IN_DIRECT:

				//
				// Get the Input buffer. WdfRequestRetrieveInputBuffer returns
				// Irp->AssociatedIrp.SystemBuffer.
				//
				status = WdfRequestRetrieveInputBuffer(Request, 0, (PVOID*)&inBuf, &bufSize);
				if (!NT_SUCCESS(status)) {
					status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}

				ASSERT(bufSize == InputBufferLength);

				PrintChars(inBuf, InputBufferLength);

				//
				// Get the output buffer. Framework calls MmGetSystemAddressForMdlSafe
				// on the Irp->MdlAddress and returns the system address.
				// Oddity: For this method, this buffer is intended for transfering data
				// from the application to the driver.
				//

				status = WdfRequestRetrieveOutputBuffer(Request, 0, (PVOID*)&buffer, &bufSize);
				if (!NT_SUCCESS(status)) {
					break;
				}

				ASSERT(bufSize == OutputBufferLength);

				PrintChars(buffer, OutputBufferLength);

				//
				// Return total bytes read from the output buffer.
				// Note OutputBufferLength = MmGetMdlByteCount(Irp->MdlAddress)
				//

				WdfRequestSetInformation(Request, OutputBufferLength);

				//
				// NOTE: Changes made to the  SystemBuffer are not copied
				// to the user input buffer by the I/O manager
				//

				break;

			case IOCTL_NONPNP_METHOD_OUT_DIRECT:

				//
				// Get the Input buffer. WdfRequestRetrieveInputBuffer returns
				// Irp->AssociatedIrp.SystemBuffer.
				//
				status = WdfRequestRetrieveInputBuffer(Request, 0, (PVOID*)&inBuf, &bufSize);
				if (!NT_SUCCESS(status)) {
					status = STATUS_INSUFFICIENT_RESOURCES;
					break;
				}

				ASSERT(bufSize == InputBufferLength);

				PrintChars(inBuf, InputBufferLength);

				//
				// Get the output buffer. Framework calls MmGetSystemAddressForMdlSafe
				// on the Irp->MdlAddress and returns the system address.
				// For this method, this buffer is intended for transfering data from the
				// driver to the application.
				//
				status = WdfRequestRetrieveOutputBuffer(Request, 0, (PVOID*)&buffer, &bufSize);
				if (!NT_SUCCESS(status)) {
					break;
				}

				ASSERT(bufSize == OutputBufferLength);

				//
				// Write data to be sent to the user in this buffer
				//
				RtlCopyMemory(buffer, data, OutputBufferLength);

				PrintChars(buffer, datalen);

				WdfRequestSetInformation(Request,
					OutputBufferLength < datalen ? OutputBufferLength : datalen);

				//
				// NOTE: Changes made to the  SystemBuffer are not copied
				// to the user input buffer by the I/O manager
				//

				break;

			case IOCTL_NONPNP_METHOD_NEITHER:
			{
				size_t inBufLength, outBufLength;

				//
				// The NonPnpEvtDeviceIoInCallerContext has already probe and locked the
				// pages and mapped the user buffer into system address space and
				// stored memory buffer pointers in the request context. We can get the
				// buffer pointer by calling WdfMemoryGetBuffer.
				//

				reqContext = GetRequestContext(Request);

				inBuf = reinterpret_cast<PCHAR>(WdfMemoryGetBuffer(reqContext->InputMemoryBuffer, &inBufLength));
				outBuf = reinterpret_cast<PCHAR>(WdfMemoryGetBuffer(reqContext->OutputMemoryBuffer, &outBufLength));

				if (inBuf == NULL || outBuf == NULL) {
					status = STATUS_INVALID_PARAMETER;
				}

				ASSERT(inBufLength == InputBufferLength);
				ASSERT(outBufLength == OutputBufferLength);

				//
				// Now you can safely read the data from the buffer in any arbitrary
				// context.
				//
				PrintChars(inBuf, inBufLength);

				//
				// Write to the buffer in any arbitrary context.
				//
				RtlCopyMemory(outBuf, data, outBufLength);

				PrintChars(outBuf, datalen);

				//
				// Assign the length of the data copied to IoStatus.Information
				// of the Irp and complete the Irp.
				//
				WdfRequestSetInformation(Request,
					outBufLength < datalen ? outBufLength : datalen);

				break;
			}
			default:

				//
				// The specified I/O control code is unrecognized by this driver.
				//
				status = STATUS_INVALID_DEVICE_REQUEST;
				
				break;
			}

			WdfRequestComplete(Request, status);

		}
		static NTSTATUS
			NonPnpDeviceAdd(
				IN WDFDRIVER Driver,
				IN PWDFDEVICE_INIT DeviceInit
				)
			/*++

			Routine Description:

			Called by the DriverEntry to create a control-device. This call is
			responsible for freeing the memory for DeviceInit.

			Arguments:

			DriverObject - a pointer to the object that represents this device
			driver.

			DeviceInit - Pointer to a driver-allocated WDFDEVICE_INIT structure.

			Return Value:

			STATUS_SUCCESS if initialized; an error otherwise.

			--*/
		{
			NTSTATUS                       status;
			WDF_OBJECT_ATTRIBUTES           attributes;
			WDF_IO_QUEUE_CONFIG      ioQueueConfig;
			WDF_FILEOBJECT_CONFIG fileConfig;
			WDFQUEUE                            queue;
			WDFDEVICE   controlDevice;
			UNICODE_STRING ntDeviceName, symbolicLinkName;

			RtlInitUnicodeString(&ntDeviceName, NTDEVICE_NAME_STRING);
			RtlInitUnicodeString(&symbolicLinkName, SYMBOLIC_NAME_STRING);

			UNREFERENCED_PARAMETER(Driver);

			PAGED_CODE();

			//
			// Set exclusive to TRUE so that no more than one app can talk to the
			// control device at any time.
			//
			WdfDeviceInitSetExclusive(DeviceInit, TRUE);

			WdfDeviceInitSetIoType(DeviceInit, WdfDeviceIoBuffered);


			status = WdfDeviceInitAssignName(DeviceInit, &ntDeviceName);

			if (!NT_SUCCESS(status)) {
				goto End;
			}

			WdfControlDeviceInitSetShutdownNotification(DeviceInit,
				NonPnpShutdown,
				WdfDeviceShutdown);

			//
			// Initialize WDF_FILEOBJECT_CONFIG_INIT struct to tell the
			// framework whether you are interested in handling Create, Close and
			// Cleanup requests that gets generated when an application or another
			// kernel component opens an handle to the device. If you don't register
			// the framework default behaviour would be to complete these requests
			// with STATUS_SUCCESS. A driver might be interested in registering these
			// events if it wants to do security validation and also wants to maintain
			// per handle (fileobject) context.
			//

			WDF_FILEOBJECT_CONFIG_INIT(
				&fileConfig,
				NonPnpEvtDeviceFileCreate,
				NonPnpEvtFileClose,
				WDF_NO_EVENT_CALLBACK // not interested in Cleanup
				);

			WdfDeviceInitSetFileObjectConfig(DeviceInit,
				&fileConfig,
				WDF_NO_OBJECT_ATTRIBUTES);

			//
			// In order to support METHOD_NEITHER Device controls, or
			// NEITHER device I/O type, we need to register for the
			// EvtDeviceIoInProcessContext callback so that we can handle the request
			// in the calling threads context.
			//
			WdfDeviceInitSetIoInCallerContextCallback(DeviceInit,
				NonPnpEvtDeviceIoInCallerContext);

			//
			// Specify the size of device context
			//
			WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes,
				CONTROL_DEVICE_EXTENSION);

			status = WdfDeviceCreate(&DeviceInit,
				&attributes,
				&controlDevice);
			if (!NT_SUCCESS(status)) {

				goto End;
			}

			//
			// Create a symbolic link for the control object so that usermode can open
			// the device.
			//


			status = WdfDeviceCreateSymbolicLink(controlDevice,
				&symbolicLinkName);

			if (!NT_SUCCESS(status)) {
				//
				// Control device will be deleted automatically by the framework.
				//
				goto End;
			}

			//
			// Configure a default queue so that requests that are not
			// configure-fowarded using WdfDeviceConfigureRequestDispatching to goto
			// other queues get dispatched here.
			//
			WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&ioQueueConfig,
				WdfIoQueueDispatchSequential);

			ioQueueConfig.EvtIoRead = FileEvtIoRead;
			ioQueueConfig.EvtIoWrite = FileEvtIoWrite;
			ioQueueConfig.EvtIoDeviceControl = FileEvtIoDeviceControl;

			WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
			//
			// Since we are using Zw function set execution level to passive so that
			// framework ensures that our Io callbacks called at only passive-level
			// even if the request came in at DISPATCH_LEVEL from another driver.
			//
			attributes.ExecutionLevel = WdfExecutionLevelPassive;

			//
			// By default, Static Driver Verifier (SDV) displays a warning if it 
			// doesn't find the EvtIoStop callback on a power-managed queue. 
			// The 'assume' below causes SDV to suppress this warning. If the driver 
			// has not explicitly set PowerManaged to WdfFalse, the framework creates
			// power-managed queues when the device is not a filter driver.  Normally 
			// the EvtIoStop is required for power-managed queues, but for this driver
			// it is not needed b/c the driver doesn't hold on to the requests or 
			// forward them to other drivers. This driver completes the requests 
			// directly in the queue's handlers. If the EvtIoStop callback is not 
			// implemented, the framework waits for all driver-owned requests to be
			// done before moving in the Dx/sleep states or before removing the 
			// device, which is the correct behavior for this type of driver.
			// If the requests were taking an indeterminate amount of time to complete,
			// or if the driver forwarded the requests to a lower driver/another stack,
			// the queue should have an EvtIoStop/EvtIoResume.
			//
			__analysis_assume(ioQueueConfig.EvtIoStop != 0);
			status = WdfIoQueueCreate(controlDevice,
				&ioQueueConfig,
				&attributes,
				&queue // pointer to default queue
				);
			__analysis_assume(ioQueueConfig.EvtIoStop == 0);
			if (!NT_SUCCESS(status)) {

				goto End;
			}

			//
			// Control devices must notify WDF when they are done initializing.   I/O is
			// rejected until this call is made.
			//
			WdfControlFinishInitializing(controlDevice);

		End:
			//
			// If the device is created successfully, framework would clear the
			// DeviceInit value. Otherwise device create must have failed so we
			// should free the memory ourself.
			//
			if (DeviceInit != NULL) {
				WdfDeviceInitFree(DeviceInit);
			}

			return status;
		}
		static NTSTATUS WdfCreateNoPnp(PDRIVER_OBJECT drv_object, PUNICODE_STRING drv_reg_path)
		{
			NTSTATUS                       status;
			WDF_DRIVER_CONFIG              config;
			WDFDRIVER                      hDriver;
			PWDFDEVICE_INIT                pInit = NULL;
			WDF_OBJECT_ATTRIBUTES          attributes;

			WDF_DRIVER_CONFIG_INIT(
				&config,
				WDF_NO_EVENT_CALLBACK // This is a non-pnp driver.
				);

			//
			// Tell the framework that this is non-pnp driver so that it doesn't
			// set the default AddDevice routine.
			//
			config.DriverInitFlags |= WdfDriverInitNonPnpDriver;

			//
			// NonPnp driver must explicitly register an unload routine for
			// the driver to be unloaded.
			//
			config.EvtDriverUnload = WdfNoPnpUnload;

			WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
			attributes.EvtCleanupCallback = NonPnpEvtDriverContextCleanup;

			//
			// Create a framework driver object to represent our driver.
			//
			status = WdfDriverCreate(drv_object,
				drv_reg_path,
				&attributes,
				&config,
				&hDriver);
			if (!NT_SUCCESS(status)) {
				KdPrint(("NonPnp: WdfDriverCreate failed with status 0x%x\n", status));
				return status;
			}

			//
			//
			// In order to create a control device, we first need to allocate a
			// WDFDEVICE_INIT structure and set all properties.
			//
			pInit = WdfControlDeviceInitAllocate(
				hDriver,
				&SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RW_RES_R
				);

			if (pInit == NULL) {
				status = STATUS_INSUFFICIENT_RESOURCES;
				return status;
			}

			//
			// Call NonPnpDeviceAdd to create a deviceobject to represent our
			// software device.
			//
			status = NonPnpDeviceAdd(hDriver, pInit);

			return status;
		}
		//////////////////////////////////////////////////////////////////////////
		static auto WDF_DEVICE_TYPE = FILE_DEVICE_KEYBOARD;
		static ULONG InstanceNo = 0;
		//// Used to identify kbfilter bus. This guid is used as the enumeration string
		//// for the device id.
		//DEFINE_GUID(GUID_BUS_KBFILTER,
		//	0xa65c87f9, 0xbe02, 0x4ed9, 0x92, 0xec, 0x1, 0x2d, 0x41, 0x61, 0x69, 0xfa);
		//// {A65C87F9-BE02-4ed9-92EC-012D416169FA}

		DEFINE_GUID(GUID_DEVINTERFACE_FILTER,
			0x3fb7299d, 0x6847, 0x4490, 0xb0, 0xc9, 0x99, 0xe0, 0x98, 0x6a, 0xb8, 0x86);
		// {3FB7299D-6847-4490-B0C9-99E0986AB886}

		static const auto FILTR_DEVICE_ID = L"{A65C87F9-BE02-4ed9-92EC-012D416169FA}\\KeyboardFilter\0";

		typedef struct _RPDO_DEVICE_DATA
		{

			ULONG InstanceNo;

			//
			// Queue of the parent device we will forward requests to
			//
			WDFQUEUE ParentQueue;

		} RPDO_DEVICE_DATA, *PRPDO_DEVICE_DATA;

		WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(RPDO_DEVICE_DATA, PdoGetData)

		typedef struct _WDF_DEVICE_EXTENSION
		{
			WDFDEVICE WdfDevice;
			//
			// Queue for handling requests that come from the rawPdo
			//
			WDFQUEUE rawPdoQueue;
			//
			// Number of creates sent down
			//
			LONG EnableCount;

		} WDF_DEVICE_EXTENSION, *PWDF_DEVICE_EXTENSION;

		WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(WDF_DEVICE_EXTENSION,
			FilterGetData)

		static 
			VOID
			Filter_EvtIoDeviceControlFromRawPdo(
				IN WDFQUEUE      Queue,
				IN WDFREQUEST    Request,
				IN size_t        OutputBufferLength,
				IN size_t        InputBufferLength,
				IN ULONG         IoControlCode
				)
			/*++

			Routine Description:

			This routine is the dispatch routine for device control requests.

			Arguments:

			Queue - Handle to the framework queue object that is associated
			with the I/O request.
			Request - Handle to a framework request object.

			OutputBufferLength - length of the request's output buffer,
			if an output buffer is available.
			InputBufferLength - length of the request's input buffer,
			if an input buffer is available.

			IoControlCode - the driver-defined or system-defined I/O control code
			(IOCTL) that is associated with the request.

			Return Value:

			VOID

			--*/
		{
			NTSTATUS status = STATUS_SUCCESS;
			WDFDEVICE hDevice;
			WDFMEMORY outputMemory;
			size_t bytesTransferred = 0;

			UNREFERENCED_PARAMETER(InputBufferLength);

			KdPrint(("Entered Filter_EvtIoInternalDeviceControl\n"));

			hDevice = WdfIoQueueGetDevice(Queue);
			auto devExt = FilterGetData(hDevice);

			//
			// Process the ioctl and complete it when you are done.
			//

			/*switch (IoControlCode) {
			
			default:
				status = STATUS_NOT_IMPLEMENTED;
				break;
			}*/

			status = STATUS_NOT_IMPLEMENTED;

			WdfRequestCompleteWithInformation(Request, status, bytesTransferred);

			return;
		}
		static VOID
			Filter_DispatchPassThrough(
				_In_ WDFREQUEST Request,
				_In_ WDFIOTARGET Target
				)
			/*++
			Routine Description:

			Passes a request on to the lower driver.


			--*/
		{
			//
			// Pass the IRP to the target
			//

			WDF_REQUEST_SEND_OPTIONS options;
			BOOLEAN ret;
			NTSTATUS status = STATUS_SUCCESS;

			//
			// We are not interested in post processing the IRP so 
			// fire and forget.
			//
			WDF_REQUEST_SEND_OPTIONS_INIT(&options,
				WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);

			ret = WdfRequestSend(Request, Target, &options);

			if (ret == FALSE) {
				status = WdfRequestGetStatus(Request);
				KdPrint(("WdfRequestSend failed: 0x%x\n", status));
				WdfRequestComplete(Request, status);
			}

			return;
		}
		static VOID Filter_EvtIoDefault(WDFQUEUE Queue, WDFREQUEST Request)
		{
			WDF_REQUEST_PARAMETERS Params;
			auto hDevice = WdfIoQueueGetDevice(Queue);
			auto devExt = FilterGetData(hDevice);
			WDF_REQUEST_PARAMETERS_INIT(&Params);
			WdfRequestGetParameters(Request, &Params);
		//	DBG_PRINT("Filter Type = %x\r\n", Params.Type);
			Filter_DispatchPassThrough(Request, WdfDeviceGetIoTarget(hDevice));
		}

		static VOID
			Filter_EvtIoDeviceControlForRawPdo(
				IN WDFQUEUE      Queue,
				IN WDFREQUEST    Request,
				IN size_t        OutputBufferLength,
				IN size_t        InputBufferLength,
				IN ULONG         IoControlCode
				)
			/*++

			Routine Description:

			This routine is the dispatch routine for device control requests.

			Arguments:

			Queue - Handle to the framework queue object that is associated
			with the I/O request.
			Request - Handle to a framework request object.

			OutputBufferLength - length of the request's output buffer,
			if an output buffer is available.
			InputBufferLength - length of the request's input buffer,
			if an input buffer is available.

			IoControlCode - the driver-defined or system-defined I/O control code
			(IOCTL) that is associated with the request.

			Return Value:

			VOID

			--*/
		{
			NTSTATUS status = STATUS_SUCCESS;
			WDFDEVICE parent = WdfIoQueueGetDevice(Queue);
			PRPDO_DEVICE_DATA pdoData;
			WDF_REQUEST_FORWARD_OPTIONS forwardOptions;

			pdoData = PdoGetData(parent);

			UNREFERENCED_PARAMETER(OutputBufferLength);
			UNREFERENCED_PARAMETER(InputBufferLength);

			KdPrint(("Entered Filter_EvtIoDeviceControlForRawPdo\n"));

			//
			// Process the ioctl and complete it when you are done.
			// Since the queue is configured for serial dispatch, you will
			// not receive another ioctl request until you complete this one.
			//

			//switch (IoControlCode) {
			//case IOCT_TEST_WDF:
			//	WDF_REQUEST_FORWARD_OPTIONS_INIT(&forwardOptions);
			//	status = WdfRequestForwardToParentDeviceIoQueue(Request, pdoData->ParentQueue, &forwardOptions);
			//	if (!NT_SUCCESS(status)) {
			//		WdfRequestComplete(Request, status);
			//	}
			//	break;
			//default:
			//	WdfRequestComplete(Request, status);
			//	break;
			//}

			WdfRequestComplete(Request, status);
			return;
		}

#define MAX_ID_LEN 128

		static NTSTATUS
			Filtr_CreateRawPdo(
				WDFDEVICE       Device,
				ULONG           InstanceNo
				)
			/*++

			Routine Description:

			This routine creates and initialize a PDO.

			Arguments:

			Return Value:

			NT Status code.

			--*/
		{
			NTSTATUS                    status;
			PWDFDEVICE_INIT             pDeviceInit = NULL;
			PRPDO_DEVICE_DATA           pdoData = NULL;
			WDFDEVICE                   hChild = NULL;
			WDF_OBJECT_ATTRIBUTES       pdoAttributes;
			WDF_DEVICE_PNP_CAPABILITIES pnpCaps;
			WDF_IO_QUEUE_CONFIG         ioQueueConfig;
			WDFQUEUE                    queue;
			WDF_DEVICE_STATE            deviceState;
			UNICODE_STRING deviceId, hardwareId;

			RtlInitUnicodeString(&deviceId, FILTR_DEVICE_ID);
			RtlInitUnicodeString(&hardwareId, FILTR_DEVICE_ID);

			DECLARE_CONST_UNICODE_STRING(deviceLocation, L"WDF Filter\0");
			DECLARE_UNICODE_STRING_SIZE(buffer, MAX_ID_LEN);

			KdPrint(("Entered Filtr_CreateRawPdo\n"));

			//
			// Allocate a WDFDEVICE_INIT structure and set the properties
			// so that we can create a device object for the child.
			//
			pDeviceInit = WdfPdoInitAllocate(Device);

			if (pDeviceInit == NULL) {
				status = STATUS_INSUFFICIENT_RESOURCES;
				goto Cleanup;
			}

			//
			// Mark the device RAW so that the child device can be started
			// and accessed without requiring a function driver. Since we are
			// creating a RAW PDO, we must provide a class guid.
			//
			status = WdfPdoInitAssignRawDevice(pDeviceInit, &GUID_DEVCLASS_KEYBOARD);
			if (!NT_SUCCESS(status)) {
				goto Cleanup;
			}

			//
			// Since keyboard is secure device, we must protect ourselves from random
			// users sending ioctls and creating trouble.
			//
			status = WdfDeviceInitAssignSDDLString(pDeviceInit,
				&SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
			if (!NT_SUCCESS(status)) {
				goto Cleanup;
			}

			//
			// Assign DeviceID - This will be reported to IRP_MN_QUERY_ID/BusQueryDeviceID
			//
			status = WdfPdoInitAssignDeviceID(pDeviceInit, &deviceId);
			if (!NT_SUCCESS(status)) {
				goto Cleanup;
			}

			//
			// For RAW PDO, there is no need to provide BusQueryHardwareIDs
			// and BusQueryCompatibleIDs IDs unless we are running on
			// Windows 2000.
			//
			if (!RtlIsNtDdiVersionAvailable(NTDDI_WINXP)) {
				//
				// On Win2K, we must provide a HWID for the device to get enumerated.
				// Since we are providing a HWID, we will have to provide a NULL inf
				// to avoid the "found new device" popup and get the device installed
				// silently.
				//
				status = WdfPdoInitAddHardwareID(pDeviceInit, &hardwareId);
				if (!NT_SUCCESS(status)) {
					goto Cleanup;
				}
			}

			//
			// We could be enumerating more than one children if the filter attaches
			// to multiple instances of keyboard, so we must provide a
			// BusQueryInstanceID. If we don't, system will throw CA bugcheck.
			//
			status = RtlUnicodeStringPrintf(&buffer, L"%02d", InstanceNo);
			if (!NT_SUCCESS(status)) {
				goto Cleanup;
			}

			status = WdfPdoInitAssignInstanceID(pDeviceInit, &buffer);
			if (!NT_SUCCESS(status)) {
				goto Cleanup;
			}

			//
			// Provide a description about the device. This text is usually read from
			// the device. In the case of USB device, this text comes from the string
			// descriptor. This text is displayed momentarily by the PnP manager while
			// it's looking for a matching INF. If it finds one, it uses the Device
			// Description from the INF file to display in the device manager.
			// Since our device is raw device and we don't provide any hardware ID
			// to match with an INF, this text will be displayed in the device manager.
			//
			status = RtlUnicodeStringPrintf(&buffer, L"wdf_Filter_%02d", InstanceNo);
			if (!NT_SUCCESS(status)) {
				goto Cleanup;
			}

			//
			// You can call WdfPdoInitAddDeviceText multiple times, adding device
			// text for multiple locales. When the system displays the text, it
			// chooses the text that matches the current locale, if available.
			// Otherwise it will use the string for the default locale.
			// The driver can specify the driver's default locale by calling
			// WdfPdoInitSetDefaultLocale.
			//
			status = WdfPdoInitAddDeviceText(pDeviceInit,
				&buffer,
				&deviceLocation,
				0x409 //英语
				);
			if (!NT_SUCCESS(status)) {
				goto Cleanup;
			}

			WdfPdoInitSetDefaultLocale(pDeviceInit, 0x409);

			//
			// Initialize the attributes to specify the size of PDO device extension.
			// All the state information private to the PDO will be tracked here.
			//
			WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&pdoAttributes, RPDO_DEVICE_DATA);

			//
			// Set up our queue to allow forwarding of requests to the parent
			// This is done so that the cached Keyboard Attributes can be retrieved
			//
			WdfPdoInitAllowForwardingRequestToParent(pDeviceInit);

			status = WdfDeviceCreate(&pDeviceInit, &pdoAttributes, &hChild);
			if (!NT_SUCCESS(status)) {
				goto Cleanup;
			}

			//
			// Get the device context.
			//
			pdoData = PdoGetData(hChild);

			pdoData->InstanceNo = InstanceNo;

			//
			// Get the parent queue we will be forwarding to
			//
			auto devExt = FilterGetData(Device);
			pdoData->ParentQueue = devExt->rawPdoQueue;

			//
			// Configure the default queue associated with the control device object
			// to be Serial so that request passed to EvtIoDeviceControl are serialized.
			// A default queue gets all the requests that are not
			// configure-fowarded using WdfDeviceConfigureRequestDispatching.
			//

			WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&ioQueueConfig,
				WdfIoQueueDispatchSequential);

			ioQueueConfig.EvtIoDeviceControl = Filter_EvtIoDeviceControlForRawPdo;

			status = WdfIoQueueCreate(hChild,
				&ioQueueConfig,
				WDF_NO_OBJECT_ATTRIBUTES,
				&queue // pointer to default queue
				);
			if (!NT_SUCCESS(status)) {
				KdPrint(("WdfIoQueueCreate failed 0x%x\n", status));
				goto Cleanup;
			}

			//
			// Set some properties for the child device.
			//
			WDF_DEVICE_PNP_CAPABILITIES_INIT(&pnpCaps);

			pnpCaps.Removable = WdfTrue;
			pnpCaps.SurpriseRemovalOK = WdfTrue;
			pnpCaps.NoDisplayInUI = WdfTrue;

			pnpCaps.Address = InstanceNo;
			pnpCaps.UINumber = InstanceNo;

			WdfDeviceSetPnpCapabilities(hChild, &pnpCaps);

			//
			// TODO: In addition to setting NoDisplayInUI in DeviceCaps, we
			// have to do the following to hide the device. Following call
			// tells the framework to report the device state in
			// IRP_MN_QUERY_DEVICE_STATE request.
			//
			WDF_DEVICE_STATE_INIT(&deviceState);
			deviceState.DontDisplayInUI = WdfTrue;
			WdfDeviceSetDeviceState(hChild, &deviceState);

			//
			// Tell the Framework that this device will need an interface so that
			// application can find our device and talk to it.
			//
			status = WdfDeviceCreateDeviceInterface(
				hChild,
				&GUID_DEVINTERFACE_FILTER,
				NULL
				);

			if (!NT_SUCCESS(status)) {
				KdPrint(("WdfDeviceCreateDeviceInterface failed 0x%x\n", status));
				goto Cleanup;
			}

			//
			// Add this device to the FDO's collection of children.
			// After the child device is added to the static collection successfully,
			// driver must call WdfPdoMarkMissing to get the device deleted. It
			// shouldn't delete the child device directly by calling WdfObjectDelete.
			//
			status = WdfFdoAddStaticChild(Device, hChild);
			if (!NT_SUCCESS(status)) {
				goto Cleanup;
			}

			//
			// pDeviceInit will be freed by WDF.
			//
			return STATUS_SUCCESS;

		Cleanup:

			KdPrint(("Filtr_CreatePdo failed %x\n", status));

			//
			// Call WdfDeviceInitFree if you encounter an error while initializing
			// a new framework device object. If you call WdfDeviceInitFree,
			// do not call WdfDeviceCreate.
			//
			if (pDeviceInit != NULL) {
				WdfDeviceInitFree(pDeviceInit);
			}

			if (hChild) {
				WdfObjectDelete(hChild);
			}

			return status;
		}
		static NTSTATUS Filter_EvtDeviceAdd(
				IN WDFDRIVER        Driver,
				IN PWDFDEVICE_INIT  DeviceInit
				)
			/*++
			Routine Description:

			EvtDeviceAdd is called by the framework in response to AddDevice
			call from the PnP manager. Here you can query the device properties
			using WdfFdoInitWdmGetPhysicalDevice/IoGetDeviceProperty and based
			on that, decide to create a filter device object and attach to the
			function stack.

			If you are not interested in filtering this particular instance of the
			device, you can just return STATUS_SUCCESS without creating a framework
			device.

			Arguments:

			Driver - Handle to a framework driver object created in DriverEntry

			DeviceInit - Pointer to a framework-allocated WDFDEVICE_INIT structure.

			Return Value:

			NTSTATUS

			--*/
		{
			WDF_OBJECT_ATTRIBUTES   deviceAttributes;
			NTSTATUS                status;
			WDFDEVICE               hDevice;
			WDFQUEUE                hQueue;
			PWDF_DEVICE_EXTENSION       filterExt;
			WDF_IO_QUEUE_CONFIG     ioQueueConfig;

			UNREFERENCED_PARAMETER(Driver);

			PAGED_CODE();

			//
			// Tell the framework that you are filter driver. Framework
			// takes care of inherting all the device flags & characterstics
			// from the lower device you are attaching to.
			//
			WdfFdoInitSetFilter(DeviceInit);

			WdfDeviceInitSetDeviceType(DeviceInit, WDF_DEVICE_TYPE);

			WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, WDF_DEVICE_EXTENSION);

			//
			// Create a framework device object.  This call will in turn create
			// a WDM deviceobject, attach to the lower stack and set the
			// appropriate flags and attributes.
			//
			status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &hDevice);
			if (!NT_SUCCESS(status)) {
				KdPrint(("WdfDeviceCreate failed with status code 0x%x\n", status));
				return status;
			}

			filterExt = FilterGetData(hDevice);

			//
			// Configure the default queue to be Parallel. Do not use sequential queue
			// if this driver is going to be filtering PS2 ports because it can lead to
			// deadlock. The PS2 port driver sends a request to the top of the stack when it
			// receives an ioctl request and waits for it to be completed. If you use a
			// a sequential queue, this request will be stuck in the queue because of the 
			// outstanding ioctl request sent earlier to the port driver.
			//
			WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&ioQueueConfig,
				WdfIoQueueDispatchParallel);

			//
			// Framework by default creates non-power managed queues for
			// filter drivers.
			//
			ioQueueConfig.EvtIoDefault = Filter_EvtIoDefault;

			status = WdfIoQueueCreate(hDevice,
				&ioQueueConfig,
				WDF_NO_OBJECT_ATTRIBUTES,
				WDF_NO_HANDLE // pointer to default queue
				);
			if (!NT_SUCCESS(status)) {
				KdPrint(("WdfIoQueueCreate failed 0x%x\n", status));
				return status;
			}

			//
			// Create a new queue to handle IOCTLs that will be forwarded to us from
			// the rawPDO. 
			//
			WDF_IO_QUEUE_CONFIG_INIT(&ioQueueConfig,
				WdfIoQueueDispatchParallel);

			//
			// Framework by default creates non-power managed queues for
			// filter drivers.
			//
			ioQueueConfig.EvtIoDeviceControl = Filter_EvtIoDeviceControlFromRawPdo;

			status = WdfIoQueueCreate(hDevice,
				&ioQueueConfig,
				WDF_NO_OBJECT_ATTRIBUTES,
				&hQueue
				);
			if (!NT_SUCCESS(status)) {
				KdPrint(("WdfIoQueueCreate failed 0x%x\n", status));
				return status;
			}

			filterExt->rawPdoQueue = hQueue;

			//
			// Create a RAW pdo so we can provide a sideband communication with
			// the application. Please note that not filter drivers desire to
			// produce such a communication and not all of them are contrained
			// by other filter above which prevent communication thru the device
			// interface exposed by the main stack. So use this only if absolutely
			// needed. Also look at the toaster filter driver sample for an alternate
			// approach to providing sideband communication.
			//
			status = Filtr_CreateRawPdo(hDevice, ++InstanceNo);

			return status;
		}
		static NTSTATUS WdfCreateFilter(PDRIVER_OBJECT drv_object, PUNICODE_STRING drv_reg_path)
		{
			//GUID
			WDF_DRIVER_CONFIG               config;
			NTSTATUS                        status;

			WDF_DRIVER_CONFIG_INIT(
				&config,
				Filter_EvtDeviceAdd
				);
			//
			// Create a framework driver object to represent our driver.
			//
			status = WdfDriverCreate(drv_object,
				drv_reg_path,
				WDF_NO_OBJECT_ATTRIBUTES,
				&config,
				WDF_NO_HANDLE); // hDriver optional
			if (!NT_SUCCESS(status)) {
				KdPrint(("WdfDriverCreate failed with status 0x%x\n", status));
			}
			return status;
		}
		static NTSTATUS WdfInit(PDRIVER_OBJECT drv_object, PUNICODE_STRING drv_regpath, DWORD Type)
		{
			NTSTATUS ns = STATUS_NOT_IMPLEMENTED;
			switch (Type)
			{
			case WDF_NOPNP:
				ns = ddk::wdf::WdfCreateNoPnp(drv_object, drv_regpath);
				break;
			case WDF_FILTER_OR_DEVICE:
				ns = ddk::wdf::WdfCreateFilter(drv_object, drv_regpath);
				break;
			default:
				break;
			}
			return ns;
		}

	};
};
