#pragma once
#include "Base.h"
#include <functional>
#include <vector>
#include <algorithm>
namespace ddk
{
	class nt_image_callback:public Singleton<nt_image_callback>
	{
	public:
		using nt_image_callback_type = std::function<void(PUNICODE_STRING,HANDLE,PIMAGE_INFO)>;
		nt_image_callback() {
			ExInitializeRundownProtection(&run_for);
			PsSetLoadImageNotifyRoutine(ddk::nt_image_callback::_ImageLoadNotifyRoutine);
		}
		~nt_image_callback(){
			PsRemoveLoadImageNotifyRoutine(ddk::nt_image_callback::_ImageLoadNotifyRoutine);
			ExWaitForRundownProtectionRelease(&run_for);
			_callback.clear();
		}
		static VOID _ImageLoadNotifyRoutine(
			__in_opt PUNICODE_STRING  FullImageName,
			__in HANDLE  ProcessId,
			__in PIMAGE_INFO  ImageInfo
			)
		{
			ddk::nt_image_callback::getInstance().do_callback(FullImageName, ProcessId, ImageInfo);
		}
		void do_callback(
			__in_opt PUNICODE_STRING  FullImageName,
			__in HANDLE  ProcessId,
			__in PIMAGE_INFO  ImageInfo
			)
		{
			//ExWaitForRundownProtectionRelease(&run_for);
			ExAcquireRundownProtection(&run_for);
			std::for_each(
				_callback.cbegin(),
				_callback.cend(),
				[&](auto _pfn) {
				_pfn(FullImageName, ProcessId, ImageInfo);
			}
				);
			ExReleaseRundownProtection(&run_for);
		}
		void reg_callback(nt_image_callback_type callback)
		{
			_callback.push_back(callback);
		}
	private:
		EX_RUNDOWN_REF run_for;
		std::vector<nt_image_callback_type>_callback;
	};
};