#pragma once
namespace ddk
{
	template<class T>
	class Singleton
	{
	public:
		Singleton()
		{
			NT_ASSERT(ms_pSingleton == nullptr);
			ms_pSingleton = static_cast<T*>(this);
		}

		~Singleton()
		{
			NT_ASSERT(ms_pSingleton);
			ms_pSingleton = nullptr;
		}

	private:
		Singleton(const Singleton<T>&) = delete;
		Singleton& operator = (const Singleton<T>&) = delete;
	public:
		static T* Instance()
		{
			return ms_pSingleton;
		}
		static T* getInstance()
		{
			return ms_pSingleton;
		}
	protected:
		static T* ms_pSingleton;
	};
	template<class T>
	T* Singleton<T>::ms_pSingleton = nullptr;
};