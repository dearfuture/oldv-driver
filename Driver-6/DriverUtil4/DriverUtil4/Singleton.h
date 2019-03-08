#pragma once
namespace ddk
{
	template<class T>
	class Singleton
	{
	public:
		Singleton()
		{
		}
		~Singleton()
		{
		}
	private:
		Singleton(const Singleton<T>&) = delete;
		Singleton& operator = (const Singleton<T>&) = delete;
	public:
		static T &getInstance()
		{
			static T ms_pSingleton;
			return ms_pSingleton;
		}
		static T *instance()
		{
			return &getInstance();
		}
	};
};