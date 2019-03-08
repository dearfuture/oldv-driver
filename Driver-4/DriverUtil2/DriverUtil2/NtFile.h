#pragma once
#include <string>
#include <vector>
namespace ddk
{
	//文件操作
	//不支持流模式>> <<
	//readline
	//writeline

	class CNtFile
	{
	public:
		struct file_rec
		{
			DWORD file_attr;
			std::wstring file_name;
		};
		using file_list_type = std::vector<ddk::CNtFile::file_rec>;
		enum OPEN_TYPE
		{
			OPEN_EXIST=1,
			CREATE_NEW,
			OPEN_IF,
		};
		enum SEEK_TYPE
		{
			FILE_BEGIN=1,
			FILE_END,
			CURRENT_OFFSET,
		};
		CNtFile();
		~CNtFile();
		CNtFile(std::wstring strFile, OPEN_TYPE type = OPEN_EXIST);
		bool seek(LONGLONG distance, SEEK_TYPE type);
		bool open(std::wstring strFile);
		bool create(std::wstring strFile);
		static bool is_file_exist(std::wstring strFile);
		bool rename(std::wstring newFile);
		CNtFile & operator = (CNtFile &_file)
		{
			this->init_file();
			this->h_file = _file.get_handle();
			_file.set_rel();
			return (*this);
		}
		HANDLE get_handle()
		{
			return h_file;
		}
		void set_rel()
		{
			h_file = nullptr;
		}
	private:
		HANDLE h_file;
		LONGLONG file_offset;
		void init_file();
	public:
		bool open_if(std::wstring strFile);
		void set_file_append();
		LONGLONG get_file_size();
		bool set_file_size(LONGLONG file_size);
		bool is_eof();
		bool read(PVOID outBuffer, size_t out_size, size_t & read_size);
		bool write(PVOID in_buffer, size_t in_size, size_t & write_size);
		bool readline(std::string & strline);
		bool writeline(std::string strline);
		void close();
		static bool del_file(std::wstring strFile);
		static bool dir_file(std::wstring strDir,  file_list_type & file_list);
		bool set_file_attr(DWORD dwFileAttributes);
	};

}

