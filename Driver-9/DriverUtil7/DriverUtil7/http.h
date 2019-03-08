#pragma once
#include "Base.h"
#include "wsk_socket.h"
#include <string>
#include <map>
#include <vector>
namespace ddk
{

	static const auto MOZZILA_USER_AGENT = "Mozilla / 5.0 (Windows NT 6.3; WOW64) AppleWebKit / 537.36 (KHTML, like Gecko) Chrome / 41.0.2272.118 Safari / 537.36";

	static const auto MS_SYMBOL_SERVER_USER_AGENT = "Microsoft-Symbol-Server";

	static const auto MS_SYMBOL_SERVER = "msdl.microsoft.com";

	static const auto MS_SYMBOL_SERVER_DOWNLOAD_URI = "/download/symbols";

	static const auto MAX_HTTP_URI_LEN = 256;

	static const auto HTTP_CONTENT_LENGTH = "content-length";
	
	class http_response
	{
	public:
		http_response()
		{
			m_Pos = 0;
			TotalSize = 0;
			m_Content = 0;
			_content_size = 0;
		}
		~http_response()
		{

		}
		void Get(CWSK_TcpClient *pClient)
		{
			m_Pos = 0;
			TotalSize = 0;
			while (1)
			{
				BYTE nBuf[PAGE_SIZE] = { 0 };
				ULONG RecvSize = 0;
				auto bRet = pClient->recv(nBuf, PAGE_SIZE, RecvSize);
				if (!bRet)
				{
					break;
				}
				if (RecvSize==0)
				{
					break;
				}
				TotalSize += RecvSize;
				m_data.resize(TotalSize);
				RtlCopyMemory(&m_data[m_Pos], nBuf, RecvSize);
				m_Pos += RecvSize;
			}
			m_Pos = 0;
			
		}

		PVOID getData() {
			return &m_data[0];
		}
		ULONG getSize() {
			return TotalSize;
		}
		PVOID getContent() {
			return &m_data[m_Content];
		}
		ULONG getContentSize() {
			return _content_size;
		}
		void Parse()
		{
			while (1)
			{
				std::string line = "";
				auto line_size = readline(line);
				//200 OK
				//DBG_PRINT("Parse %s\r\n", line.c_str());
				if (line.find("HTTP/1.1")!=std::string::npos)
				{
					continue;
				}
				auto pos = line.find(":");
				if (pos==std::string::npos)
				{
					break;
				}
				std::string head_string = "";
				std::string sub = "";
				sub = line.substr(pos+1);
				head_string = line.substr(0, pos);
				std::transform(head_string.begin(), head_string.end(), head_string.begin(), ::tolower);
				//DBG_PRINT("parsing %s %s\r\n", head_string.c_str(), sub.c_str());
				header[head_string] = sub;
			}
			if (header.find(HTTP_CONTENT_LENGTH) != header.end())
			{
				DBG_PRINT("get it\r\n");
				m_Content = m_Pos;
				RtlCharToInteger(header[HTTP_CONTENT_LENGTH].c_str(), 10, &_content_size);
			}

		}
		std::string & operator [](const std::string key)
		{
			auto p = header.find(key);
			if (p == header.end())
			{
				header[key] = "";
			}
			return header[key];
		}
	private:
		std::map<std::string, std::string> header;
		std::vector<BYTE> m_data;
		LONG m_Pos;
		LONG m_Content;
		ULONG _content_size;
		ULONG TotalSize;
	private:
		size_t readline(std::string &line)
		{
			line = "";
			auto pos = m_Pos;
			while (pos<TotalSize)
			{
				char sz[2] = {};
				auto pBuf = reinterpret_cast<CHAR*>(&m_data[pos]);
				sz[0] = pBuf[0];
				sz[1] = 0;
				if (sz[0] != 0
					&& sz[0] != '\n'
					&& sz[0] != '\r')
				{
					line += std::string(sz);
				}
				if(sz[0]=='\n' || sz[0]==0)
				{
					pos++;
					break;
				}
				pos++;
			}
			m_Pos = pos;
			return line.length();
		}
	};
	class http_request
	{
	public:
		http_request()
		{
			request_header["Host"] = "";
			request_header["User-Agent"] = "Mozilla / 5.0 (Windows NT 6.3; WOW64) AppleWebKit / 537.36 (KHTML, like Gecko) Chrome / 41.0.2272.118 Safari / 537.36";
			request_header["Connection"] = "close";
			request_header["Accept"] = "*/*";
			request_header["Cookie"] = "";
		}
		~http_request() {};
		std::string & operator [](const std::string &key)
		{
			auto p = request_header.find(key);
			if (p == request_header.end())
			{
				request_header[key] = "";
			}
			return request_header[key];
		}
		void getRequest(std::string &request,std::string page)
		{
			request = std::string("GET") + " " + page + " HTTP/1.1\r\n";
			for (auto item :request_header)
			{
				if(item.second.length()>1)
					request += item.first + ": " + item.second + "\r\n";
			}
			request += "\r\n";
		}
	private:
		std::map<std::string, std::string> request_header;
	};
	
	class http_client
	{
	public:
		http_client() {

		}
		~http_client() {
			sock.shutdown();
		}
		bool open(std::string host, std::string agent)
		{
			request["User-Agent"] = agent;
			request["Host"] = host;
			UNICODE_STRING nsString;
			ANSI_STRING asString;
			wchar_t nhost[MAX_PATH] = {};
			RtlInitAnsiString(&asString, host.c_str());
			RtlInitEmptyUnicodeString(&nsString, nhost, sizeof(nhost));
			RtlAnsiStringToUnicodeString(&nsString, &asString, FALSE);
			DBG_PRINT("host %ws\r\n", nhost);
			auto b = sock.connect(std::wstring(nhost), L"80");
			return b;
		}
		bool get(std::string uri, http_response &httpResponse)
		{
			std::string s_requset;
			request.getRequest(s_requset, uri);
			DBG_PRINT("http %s\r\n",s_requset.c_str());
			PVOID send_buff = malloc(s_requset.length() + MAX_PATH);
			if (send_buff)
			{
				ULONG sendSize = s_requset.length();
				ULONG sent = 0;
				RtlCopyMemory(send_buff, s_requset.c_str(), sendSize);
				auto b= sock.send(send_buff, sendSize, sent);
				if (b)
				{
					//开始http收包处理
					httpResponse.Get(&sock);
					httpResponse.Parse();
					return true;
				}
			}
			return false;
		}
	private:
		CWSK_TcpClient sock;
		http_request request;
	};
};