#pragma once
#include "Base.h"
#include <functional>
namespace ddk
{
	namespace KSOCKET
	{
#include "3rd/ksocket/ksocket.h"
	}

	class CTDI_Client
	{
	private:
		INT_PTR m_sock;
	public:
		CTDI_Client():m_sock(0)
		{

		}
		CTDI_Client(INT_PTR Socket)
		{
			if (Socket != 0 && Socket != -1)
				m_sock = Socket;
		}
		~CTDI_Client()
		{
			if (m_sock != 0 && m_sock != -1)
			{
				KSOCKET::close(m_sock);
				m_sock = 0;
			}
		}
		CTDI_Client & operator = (CTDI_Client & client)
		{
			this->m_sock = client.get_sock();
			client.clear_sock();
			return *this;
		}
		INT_PTR get_sock()
		{
			return m_sock;
		}
		void clear_sock()
		{
			m_sock = 0;
		}
		BOOL Connect(LPCSTR lpIp, UINT nPort)
		{
			if (m_sock != 0 && m_sock != -1)
			{
				return FALSE;
			}
			struct KSOCKET::sockaddr_in  toAddr;
			int status = 0;
			int i = 0;
			m_sock = KSOCKET::socket(AF_INET, SOCK_STREAM, 0);
			if (m_sock == -1)
			{
				DBG_PRINT("client: socket() error\r\n");
				return FALSE;
			}
			toAddr.sin_family = AF_INET;
			toAddr.sin_port = KSOCKET::htons(USHORT(nPort));//7792¶Ë¿Ú
			toAddr.sin_addr.s_addr = KSOCKET::inet_addr(lpIp);

			status = KSOCKET::connect(m_sock, (struct KSOCKET::sockaddr*)&toAddr, sizeof(toAddr));
			if (status < 0)
			{
				DBG_PRINT("client failed\r\n");
				KSOCKET::close(m_sock);
				m_sock = 0;
				return FALSE;
			}

			return TRUE;
		}
		int Send(LPVOID Buffer, UINT nBufferSize)
		{
			if (m_sock == 0 || m_sock == -1)
			{
				return 0;
			}
			int status = KSOCKET::send(m_sock, (const char *)Buffer, nBufferSize, 0);
			if (status < 0)
			{
				DBG_PRINT("failed to send\r\n");
				return 0;
			}
			return status;
		}
		int Recv(PVOID outBuffer, UINT nSize)
		{
			if (m_sock == 0 || m_sock == -1)
			{
				return 0;
			}
			int st = KSOCKET::recv(m_sock, (char *)outBuffer, nSize, 0);
			if (st < 0)
			{
				return 0;
			}
			return st;
		}
		void Clear()
		{
			if (m_sock&&m_sock != -1)
			{
				KSOCKET::close(m_sock);
				m_sock = 0;
			}
		}
	};
	class CTDI_Server
	{
	private:
		INT_PTR m_sock_srv;
	public:
		using _callback_accept = std::function<void(INT_PTR)>;
		CTDI_Server():m_sock_srv(0)
		{
			pfn_callback_on_accept = nullptr;
		}
		~CTDI_Server()
		{
			if (m_sock_srv != 0 && m_sock_srv != -1)
			{
				KSOCKET::close(m_sock_srv);
			}
		}
		BOOL Bind(USHORT nPort)
		{
			if (m_sock_srv&&m_sock_srv != -1)
			{
				return FALSE;
			}
			struct KSOCKET::sockaddr_in  localAddr;
			int  rVal;

			m_sock_srv = KSOCKET::socket(AF_INET, SOCK_STREAM, 0);

			if (m_sock_srv == -1)
			{
				DBG_PRINT("server: socket() error\n");
				return FALSE;
			}

			localAddr.sin_family = AF_INET;
			localAddr.sin_port = KSOCKET::htons(nPort);//¶Ë¿Ú7792
			localAddr.sin_addr.s_addr = INADDR_ANY;

			rVal = KSOCKET::bind(m_sock_srv, (struct KSOCKET::sockaddr*) &localAddr, sizeof(localAddr));

			if (rVal < 0)
			{
				DBG_PRINT("server: bind error %#x\r\n", rVal);
				KSOCKET::close(m_sock_srv);
				m_sock_srv = 0;
				return FALSE;
			}

			rVal = KSOCKET::listen(m_sock_srv, SOMAXCONN);

			if (rVal < 0)
			{
				DBG_PRINT("server: listen error %#x\r\n", rVal);
				KSOCKET::close(m_sock_srv);
				m_sock_srv = 0;
				return FALSE;
			}
			return TRUE;
		}
		BOOL Accept(INT_PTR * Socket)
		{
			INT_PTR             reqSocket;
			struct KSOCKET::sockaddr_in  remoteAddr;
			int                 remoteLen = sizeof(remoteAddr);
			char                *addrStr;

			reqSocket = KSOCKET::accept(m_sock_srv, (struct KSOCKET::sockaddr*) &remoteAddr, &remoteLen);

			if (reqSocket != -1)
			{
#if 1
				addrStr = KSOCKET::inet_ntoa(remoteAddr.sin_addr);
				if (addrStr)
				{
					DBG_PRINT("server: connection from %s:%u\r\n", addrStr, KSOCKET::ntohs(remoteAddr.sin_port));
					ExFreePool(addrStr);
				}
#endif
				if (Socket)
				{
					*Socket = reqSocket;
				}
				return TRUE;
			}
			return FALSE;
		}
		void StartWorker(_callback_accept onAccept)
		{
			pfn_callback_on_accept = onAccept;
			if (m_sock_srv!=0 && m_sock_srv!=-1)
			{
				auto work_thread = ddk::CThread(std::bind(&ddk::CTDI_Server::worker_thread, this));
				work_thread.detach();
			}
		}
		void worker_thread()
		{
			while (1)
			{
				INT_PTR sock = 0;
				if (Accept(&sock))
				{
					pfn_callback_on_accept(sock);
				}
				else
				{
					break;
				}
			}
		}
	private:
		_callback_accept pfn_callback_on_accept;
	protected:
		CTDI_Server & operator = (CTDI_Server &) = delete;
	};
};


