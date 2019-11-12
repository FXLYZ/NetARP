
// NetDataGetDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "NetDataGet.h"
#include "NetDataGetDlg.h"
#include "afxdialogex.h"
#include "pcap.h"
#include<string>
#include<iostream>
using namespace std;
#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define WM_MYMESSAGE WM_USER+1

#define ETH_IP 0X0800
#define ETH_ARP 0X0806
#define ARP_REQUEST 0X0001
#define ARP_REPLY 0X0002
#define ARP_HARDWARE 0X0001
#define max_num_adapter 10

#pragma pack(1)
struct arp_head
{
	unsigned short hardware_type; //硬件类型
	unsigned short protocol_type; //协议类型
	unsigned char hardware_add_len; //硬件地址长度
	unsigned char protocol_add_len; //协议地址长度
	unsigned short operation_field; //操作字段
	unsigned char source_mac_add[6]; //源mac地址
	unsigned long source_ip_add; //源ip地址
	unsigned char dest_mac_add[6]; //目的mac地址
	unsigned long dest_ip_add; //目的ip地址
};
struct ethernet_head
{
	unsigned char dest_mac_add[6];
	unsigned char source_mac_add[6];
	unsigned short type; // 帧类型
};
struct arp_packet
{
	ethernet_head eh;
	arp_head ah;
};
#pragma pack()

//全局变量
u_char selfMac[6] = { 0 };
u_long myip;
int arpInfoCount = 0;


#pragma pack(1)
struct FrameHeader_t
{
	BYTE DesMAC[6];
	BYTE SrcMAC[6];
	WORD FrameTYPE;
};
struct IPHeader_t
{
	BYTE Ver_HLen;
	BYTE TOS;
	WORD TotalLen;
	WORD ID;
	WORD Flag_Segment;
	BYTE TTL;
	BYTE Protocol;
	WORD Checksum;
	ULONG SrcIP;
	ULONG DstIP;
};
struct Data_t
{
	FrameHeader_t  FrameHeader;
	IPHeader_t IPHeader;
};
struct ARPFrame_t
{
	FrameHeader_t FrameHeader;
	WORD HardwareType;
	WORD ProtocolType;
	BYTE HLen;
	BYTE PLen;
	WORD Operation;
	BYTE SendHa[6];
	DWORD SendIP;
	BYTE RecvHa[6];
	DWORD RecvIP;
};
#pragma pack()

CString MACstring(unsigned char mac[6])
{
	CString MAC;
	MAC.Format(L"%2x-%2x-%2x-%2x-%2x-%2x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return MAC;
}
CString IPstring(unsigned long ip)
{
	in_addr addr;
	memcpy(&addr, &ip, sizeof(ip));
	string strIp = inet_ntoa(addr);
	return CString(strIp.c_str());
}
// 用于应用程序“关于”菜单项的 CAboutDlg 对话框
/* 将数字类型的IP地址转换成字符串类型的 */
#define IPTOSBUFFERS    12
char* iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char* p;

	p = (u_char*)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

char* ip6tos(struct sockaddr* sockaddr, char* address, int addrlen)
{
	socklen_t sockaddrlen;

#ifdef WIN32
	sockaddrlen = sizeof(struct sockaddr_in6);
#else
	sockaddrlen = sizeof(struct sockaddr_storage);
#endif


	if (getnameinfo(sockaddr,
		sockaddrlen,
		address,
		addrlen,
		NULL,
		0,
		NI_NUMERICHOST) != 0) address = NULL;

	return address;
}

/*获取自己的主机的IP地址和MAC地址*/
CString GetSelfMac(pcap_t* adhandle, string desIP)
{
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	unsigned char sendbuf[42] = { 0 }; // 发送缓冲区，也是arp包的大小
	int i = -1;
	int res;
	ethernet_head eh;
	arp_head ah;


	memset(eh.dest_mac_add, 0xff, 6);
	memset(eh.source_mac_add, 0x00, 6);

	memset(ah.source_mac_add, 0x00, 6);
	memset(ah.dest_mac_add, 0x00, 6);

	eh.type = htons(ETH_ARP);
	ah.hardware_type = htons(ARP_HARDWARE);
	ah.protocol_type = htons(ETH_IP);
	ah.hardware_add_len = 6;
	ah.protocol_add_len = 4;
	ah.source_ip_add = inet_addr("0.0.0.0"); //源ip地址位任意的ip地址
	ah.operation_field = htons(ARP_REQUEST);
	ah.dest_ip_add = inet_addr(desIP.c_str());

	memset(sendbuf, 0, sizeof(sendbuf));
	memcpy(sendbuf, &eh, sizeof(eh));
	memcpy(sendbuf + sizeof(eh), &ah, 14);
	memcpy(sendbuf + sizeof(eh) + 14, &ah.source_ip_add, 10);
	memcpy(sendbuf + sizeof(eh) + 24, &ah.dest_ip_add, 4);

	if (pcap_sendpacket(adhandle, sendbuf, 42) == 0)
		cout << "发送arp包成功" << endl;
	else
		cout << "发送arp包失败" << GetLastError() << endl;

	//得到包的回复
	while ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) > 0)
	{
		if (*(unsigned short*)(pkt_data + 12) == htons(ETH_ARP) &&
			*(unsigned short*)(pkt_data + 20) == htons(ARP_REPLY) &&
			*(unsigned long*)(pkt_data + 38) == inet_addr("0.0.0.0"))
		{
			cout << "本机网卡物理地址：";
			for (i = 0; i < 5; i++)
			{
				selfMac[i] = *(unsigned char*)(pkt_data + 22 + i);
				cout << selfMac[i];
			}

			selfMac[i] = *(unsigned char*)(pkt_data + 22 + i);
			cout << selfMac[i] << endl;
			myip = *(unsigned long*)(pkt_data + 28);
			break;
		}
	}
	CString MAC = MACstring(selfMac);
	CString IP = IPstring(myip);
	if (res == 0)
		cout << "超时！接收网络包超时" << endl;

	if (res == -1)
		cout << "读取网络包时错误" << endl;

	if (i == 5)
		return MAC+L"\r\n"+IP+L"\r\n";
	else
		return CString("EORR") ;
}
class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CNetDataGetDlg 对话框



CNetDataGetDlg::CNetDataGetDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_NETDATAGET_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CNetDataGetDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT3, DataContent);
	DDX_Control(pDX, IDC_LIST1, NetWorkCardBox);
	DDX_Control(pDX, IDC_EDIT2, NetWorkCardInfo);
	DDX_Control(pDX, IDC_BUTTON1, StartCatch);
	DDX_Control(pDX, IDC_BUTTON3, StopCatch);
	DDX_Control(pDX, IDC_EDIT1, MACinfo);
	DDX_Control(pDX, IDC_IPADDRESS1, DesIPAddr);
}

BEGIN_MESSAGE_MAP(CNetDataGetDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CNetDataGetDlg::OnBnClickedButtonStart)
	ON_BN_CLICKED(IDC_BUTTON3, &CNetDataGetDlg::OnBnClickedButtonStop)
	ON_MESSAGE(WM_MYMESSAGE, &CNetDataGetDlg::OnMymessage)
	ON_WM_TIMER()
	ON_BN_CLICKED(IDC_BUTTON2, &CNetDataGetDlg::OnBnClickedSend)
END_MESSAGE_MAP()


// CNetDataGetDlg 消息处理程序

BOOL CNetDataGetDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	pcap_if_t* alldevs; 	               //指向设备链表首部的指针
	pcap_if_t* d;
	pcap_addr_t* a;
	char		errbuf[PCAP_ERRBUF_SIZE];	//错误信息缓冲区
	//获得本机的设备列表
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, 	//获取本机的接口设备
		NULL,			       //无需认证
		&alldevs, 		       //指向设备列表首部
		errbuf			      //出错信息保存缓存区
	) == -1)
	{
		NetWorkCardInfo.SetWindowTextW(L"获取网卡失败");
	}
	else
	{
		addrs = new pcap_addr[20];
		int count = 0;
		for (d = alldevs; d != NULL; d = d->next)
		{
			dnames[count] = d->name;
			dinfos[count] = d->description;
			NetWorkCardBox.InsertString(count,dnames[count]);
			count++;
			CString num;
			num.Format(L"%d", count);
			CString temp;
			NetWorkCardInfo.GetWindowTextW(temp);
			NetWorkCardInfo.SetWindowTextW(temp + "------------------------------------\r\n网卡序号："+num+"\r\n"+d->name+"\r\n"+d->description+"\r\n");

			for (a=d->addresses; a!=NULL; a=a->next)
			{
				char* ip4str = "";
				char* netmask = "";
				char* info = "";
				char ip6str[128];

				switch (a->addr->sa_family)
				{
				case AF_INET:
					info = "Address Family Name: AF_INET";
					if (a->addr)
						ip4str = iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr);
					if (a->netmask)
						netmask = iptos(((struct sockaddr_in*)a->netmask)->sin_addr.s_addr);
					if (a->broadaddr)
						printf("\tBroadcast Address: %s\n", iptos(((struct sockaddr_in*)a->broadaddr)->sin_addr.s_addr));
					if (a->dstaddr)
						printf("\tDestination Address: %s\n", iptos(((struct sockaddr_in*)a->dstaddr)->sin_addr.s_addr));
					break;
				case AF_INET6:
					info = "Address Family Name: AF_INET6";
					if (a->addr)
					{
						ip6tos(a->addr, ip6str, sizeof(ip6str));
						ip4str = ip6str;
					}
					break;
				default:
					info = "Address Family Name: Unknown";
					break;
				}
				CString addrInfo;
				addrInfo.Format(L"%hs\r\nIP=%hs\r\nNetMask=%hs\r\n", info, ip4str, netmask);
				NetWorkCardInfo.GetWindowTextW(temp);
				NetWorkCardInfo.SetWindowTextW(temp+addrInfo);
			}
			NetWorkCardInfo.GetWindowTextW(temp);
			NetWorkCardInfo.SetWindowTextW(temp + "\r\n------------------------------------\r\n");

		}
	}
	pcap_freealldevs(alldevs);
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CNetDataGetDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CNetDataGetDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CNetDataGetDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

UINT TheCapture(LPVOID pParam);
void CNetDataGetDlg::OnBnClickedButtonStart()
{
	// TODO: 在此添加控件通知处理程序代码
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	//抓包
	int index = NetWorkCardBox.GetCurSel();

	USES_CONVERSION;
	string s(W2A(dnames[index]));
	const char* namecstr = s.c_str();

	//pcap_addr* a=&addrs[index];
	if ((adhandle = pcap_open(namecstr,          // 设备名
		65536,            // 要捕捉的数据包的部分 
						  // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
		1000,             // 读取超时时间
		NULL,             // 远程机器验证
		errbuf            // 错误缓冲池
	)) == NULL)
	{
		DataContent.SetWindowTextW(L"获取网卡失败");
		return;
	}

	//静态设置
	string myip = "10.129.253.241";

	CString MAC = GetSelfMac(adhandle, myip);
	MACinfo.SetWindowTextW(MAC);
}
void CNetDataGetDlg::OnBnClickedButtonStop()
{
	// TODO: 在此添加控件通知处理程序代码
	//停止抓包
	//WaitForSingleObject(MyThread, INFINITE);
}

struct msginfo
{
	CString content;
};

afx_msg LRESULT CNetDataGetDlg::OnMymessage(WPARAM wParam, LPARAM lParam)
{
	msginfo* info = (msginfo*)lParam;
	CString temp;
	DataContent.GetWindowTextW(temp);
	DataContent.SetWindowTextW(temp +info->content);
	return 0;
}

void CNetDataGetDlg::OnTimer(UINT_PTR nIDEvent)
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	CDialogEx::OnTimer(nIDEvent);
}
struct arpAccept
{
	pcap_t* adhandle;
	u_long desIP;
};
struct pc
{
	unsigned long ip;
	unsigned char mac[6];
}pcGroup[10000];
CString arpInfo(arp_head arp)
{
	arpInfoCount++;
	CString sip = IPstring(arp.source_ip_add);
	CString smac = MACstring(arp.source_mac_add);
	CString dip = IPstring(arp.dest_ip_add);
	CString dmac = MACstring(arp.dest_mac_add);
	CString info;
	info.Format(L"\r\nARP序号%d\r\n------------\r\nSourceIP=%s   SourceMAC=%s\r\nDesIP=%s  DesMac=%s\r\n------------\r\n", arpInfoCount,sip, smac, dip, dmac);
	return info;
}
UINT TheCapture(LPVOID pParam)
{
	int res;
	struct pcap_pkthdr* pkt_header;
	const u_char* pkt_data;
	unsigned char tempMac[6];
	arpAccept* accept = ((arpAccept*)pParam);
	pc target;
	while (TRUE)
	{
		if ((res = pcap_next_ex(accept->adhandle, &pkt_header, &pkt_data)) > 0)
		{
			if (*(unsigned short*)(pkt_data + 12) == htons(ETH_ARP) &&
				*(unsigned short*)(pkt_data + 20) == htons(ARP_REPLY) &&
				*(unsigned long*)(pkt_data + 38) == myip/*&& 
				*(unsigned long*)(pkt_data + 28)==accept->desIP*/)
			{
				arp_packet* recv = (arp_packet*)pkt_data;
				CString data= arpInfo(recv->ah);
				msginfo* pinfo = new msginfo();
				pinfo->content = L"捕获ARP"+data;
				AfxGetApp()->m_pMainWnd->PostMessageW(WM_MYMESSAGE, 0, (LPARAM)pinfo);
				break;
			}
		}
	}
	return 0;
}

//发送arp请求
unsigned int sendArpPacket(pcap_t* adhandle,u_long desIP)
{
	unsigned char sendbuf[42] = {0};
	unsigned long ip;
	const char iptosendh[20] = { 0 };
	ethernet_head eh;
	arp_head ah;

	memset(eh.dest_mac_add, 0xff, 6);
	memcpy(eh.source_mac_add, selfMac, 6);

	memcpy(ah.source_mac_add, selfMac, 6);
	memset(ah.dest_mac_add, 0x00, 6);

	eh.type = htons(ETH_ARP);
	ah.hardware_type = htons(ARP_HARDWARE);
	ah.protocol_type = htons(ETH_IP);
	ah.hardware_add_len = 6;
	ah.protocol_add_len = 4;
	ah.source_ip_add = myip;
	ah.operation_field = htons(ARP_REQUEST);
	ah.dest_ip_add = desIP;

	memset(sendbuf, 0, sizeof(sendbuf));
	memcpy(sendbuf, &eh, sizeof(eh));
	memcpy(sendbuf + sizeof(eh), &ah, 14);
	memcpy(sendbuf + sizeof(eh) + 14, &ah.source_ip_add, 10);
	memcpy(sendbuf + sizeof(eh) + 24, &ah.dest_ip_add, 4);
	if (pcap_sendpacket(adhandle, sendbuf, 42) == 0)
	{
		//接受ARP线程

		arpAccept* accept = new arpAccept();
		accept->adhandle = adhandle;
		accept->desIP = desIP;
		CWinThread* MyThread = AfxBeginThread(TheCapture, accept, THREAD_PRIORITY_NORMAL, 0, 0, NULL);

		msginfo* pinfo = new msginfo();
		CString data;
		data.Format(L"发送ARP%s\r\n",arpInfo(ah));
		pinfo->content = data;
		AfxGetApp()->m_pMainWnd->PostMessageW(WM_MYMESSAGE, 0, (LPARAM)pinfo);
	}
	else
	{
		msginfo* pinfo = new msginfo();
		CString data;
		data.Format(L"发送ARP失败\r\n");
		pinfo->content = data;
		AfxGetApp()->m_pMainWnd->PostMessageW(WM_MYMESSAGE, 0, (LPARAM)pinfo);
	}
	return 0;
}
void CNetDataGetDlg::OnBnClickedSend()
{
	// TODO: 在此添加控件通知处理程序代码
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	//抓包
	int index = NetWorkCardBox.GetCurSel();
	USES_CONVERSION;
	string s(W2A(dnames[index]));
	const char* namecstr = s.c_str();
	//pcap_addr* a=&addrs[index];
	if ((adhandle = pcap_open(namecstr,          // 设备名
		65536,            // 要捕捉的数据包的部分 
						  // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,    // 混杂模式
		1000,             // 读取超时时间
		NULL,             // 远程机器验证
		errbuf            // 错误缓冲池
	)) == NULL)
	{
		DataContent.SetWindowTextW(L"获取网卡失败");
		return;
	}
	u_long desIP=0;
	DesIPAddr.GetAddress(desIP);
	desIP = htonl(desIP);
	//desIP = inet_addr("10.129.253.241");
	sendArpPacket(adhandle, desIP);
}
