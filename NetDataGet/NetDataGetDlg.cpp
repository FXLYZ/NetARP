
// NetDataGetDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "NetDataGet.h"
#include "NetDataGetDlg.h"
#include "afxdialogex.h"
#include "pcap.h"
#include<string>
using namespace std;
#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define WM_MYMESSAGE WM_USER+1

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
}

BEGIN_MESSAGE_MAP(CNetDataGetDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CNetDataGetDlg::OnBnClickedButtonStart)
	ON_BN_CLICKED(IDC_BUTTON3, &CNetDataGetDlg::OnBnClickedButtonStop)
	ON_MESSAGE(WM_MYMESSAGE, &CNetDataGetDlg::OnMymessage)
	ON_WM_TIMER()
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
			/*dnames[count] = d->name;
			dinfos[count] = d->description;
			NetWorkCardBox.InsertString(count,dnames[count]);
			a = d->addresses;
			addrs[count].addr = a->addr;
			addrs[count].netmask = a->netmask;
			addrs[count].broadaddr = a->broadaddr;
			addrs[count].dstaddr = a->dstaddr;
			count++;*/
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
				CString temp;
				NetWorkCardInfo.GetWindowTextW(temp);
				NetWorkCardInfo.SetWindowTextW(temp+addrInfo);
			}			
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
	int index=NetWorkCardBox.GetCurSel();

	USES_CONVERSION;
	string s(W2A(dnames[index]));
	const char* namecstr = s.c_str();
	pcap_addr* a=&addrs[index];

	char* ip4str="";
	char* netmask="";
	char* info = "";
	char ip6str[128];

	/*ip4str = "192.168.0.1";
	netmask = "255.255.255.0";*/

	switch (a->addr->sa_family)
	{
	case AF_INET:
		info = "Address Family Name: AF_INET";
		if (a->addr)
			ip4str = iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr);
		if (a->netmask)
			netmask = iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr);
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
	/*sockaddr_in* saddr = (sockaddr_in*)a->addr;
	char* IP=inet_ntoa(saddr->sin_addr);
	sockaddr_in* snetmask = (sockaddr_in*)a->netmask;
	char* netmask = inet_ntoa(snetmask->sin_addr);*/
	CString addrInfo;
	addrInfo.Format(L"%hs\r\nIP=%hs\r\nNetMask=%hs\r\n", info,ip4str, netmask);
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

	//ARPFrame_t  ARPFrame;
	////将ARPFrame.FrameHeader.DesMAC设置为广播地址。
	////将ARPFrame.FrameHeader.SrcMAC设置为本机网卡的MAC地址。
	//ARPFrame.FrameHeader.FrameTYPE= htons(0x0806);	//帧类型为ARP
	//ARPFrame.HardwareType = htons(0x0001);		//硬件类型为以太网
	//ARPFrame.ProtocolType = htons(0x0800);		//协议类型为IP
	//ARPFrame.HLen = 6;										//硬件地址长度为6
	//ARPFrame.PLen = 4;										//协议地址长度为4
	//ARPFrame.Operation = htons(0x0001);			//操作为ARP请求
	////将ARPFrame.SendHa设置为本机网卡的MAC地址。
	////将ARPFrame.SendIP设置为本机网卡上绑定的IP地址。
	////将ARPFrame.RecvHa设置为0。	
	////将ARPFrame.RecvIP设置为请求的IP地址;
	//if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t) != 0))
	//{
	//	NetWorkCardInfo.SetWindowTextW(L"发送ARP失败\n");
	//}
	//else
	//{

	//}
	NetWorkCardInfo.SetWindowTextW( dnames[index]+L"\r\n"+dinfos[index]+"\r\n"+addrInfo);
	CWinThread* MyThread = AfxBeginThread(TheCapture, adhandle, THREAD_PRIORITY_NORMAL, 0, 0, NULL);
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

UINT TheCapture(LPVOID pParam)
{
	msginfo* pinfo=new msginfo();
	struct tm* ltime;
	char timestr[16];
	struct pcap_pkthdr* header;
	const u_char* pkt_data;
	time_t local_tv_sec;
	pcap_t* adhandle=(pcap_t*)pParam;
	int res;
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
		if (res == 0)
			/* 超时时间到 */
			continue;
		/* 将时间戳转换成可识别的格式 */
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

		/*Data_t* IPPacket;
		ULONG SourceIP, DestinationIP;
		IPPacket = (Data_t*)pkt_data;

		SourceIP = ntohl(IPPacket->IPHeader.SrcIP);
		DestinationIP = ntohl(IPPacket->IPHeader.DstIP);
		int version = (IPPacket->IPHeader.Ver_HLen & 0xf0) >> 4;
		int hlen = (IPPacket->IPHeader.Ver_HLen & 0x0f);
		if (version==4)
		{
			char ID[4];
			char Checksum[4];
			_itoa(IPPacket->IPHeader.ID,ID,16);
			_itoa(IPPacket->IPHeader.Checksum, Checksum, 16);
			CString data;
			data.Format(L"%hs,%.6d  len:%d\r\n标识:%hs  头部校验和:%hs\r\n\r\n", timestr, header->ts.tv_usec, header->len,ID,Checksum);
			pinfo->content = data;
			AfxGetApp()->m_pMainWnd->PostMessageW(WM_MYMESSAGE, 0, (LPARAM)pinfo);
		}*/
	}
	if (res == -1) {
		CString data;
		data.Format(L"Error reading the packets: %hs\r\n", pcap_geterr(adhandle));
		pinfo->content = data;
		AfxGetApp()->m_pMainWnd->PostMessageW(WM_MYMESSAGE, 0, (LPARAM)pinfo);
	}
	return 0;
}
