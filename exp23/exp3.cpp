/*
* THIS FILE IS FOR IP FORWARD TEST
*/
#include "sysinclude.h"
#include<vector>
using std::vector;

// system support
extern void fwd_LocalRcv(char *pBuffer, int length);

extern void fwd_SendtoLower(char *pBuffer, int length, unsigned int nexthop);

extern void fwd_DiscardPkt(char * pBuffer, int type);

extern unsigned int getIpv4Address( );


// implemented by students
struct route_table
{
 	int dest;
 	int nexthop;
 	int masklen;
};
vector<route_table> mytable;               //·�ɱ�
 
 
void stud_Route_Init()
{
 mytable.clear();                       //���·�ɱ�
 return;
}



typedef struct stud_route_node
{
	stud_route_msg  stRt;
	struct stud_route_node *pnext;
} stud_route_node;

typedef struct ippkt_struc
{
	char verhlen; 
	char tos; 
	unsigned short totallen; 
	unsigned short id; 
	unsigned short flagoff; 
	unsigned char ttl; 
	char protocol; 
	unsigned short cksum; 
	long srcadd; 
	long dstadd; 
}ippkt_struc; 


stud_route_node *g_routetable;


unsigned short stud_ipf_cksum(unsigned short *buf, int nwords)
{
	unsigned long sum;
	int k;

	sum=0;
	if (nwords < 0)
	{
		return 0;
	}
	for(k=0; k<nwords; k++)
	{

		sum += (unsigned short)(*buf++);

		if (sum & 0xFFFF0000)
		{
			sum=(sum>>16)+(sum & 0x0000ffff);	
		}

	}
	sum=(sum>>16)+(sum & 0xffff);
	sum+=(sum>>16);
	return htons((unsigned short)(~sum));
}


//void stud_Route_Init()
//{
//	g_routetable = NULL;
//	return;
//}


unsigned int stud_BestRoute(unsigned int dest)
{
	stud_route_msg *bestrt;
	stud_route_node *pnode;
	int masklen, maxlen = 0;

	bestrt = NULL;
	pnode = g_routetable;
	while(pnode)
	{
		masklen = pnode->stRt.masklen;
		if (masklen >= maxlen)
			if ((pnode->stRt.dest >> (32-masklen)) == (dest >> (32-masklen)))
			{
				maxlen = masklen;
				bestrt = &(pnode->stRt);
			}
			pnode = pnode->pnext;
	}

	if (bestrt)
		return bestrt->nexthop;
	else
		return 0;
}


void stud_route_add(stud_route_msg *proute)		// ���һ���µı���
{
 	route_table t;
 	// ����Ŀ�ĵ�ַ
 	t.dest = ntohl(proute->dest);
 	t.masklen = proute->masklen;
 	// ������һ��
 	t.nexthop=ntohl(proute->nexthop);
 	// �������
 	mytable.push_back(t);
    return;
}
 
 
int stud_fwd_deal(char *pBuffer, int length)
{
	// ͷ������
 	int IHL = pBuffer[0] & 0xf;
 	// TTL
 	int TTL = (int)pBuffer[8];
 	// ͷ��У���
 	int Head_Checksum = ntohs(*(unsigned short*)(pBuffer+10));
 	// Ŀ��IP��ַ
 	int Dst_IP=ntohl(*(unsigned int*)(pBuffer+16)); 
 
 	// ���������ַ����Ŀ��IP��ַ
 	if (Dst_IP == getIpv4Address())
 	{	
 		// �����ļ�
  		fwd_LocalRcv(pBuffer,length);
  		return 0;
 	}
 
 	// ���TTL = 0
 	if(TTL<=0)
 	{
 		// ����
  		fwd_DiscardPkt(pBuffer, STUD_FORWARD_TEST_TTLERROR);
  		return 1;
 	}
 
 	// ����·�ɱ�
 	vector<route_table>::iterator ii;
 	for(ii = mytable.begin(); ii!=mytable.end(); ii++)
 	{	
 
 		// �������Ŀ�ĵ�ַ
  		if((ii->dest&((1<<31)>>(ii->masklen - 1)))== (Dst_IP&((1<<31)>>(ii->masklen - 1))))
  		{
			
			
   			char *buffer=new char[length];
   			memcpy(buffer,pBuffer,length);
   			// TTL-1
   			buffer[8]--;
   			// �����ײ�У���
   			int sum=0,i=0;
   			unsigned short Local_Checksum=0;
   			for(; i<2*IHL; i++)
   			{
    			if(i!=5)
    			{
     				sum+=(buffer[2*i]<<8)+(buffer[2*i+1]);
     				sum%=65535;
    			}
   			}
   			Local_Checksum=htons(0xffff-(unsigned short)sum);
   			memcpy(buffer+10, &Local_Checksum, 2);
   			// �������һ��
   			fwd_SendtoLower(buffer, length, ii->nexthop);
   			return 0;
  		}
 	}
 	// û��·����
 	fwd_DiscardPkt(pBuffer,STUD_FORWARD_TEST_NOROUTE);
 	return 1;
}


//void stud_route_add(stud_route_msg *proute)
//{
//	stud_route_node *pstRt=NULL;
//	pstRt = (stud_route_node *)malloc(sizeof(stud_route_node));
//
//        // implemented by students
//	
//
//
//}
//
//
//
//
//int stud_fwd_deal(char * pBuffer, int length)
//{
//	ippkt_struc *pkt = (ippkt_struc *)pBuffer;
//	unsigned int nexthop;
//
//               // implemented by students
//
//
//
//}

