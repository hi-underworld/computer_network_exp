/*
* THIS FILE IS FOR IP TEST
*/
// system support
#include "sysInclude.h"

extern void ip_DiscardPkt(char* pBuffer,int type);

extern void ip_SendtoLower(char*pBuffer,int length);

extern void ip_SendtoUp(char *pBuffer,int length);

extern unsigned int getIpv4Address();

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
}; 

unsigned short ipcksum(unsigned short *buf, unsigned int nwords)
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


int stud_ip_recv(char *pBuffer,unsigned short length)
{
    int version = pBuffer[0] >> 4;  
    int headLength = pBuffer[0] & 0xf; 
	int TTL = (unsigned short)pBuffer[8]; 
	int headCheckSum = ntohs(*(unsigned short *)(pBuffer + 10));
	int dstAddr = ntohl(*(unsigned int*)(pBuffer + 16));
	
	//TTLֵ����
	if (TTL <= 0){
		ip_DiscardPkt(pBuffer, STUD_IP_TEST_TTL_ERROR);
		return 1;
	}
	
	//IP�汾�Ŵ�
	if (version != 4){
		ip_DiscardPkt(pBuffer, STUD_IP_TEST_VERSION_ERROR);
		return 1;
	}
	
	//ͷ�����ȴ�
	if (headLength < 5){
		ip_DiscardPkt(pBuffer, STUD_IP_TEST_HEADLEN_ERROR);
		return 1;
	}
	
	//Ŀ�ĵ�ַ��
	if (dstAddr != getIpv4Address() && dstAddr != 0xffff){
		ip_DiscardPkt(pBuffer,STUD_IP_TEST_DESTINATION_ERROR);  
		return 1;
	}
	
	//У��ʹ�Ӧ�����������
	unsigned short sum = 0; 
	unsigned short tempNum = 0; 
	for (int i = 0; i < headLength * 2; i++){
		tempNum = ((unsigned char)pBuffer[i*2]<<8) + (unsigned char)pBuffer[i*2 + 1];
		if (0xffff - sum < tempNum)
			sum = sum + tempNum + 1;
		else
			sum = sum + tempNum;
	}
	if (sum != 0xffff){
		ip_DiscardPkt(pBuffer, STUD_IP_TEST_CHECKSUM_ERROR);
		return 1;
	}
 
	//�ɹ�����
 	ip_SendtoUp(pBuffer,length); 
	return 0;
}
 
int stud_ip_Upsend(char *pBuffer,unsigned short len,unsigned int srcAddr,
				   unsigned int dstAddr,byte protocol,byte ttl)
{
	char *IPBuffer = (char *)malloc((20 + len) * sizeof(char));
	memset(IPBuffer, 0, len+20);  
	IPBuffer[0] = 0x45;	//�汾��+ͷ����
	unsigned short totalLength =  htons(len + 20);	//�����ܳ���
	memcpy(IPBuffer + 2, &totalLength, 2);
	IPBuffer[8] = ttl;  	//ttl
	IPBuffer[9] = protocol; //Э��
      
	unsigned int src = htonl(srcAddr);  
	unsigned int dis = htonl(dstAddr);  
	memcpy(IPBuffer + 12, &src, 4);  //Դ��Ŀ��IP��ַ
	memcpy(IPBuffer + 16, &dis, 4);  
      
	unsigned short sum = 0; 
	unsigned short tempNum = 0; 
	unsigned short headCheckSum = 0;
 
	//����checksum
	for (int i = 0; i < 10; i++){
		tempNum = ((unsigned char)IPBuffer[i*2]<<8) + (unsigned char)IPBuffer[i*2 + 1];
		if (0xffff - sum < tempNum)
			sum = sum + tempNum + 1;
		else
			sum = sum + tempNum;
	}
	headCheckSum = htons(0xffff - sum);  
	memcpy(IPBuffer + 10, &headCheckSum, 2);  
	memcpy(IPBuffer + 20, pBuffer, len);    
	ip_SendtoLower(IPBuffer,len+20);  
	return 0;  
}

//
//int stud_ip_recv(char * pBuffer, unsigned short length)
//{
//
//	ippkt_struc   *pstIP;
//	int headlen;
//
//	pstIP = (ippkt_struc *)pBuffer;
//
//	// implemented by students
//
//
//
//
//}
//
//int stud_ip_Upsend(char* pBuffer, unsigned short len, unsigned int  srcAddr,
//				   unsigned int dstAddr, byte  protocol, byte  ttl)
//{
//	char buf[1500];
//	ippkt_struc   *pstIP;
//
//           // implemented by students
//	
//
//
//
//}