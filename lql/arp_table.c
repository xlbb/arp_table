#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#define STRMAX 256
typedef struct ListNode
{
	char ip_addr[256];  //IP_Address
	char mac_addr[256]; //MAC_Address
	int  type;          //static or dynamic 
	int  timeout;       //timeout
	struct ListNode *next;
}Linklist;
//========= public varible   =============
Linklist *head;
int TIMEOUT= 10000;
//======== static =======================	
const char *errorCode="Fail:wrong input,please check your input format";
const char *cmdHelp="cmd:-a or -s or -d  or -t";
const char *potocol_cnt="ARP";
const char *potocol_low_cnt="arp";
const char *cmdChar_cnt="asdtASDT";
const int   Period_cnst= 5; // refresh the timeout
//==============public varibles============
char _potocol[256];
char _cmd[256];
char _ip[256];
char _mac[256];
int  _type;
int _timeout;
Linklist* CreateList()
{
	Linklist *head = (struct ListNode *)malloc(sizeof(struct ListNode));
	head->next = NULL;
	return head;
}
int ListEmpty(Linklist *head)
{
	if(!head->next)
		return 0;
	else
		return 1;
}
int Judge_ip(char * ip) //check the ip format is XX.XX.XX.XX
{
	int a[4]={0,0,0,0};
	int cnt=0;
	char b[4];
	strcpy(b,"");
	int i=0,j=0;
	for(i=0,j=0;i<strlen(ip);i++)
	{
		if(!(('0'<=*(ip+i)&&*(ip+i)<='9')||*(ip+i)=='.'))
		{
			printf("%s\n",errorCode);
			return 0;
		}
		if(j==4)
		{
			printf("%s\n",errorCode);
			return 0;
		}
		if(*(ip+i)!='.'){
			b[j]=*(ip+i);
			j++;
		}
		else
		{
			b[j]='\0';
			a[cnt]=atoi(b);
			cnt++;
			j=0;
		}
	}
	a[3]=atoi(b);
	if(cnt!=3)
	{
		printf("%s\n",errorCode);
		return 0;
	}
	for(i=0;i<4;i++)
	{
		if(a[i]>255)
		{
			printf("%s\n",errorCode);
			return 0;
		}
	}
	return 1;
}
int Judge_mac(char * mac)//check the mac format XX-XX-XX-XX-XX-XX
{

	char *b="f5-15-20-06-56-10";
	int i=0,j=0;
	if(strlen(mac)!=strlen(b))
	{printf("%s\n",errorCode);
		//printf("len\n");
		return 0;
	}
	for(i=0;i<strlen(mac);i++)
	{
		if(!(('0'<=*(mac+i)&&*(mac+i)<='9')||*(mac+i)=='-'||'a'<=*(mac+i)&&*(mac+i)<='f'||'A'<=*(mac+i)<='F'))
		{printf("%s\n",errorCode);
			//printf("1");
			//printf("%s\n",errorCode);
			return 0;
		}
		if(i==2||i==5||i==8||i==11||i==14){
			if(*(mac+i)!='-')
			{printf("%s\n",errorCode);
				//printf("wrong -\n" );
			}
		}
	}
	//printf("pass\n");
	return 1;
}
int InsertNode(Linklist *head)
{
	Linklist *node=(struct ListNode *)malloc(sizeof(struct ListNode));
	if(!(Judge_ip(_ip)&&Judge_mac(_mac)))
	{
		return 0;
	}
	strcpy(node->ip_addr,_ip);
	strcpy(node->mac_addr,_mac);
	node->type=_type;
	node->timeout=_timeout;
	node->next=NULL;
	if(head->next==NULL)
	{
		head->next=node;
	}
	else 
	{
		node->next=head->next;
		head->next=node;
	}
	return 1;
}
void ShowList(Linklist *head)
{
	Linklist *p=head->next;
	while(p!=NULL)
	{
		printf("ip:%s\t",p->ip_addr);
		printf(" mac:%s\t",p->mac_addr);
		printf(" type:%s\t",!p->type? "static":"dynamic");
		if(p->type)	
			printf("_timeout:%d\n",p->timeout);
		else
			printf("\n");
		p=p->next;
	}
	
}
int FindNode(Linklist *head,char *ip)
{
	Linklist *p;
	if(!Judge_ip(ip))
	{
		return 0;
	}
	for(p=head->next;p!=NULL;p=p->next)
	{
		if(!strcmp(p->ip_addr,ip))
		{
			printf("ip:%s\t",p->ip_addr);
			printf(" mac:%s\t",p->mac_addr);
			printf(" type:%s\t",!p->type? "static":"dynamic");
			if(p->type)		
			printf("_timeout:%d\n",p->timeout);
			return 1;
		}
	}
	return 0;

}
int DeleteNode(Linklist *head,char *ip)
{
	if(!Judge_ip(ip))
	{
		return 0;
	}
	Linklist *p,*q;
	p=head;
	q=p->next;
	while(q!=NULL)
	{
		if(strcmp(q->ip_addr,ip)==0)
		{
			p->next=q->next;
			free(q);
			return 1;
		}
		p=p->next;
		q=p->next;
	}
	printf("no find this arp item\n");
	return 0;
}
int JudgeProtocol(char* input)
{
	if(strlen(input)<3)
		return 0;
	if(strlen (input)==3)  // input="ARP" ||"arp"
	{
		if(strcmp(input,potocol_cnt)==0||strcmp(input,potocol_low_cnt)==0)
		{
			return 1;
		}
	}
	return 0;
}
int JudgeCmd(char* cmd)  //check -a,-s,-d,-t
{
	int i=0;
	if(cmd==NULL||*cmd!='-'||strlen(cmd)!=2)
	{
		return 0;
	}
	
	for(i=0;i<strlen(cmdChar_cnt);i++)
	{
		if(*(cmd+1)==cmdChar_cnt[i])
		{
			return 1;
		}
	}
	return 0;
}

int Arp_Set(Linklist *head,char* ip,char* mac,int type,int timeout)// add a ARP
{
	if(ip==NULL||mac==NULL)
	{
		printf("%s",errorCode);
		return 0;
	}	
	Linklist *node=(struct ListNode *)malloc(sizeof(struct ListNode));
	node->timeout=timeout;
	node->next=NULL;
	InsertNode(head);
    return 1;
}
void Arp_Display(Linklist *head,char *ip)//print the ARP table
{
	int pri,exi;
	pri=ListEmpty(head);
	if (!pri)
	{
		printf("empty arp table\n");
	}
	else
	{
		if(!strcmp(ip,""))
		{
			ShowList(head);
		}
		else
		{
			exi=FindNode(head,ip);
			if(!exi)
				printf("no find this arp item\n");
		}
	}
}
void DeleteList(Linklist *head)
{
	Linklist *p=head;
	Linklist  *q=p->next;
	while(q!=NULL) 
	{
		p->next=q->next;
		free(q);
		q=p->next;
	}
}
int Arp_Delete(Linklist *head,char *ip)// Delete the arp
{
	int dri,fri;
	dri=ListEmpty(head);
	if (!dri)
	{
		printf("arp table is empty\n");
		return 0;
	}
	else
	{
		if(strcmp(ip,"*")==0)
			DeleteList(head);
		else
			DeleteNode(head,ip);
		return 1;
	}	
}
int Arp_SetTimeOut(char * ip) // set the timeout
{
	if(strcmp(ip,"")==0)
	{
		printf("1 %s",errorCode);
		return 0;
	}
	int i=0;
	for(i=0;i<strlen(ip);i++)
	{
		if(!('0'<=(*ip+i) && *(ip+i)<='9'))
		{
			printf("input num");
			return 0;
		}
	}
	_timeout=atoi(ip);

	// _timeout=atoi(ip);
	Linklist* p=head->next;
	while(p!=NULL)
	{
		if(p->type)
		{
			p->timeout=_timeout;
		}
		p=p->next;
	}
	return 1;
}
void GlobalTimeout()// delete the arp : timeout<0
{
	Linklist* p=head;
	Linklist* q=p->next;
	while(q!=NULL)
	{
		if(q->type)
		{
			if(q->timeout<=Period_cnst){
				p->next=q->next;
				free(q);
				q=p->next;
			}
			else{
				q->timeout-=Period_cnst;
				p=q;
				q=q->next;
			}
		}
		else
		{
		p=q;
		q=q->next;	
		}
		
	}
	signal(SIGALRM,GlobalTimeout);
	alarm(Period_cnst);

}
void  InputSplit(char *input)// split the input string
{
	if(input==NULL)
	{
		printf("%s",errorCode);		
		return ;
	}
	sscanf(input,"%s%s%s%s%d",_potocol,_cmd,_ip, _mac,&_type);
	//printf("%s\n", _potocol);
	//printf("%s\n", _cmd );
	//printf("%s\n",_ip );
	//printf("%s\n",_mac );
	//printf("%d\n",_type );
	if(!JudgeProtocol(_potocol))   // judge potocol
	{
		printf("%s\n",errorCode);	
		return ;	
	}
	if(!JudgeCmd(_cmd))
	{
		printf("%s\n",errorCode);	
		return ;
	}
	else
	{
		switch(_cmd[1])
		{
			case 'a':
			case 'A':
				//printf("a");
				Arp_Display(head,_ip);
				strcpy(_ip,"");
				strcpy(_mac,"");
				strcpy(_potocol,"");
				strcpy(_cmd,"");
				break;
			case 's':
			case 'S':
				//printf("set");
				Arp_Set(head,_ip,_mac,_type,_timeout);
				strcpy(_ip,"");
				strcpy(_mac,"");
				strcpy(_potocol,"");
				strcpy(_cmd,"");
			 	break;
			case 'd':
			case 'D':
				//printf("d");
				Arp_Delete(head,_ip);
				strcpy(_ip,"");
				strcpy(_mac,"");
				strcpy(_potocol,"");
				strcpy(_cmd,"");
				break;
			case 't':
			case 'T':
				//printf("t");
				Arp_SetTimeOut(_ip);
				strcpy(_ip,"");
				strcpy(_mac,"");
				strcpy(_potocol,"");
				strcpy(_cmd,"");
				break;	
		}
	}
}
int main()
{
	head=CreateList();
	char input[STRMAX];
	strcpy(_ip,"");
	strcpy(_mac,"");
	strcpy(_potocol,"");
	strcpy(_cmd,"");
	_type=0;
	_timeout=10000;
	alarm(Period_cnst);
	signal(SIGALRM,GlobalTimeout);
	for(;;)
	{
		int i=0;
		while((input[i]=getchar())!='\n' && i<STRMAX-1)
		{
			i++;
		}
		input[i++]='\0';
		InputSplit(input);

		//strcpy(_ip,"");
		//strcpy(_mac,"");
		//strcpy(_potocol,"");
		//strcpy(_cmd,"");
		_type=0;
		_timeout=10000;
	}
	//printf("ip %s\n",_ip );
	// for(;;)
	// {
	// 	int i=0;

	return 0;
}