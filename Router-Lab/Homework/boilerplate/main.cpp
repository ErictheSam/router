#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <list>
using namespace std;
//检查一个

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
extern list<uint32_t> lst_addr;
extern list<uint32_t> lst_len;
extern list<uint32_t> lst_if_index;
extern list<uint32_t> lst_nexthop;
extern list<uint32_t> lst_metric;

uint8_t packet[2048];
uint8_t output[2048];
// 0: 192.168.3.2
// 1: 192.168.4.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = { 0x0203a8c0, 0x0104a8c0, 0x0102000a,
									 0x0103000a };

extern uint32_t Mask(uint32_t len);
uint32_t NetAddr(int len, int address){//CHECKED
  return Mask(len) & address;
}

uint32_t ShuffleEndian(uint32_t x)
{
	return ((x & 0xff000000) >> 24) | ((x & 0x00ff0000) >> 8) | ((x & 0x0000ff00) << 8) | ((x & 0x000000ff) << 24);
}


void printRouter(){
  printf("This is the router to be print\n");
  list<uint32_t>::iterator it1 = lst_addr.begin();
  list<uint32_t>::iterator it2 = lst_len.begin();
  list<uint32_t>::iterator it3 = lst_if_index.begin();
  list<uint32_t>::iterator it4 = lst_nexthop.begin();
  list<uint32_t>::iterator it5 = lst_metric.begin();
  for(; it1 != lst_addr.end(); ){
    uint32_t addr = *it1;
    uint32_t len = *it2;
    uint32_t ifindex = *it3;
    uint32_t nexthop = *it4;
    uint32_t metric = *it5;
    printf("addr: %x , len: %u , if_index: %u , nexthop: %x , metric: %u\n", addr, len, ifindex, nexthop, ShuffleEndian(metric));
    it1 ++; it2 ++; it3 ++; it4 ++; it5 ++;
  }
}

uint32_t generateCheckSum(){//检查过，无问题
  uint32_t sum = 0;
  for(int i = 0; i < 20; i += 2){
    sum += (((uint32_t)output[i]) << 8);
    sum += ((uint32_t)output[i+1]);
  }
  sum -= (((uint32_t)output[10])<<8);
  sum -= ((uint32_t)output[11]);
  while( (sum >> 16) != 0 ){
    sum = (sum >> 16) + (sum & 0xFFFF);
  }
  return 0xFFFF - sum;
}

int main(int argc, char *argv[]) {
  // 0a.
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }
  // 0b. Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
    RoutingTableEntry entry = {
        .addr = addrs[i], // big endian
        .len = 24,        // small endian
        .if_index = i,    // small endian
        .nexthop = 0,      // big endian, means direct
        .metric = ShuffleEndian(1u)
    };
    update(true, entry);
  }
  //WYF's test
  for (int k = 0; k < N_IFACE_ON_BOARD; k++)
	{
		RipPacket rip;
		rip.command = 1;
		rip.numEntries = 1;
		rip.entries[0].addr = 0;
		rip.entries[0].mask = 0;
		rip.entries[0].metric = ShuffleEndian(16u);
		rip.entries[0].nexthop = 0;
		output[0] = 0x45;
		output[1] = 0x00;//TOS
		//2-3 total len
		uint32_t totlen = 20 + 8 + 4 + rip.numEntries * 20;//长度
		output[2] = totlen / 0x100;
		output[3] = totlen % 0x100;
		output[4] = output[5] = 0x00;//ID
		output[6] = output[7] = 0x00;//OFF
		output[8] = 0x01;//TTL
		output[9] = 0x11;//UDP
		//12-15 src ip
		output[12] = addrs[k] & 0xff;
		output[13] = (addrs[k] >> 8) & 0xff;
		output[14] = (addrs[k] >> 16) & 0xff;
		output[15] = (addrs[k] >> 24) & 0xff;
		printf("%x %x %x %x\n", output[12], output[13], output[14], output[15]);
		printf("%x\n", addrs[k]);
		//16-19 dst ip
		output[16] = 0xe0;
		output[17] = 0x00;
		output[18] = 0x00;
		output[19] = 0x09;
		//10-11 validation
		uint32_t tmp = generateCheckSum();
		output[10] = tmp & 0xff;
		output[11] = ((tmp & 0xff00) >> 8);
		// ...
		// UDP
		// port = 520
		output[20] = 0x02;
		output[21] = 0x08;//src port
		output[22] = 0x02;
		output[23] = 0x08;//dst port
		//24-25 len
		totlen -= 20;
		output[24] = totlen / 0x100;
		output[25] = totlen % 0x100;
		//26-27 validation
		output[26] = output[27] = 0;//不管它
		uint32_t rip_len = assemble(&rip, &output[20 + 8]);
		macaddr_t dst_mac;
		if (HAL_ArpGetMacAddress(k, 0x090000e0, dst_mac) == 0)
			HAL_SendIPPacket(k, output, rip_len + 20 + 8, dst_mac);
		else
			printf("WRONG! DST_MAC NOT FOUND!");
	}
  // WYF's test end,

  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 5 * 1000) {

      printf("Timer response RoutingTable:\n");
      printRouter();
      output[0]= 0x45;
      output[1] = 0x00;
      output[4] = 0x00;
      output[5] = 0x00;
      output[6] = 0x00;
      output[7] = 0x00;
      output[8] = 0x01;
      output[9] = 0x11;
      output[16] = 0xe0;
      output[17] = 0x00;
      output[18] = 0x00;
      output[19] = 0x09;
      output[20] = 0x02;
      output[21] = 0x08;
      output[22] = 0x02;
      output[23] = 0x08;
      output[26] = 0x00;
      output[27] = 0x00;
      
      for( int k = 0; k < N_IFACE_ON_BOARD; k++){//每一个口都发出去广播
        
        RipPacket pakt;
        pakt.numEntries  =  0;
        pakt.command = 2 ;
        list<uint32_t>::iterator it1 = lst_addr.begin();
        list<uint32_t>::iterator it2 = lst_len.begin();
        list<uint32_t>::iterator it3 = lst_if_index.begin();
        list<uint32_t>::iterator it4 = lst_nexthop.begin();
        list<uint32_t>::iterator it5 = lst_metric.begin();
        for(; it1 != lst_addr.end(); ){
          uint32_t addr = *it1;
          uint32_t len = *it2;
          uint32_t ifindex = *it3;
          uint32_t nexthop = *it4;
          uint32_t metric = *it5;
          uint32_t masklen = Mask(len);
          it1 ++; it2 ++; it3 ++; it4 ++; it5 ++;
          if(ifindex == k ){
            continue;
          }
          else{
            pakt.entries[pakt.numEntries].addr = addr & masklen;
            pakt.entries[pakt.numEntries].mask =  masklen;//mask
            pakt.entries[pakt.numEntries].metric = metric; //
            pakt.entries[pakt.numEntries].nexthop = nexthop;
            pakt.numEntries ++; 
          }
        }
        uint32_t rip_len = assemble(&pakt,&output[20 + 8]);//packet
        uint32_t getUdp = 8 + 4 + pakt.numEntries * 20;
        uint32_t getPut = 20 + 8 + 4 + pakt.numEntries * 20;
        output[24] = (uint8_t)( (getUdp>>8)&0xFF);
        output[25] = (uint8_t)(getUdp&0xFF);
        output[2] = (uint8_t)((getPut>>8)&0xFF);
        output[3] =(uint8_t)(getPut&0xFF);
        output[12] = (uint8_t)(addrs[k] & 0xFF);//src_dir和dst_dir
        output[13] = (uint8_t)( (addrs[k] >>8) & 0xFF);//src_dir和dst_dir的东西应该没问题吧...
        output[14] = (uint8_t)( (addrs[k] >>16) & 0xFF);
        output[15] =  (uint8_t)( (addrs[k]>>24) & 0xFF);
        uint32_t cksm = generateCheckSum();
        output[10] = (uint8_t)((cksm >> 8) & 0xFF);
        output[11] = (uint8_t)(cksm & 0xFF);
        macaddr_t thismac;
        if(HAL_ArpGetMacAddress(k,0x090000e0,thismac) == 0 ){
          HAL_SendIPPacket(k,output,rip_len + 20 + 8 ,thismac);
        }
        else{
          printf("WRONG! DST_MAC NOT FOUND!\n");
        }
      }
      printf("5s Timer\n");
      last_time = time;
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac,
                              1000, &if_index);
    if (res == HAL_ERR_EOF) {
      printf("HAL_ERR_EOF\n");
      break;
    } else if (res < 0) {
      printf("RES < 0\n");
      return res;
    } else if (res == 0) { //收不到东西?
      // Timeout
      //printf("CANNOT GET SOMETHING\n");
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it,MAYBE NOT TO DO.
      printf("truncated\n");
      continue;
    }
    // 1. validate
    if (!validateIPChecksum(packet, res) ) {
      printf("Invalid IP Checksum\n");
      continue;
    }
    in_addr_t src_addr, dst_addr;

    // extract src_addr and dst_addr from packet,DONE.
    // big endian,CHECKED.
    //src_addr = (in_addr_t)( packet[15] )<< 24 +  (in_addr_t)(packet[14] )<< 16 +  (in_addr_t)(packet[13] )<< 8 +  (in_addr_t)(packet[12] );//端转换
    //dst_addr = (in_addr_t)( packet[19] )<< 24 +  (in_addr_t)(packet[18] )<< 16 +  (in_addr_t)(packet[17] )<< 8 +  (in_addr_t)(packet[16] );//端转换

    src_addr = 0;
		src_addr += packet[15];
		src_addr <<= 8;
		src_addr += packet[14];
		src_addr <<= 8;
		src_addr += packet[13];
		src_addr <<= 8;
		src_addr += packet[12];

		dst_addr = 0;
		dst_addr += packet[19];
		dst_addr <<= 8;
		dst_addr += packet[18];
		dst_addr <<= 8;
		dst_addr += packet[17];
		dst_addr <<= 8;
		dst_addr += packet[16];

    printf("Received address %x %x\n",src_addr, dst_addr);
    in_addr_t group = 0x090000e0;
    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
      if(memcmp(&dst_addr, &group ,sizeof(in_addr_t))==0){ //如果是广播地址，那么dist就是我
        printf("is me!\n");
        dst_is_me = true;
        break;
      }
    }
    
    
    if (dst_is_me) {

      RipPacket rip;
      //printf("dst_is_me\n");
      // check and validate
      if (disassemble(packet, res, &rip)) {
        if (rip.command == 1) {
          // 3a.3 request, ref. RFC2453 3.9.1
          // only need to respond to whole table requests in the lab
          printf("command1\n");
          if(rip.numEntries != 1 || ShuffleEndian(rip.entries[0].metric)!= 16 ){
            printf("ERROR!  in num or metrics\n");
            continue;//忘记了跳出条件#1
          }
          RipPacket resp;
          resp.command = 2;
          resp.numEntries = 0;
          list<uint32_t>::iterator it1 = lst_addr.begin();
          list<uint32_t>::iterator it2 = lst_len.begin();
          list<uint32_t>::iterator it3 = lst_if_index.begin();
          list<uint32_t>::iterator it4 = lst_nexthop.begin();
          list<uint32_t>::iterator it5 = lst_metric.begin();
          for(; it1 != lst_addr.end(); ){
            uint32_t addr = *it1;
            uint32_t len = *it2;
            uint32_t ifindex = *it3;
            uint32_t nexthop = *it4;
            uint32_t metric = *it5;
            uint32_t masklen = Mask(len);
            
            if( (NetAddr(len,addr) != (src_addr & masklen)) && (ifindex != if_index ) ){
              resp.entries[resp.numEntries].addr = addr & masklen;
              resp.entries[resp.numEntries].mask =  masklen;
              resp.entries[resp.numEntries].nexthop = nexthop;
              resp.entries[resp.numEntries].metric = metric;
              printf("nexthop %x\n",nexthop);
              resp.numEntries ++;
            }
            it1 ++; it2 ++; it3 ++; it4 ++; it5 ++;
          }
          printRouter();
          output[0] = 0x45;
          output[1] = 0x00;
          output[4] = 0x00;
          output[5] = 0x00;
          output[6] = 0x00;
          output[7] = 0x00;
          output[8] = 0x01;
          output[9] = 0x11; // Protocol:UDP

          output[12] = (uint8_t)(addrs[if_index] & 0xFF);//src_dir和dst_dir
          output[13] = (uint8_t)( (addrs[if_index] >>8) & 0xFF);
          output[14] = (uint8_t)( (addrs[if_index] >>16) & 0xFF);
          output[15] =  (uint8_t)( (addrs[if_index] >>24) & 0xFF);
          output[16] = (uint8_t)(src_addr & 0xFF);
          output[17] = (uint8_t)( (src_addr >>8) & 0xFF);
          output[18] = (uint8_t)( (src_addr >>16) & 0xFF);
          output[19] =  (uint8_t)( (src_addr >>24) & 0xFF);


          output[20] = 0x02;
          output[21] = 0x08;
          output[22] = 0x02;
          output[23] = 0x08;
          // ...
          // RIP
          uint32_t rip_len = assemble(&resp, &output[20 + 8]);
          uint32_t getUdp = 4 + 8 + resp.numEntries * 20;
          uint32_t getPut = 20 + 4 + 8 + resp.numEntries * 20;
          output[24] = (uint8_t)( (getUdp >> 8)&0xFF);
          output[25] = (uint8_t)(getUdp&0xFF);
          output[2] = (uint8_t)((getPut>>8)&0xFF);
          output[3] =(uint8_t)(getPut&0xFF);
          uint32_t cksm = generateCheckSum();//After first 20 generated, CHECKED
          output[10] = (uint8_t)((cksm >> 8) & 0xFF);
          output[11] = (uint8_t)(cksm & 0xFF);
          //uint32_t udp_checksum = generateUDPCheckSum();
          output[26]=0x00;//(uint8_t)( (udp_checksum)>>8 & 0xFF );
          output[27]=0x00;//(uint8_t)(udp_checksum & 0xFF);
          // checksum calculation for ip and udp
          // if you don't want to calculate udp checksum, set it to zero
          // send it back
          //printf("before send of router_list\n");
          HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
        } 
        else { //更新报
          printf("for update\n");
          bool updated = false;
          RipPacket resp;
          resp.numEntries = 0;
          resp.command = 2;
          list<uint32_t>::iterator it1 = lst_addr.begin();
          list<uint32_t>::iterator it2 = lst_len.begin();
          list<uint32_t>::iterator it3 = lst_if_index.begin();
          list<uint32_t>::iterator it4 = lst_nexthop.begin();
          list<uint32_t>::iterator it5 = lst_metric.begin();
          /* for(; it1 != lst_addr.end(); ){
            uint32_t addr = *it1;
            uint32_t len = *it2;
            uint32_t ifindex = *it3;
            uint32_t nexthop = *it4;
            uint32_t metric = *it5;
            uint32_t masklen = Mask(len);
            int s = findOrNot(len,addr, rip);//如果找到了的话
            if(s >= 0){
                RoutingTableEntry entry = {
                    .addr = addr,
                    .len = len ,
                    .if_index = if_index,
                    .nexthop = nexthop,
                    .metric =  ( ShuffleEndian(rip.entries[s].metric) + 1 <= ShuffleEndian(metric) )? ShuffleEndian( ShuffleEndian(rip.entries[s].metric) + 1 )  : ShuffleEndian( ShuffleEndian(metric) + 1 )  //是每一次只更新内层循环吗?
                };
              if( ShuffleEndian( rip.entries[s].metric )+ 1 <= ShuffleEndian( metric ) ){
				printf("update and shuffle right!\n");
                updated = true;
                update(true,entry);
              }
              if( ShuffleEndian( rip.entries[s].metric ) + 1 >= 16 && nexthop == rip.entries[s].nexthop ){ 
                resp.entries[resp.numEntries].addr = addr;
                resp.entries[resp.numEntries].mask =  masklen;
                resp.entries[resp.numEntries].nexthop = nexthop;
                resp.entries[resp.numEntries].metric = metric;
                resp.numEntries ++;
                update(false, entry);
				//*it1 = 
                printf("deleting Route\n");
               }
               else{
                update(true, entry);
                printf("updated routing!\n");
              }
            }
            it1 ++; it2 ++; it3 ++; it4 ++; it5 ++;
          }
		  uint32_t tmp_nexthop;
          uint32_t tmp_if_index;
          for( int i = 0; i < rip.numEntries; i ++){
            if(query(rip.entries[i].addr ,&tmp_nexthop, &tmp_if_index) == false && rip.entries[i].metric + 1 <= 16 ){//如果都没有query到的话，那么就加上去!
                updated = true;
                RoutingTableEntry entry = {
                    .addr =rip.entries[i].addr,
                    .len =getLen(rip.entries[i].mask),
                    .if_index = if_index,
                    .nexthop = src_addr,
                    .metric = ShuffleEndian(ShuffleEndian(rip.entries[i].metric) + 1 )
                };
                update(true,entry);
            }
          }
		  */
		//先试着用wyf的代码看能不能过
    for( int i = 0; i < rip.numEntries; i ++)
		{
			uint32_t curMetric = rip.entries[i].metric;
			uint32_t addr = rip.entries[i].addr;
			uint32_t mask = rip.entries[i].mask;
			uint32_t len = __builtin_popcount(mask);
			uint32_t nexthop = rip.entries[i].nexthop;
			if(nexthop == 0)
			{
				nexthop = src_addr;
			}
			curMetric = ShuffleEndian(curMetric);
			curMetric = min(curMetric + 1, 16u);

			bool found = false;
			list<uint32_t>::iterator it1 = lst_addr.begin();
          	list<uint32_t>::iterator it2 = lst_len.begin();
          	list<uint32_t>::iterator it3 = lst_if_index.begin();
          	list<uint32_t>::iterator it4 = lst_nexthop.begin();
          	list<uint32_t>::iterator it5 = lst_metric.begin();
			for (; it1 != lst_addr.end(); ){
				uint32_t lstlen = *it2;
				uint32_t lstaddr = *it1;
				uint32_t lstifindex = *it3;
				uint32_t lstnexthop = *it4;
				uint32_t lstmetric = *it5;
				if (len == lstlen)
				{
					if ( NetAddr(lstlen, lstaddr ) == (Mask(len) & addr))
					{
						found = true;
						if (curMetric >= 16 && nexthop==lstnexthop)
						{
							RoutingTableEntry del_tmp;
							del_tmp.addr=addr;
							del_tmp.len = len;
							update(false, del_tmp);
							break;
						}
						if (curMetric <= ShuffleEndian(lstmetric))
						{
							//update
							updated = true;
							*it1 = addr;
							*it5 = ShuffleEndian(curMetric);
							*it4 = nexthop;
							*it3 = if_index;
							//printf("updated routing!\n");
							//TODO:what is if_index?
						}
						break;
					}
				}
				it1 ++; it2 ++; it3 ++; it4 ++; it5 ++;
			}
			if (!found&&curMetric<16)
			{
				updated = true;
				RoutingTableEntry tmp;
				tmp.addr = addr;
				tmp.len = len;
				tmp.metric = ShuffleEndian(curMetric);
				tmp.if_index = if_index;
				tmp.nexthop = src_addr;
	//printf("tmp.addr=%x\n",tmp.addr);
				update(true, tmp);
				//printf("not found! adding new Routing!\n");
			}
		}
		printRouter();

    if( updated )
		{
      printf("RoutingTable updated!\n");
          
      output[0] = 0x45;
      output[1] = 0x00;
      output[4] = 0x00;
      output[5] = 0x00;
      output[6] = 0x00;
      output[7] = 0x00;
      output[8] = 0x01;
      output[9] = 0x11;
      output[16] = 0xe0;
      output[17] = 0x00;
      output[18] = 0x00;
      output[19] = 0x09;
      output[20] = 0x02;
      output[21] = 0x08;
      output[22] = 0x02;
      output[23] = 0x08;
      output[26] = output[27] = 0;
      for( int i = 0; i < N_IFACE_ON_BOARD; i ++){
        RipPacket pakt;
        pakt.command = 2;
        pakt.numEntries = 0;
        list<uint32_t>::iterator it1 = lst_addr.begin();
        list<uint32_t>::iterator it2 = lst_len.begin();
        list<uint32_t>::iterator it3 = lst_if_index.begin();
        list<uint32_t>::iterator it4 = lst_nexthop.begin();
        list<uint32_t>::iterator it5 = lst_metric.begin();
        for(; it1 != lst_addr.end(); ){
          uint32_t addr = *it1;
          uint32_t len = *it2;
          uint32_t ifindex = *it3;
          uint32_t nexthop = *it4;
          uint32_t metric = *it5;
          uint32_t masklen = Mask(len);
          if( ifindex != i ){//分割
            pakt.entries[pakt.numEntries].addr = addr & masklen;
            pakt.entries[pakt.numEntries].mask =  masklen;//mask
            pakt.entries[pakt.numEntries].metric = metric; //
            pakt.entries[pakt.numEntries].nexthop = nexthop;
            printf("nexthop %x\n",nexthop);
            pakt.numEntries ++;
          }
          it1 ++; it2 ++; it3 ++; it4 ++; it5 ++;
        }
        uint32_t rip_len = assemble(&resp, &output[20 + 8]);
        uint32_t getUdp = 4 + 8 + resp.numEntries * 20;
        uint32_t getPut = 20 + 4 + 8 + resp.numEntries * 20;
        output[24] = (uint8_t)( (getUdp >> 8)&0xFF);
        output[25] = (uint8_t)(getUdp&0xFF);
        output[2] = (uint8_t)((getPut>>8)&0xFF);
        output[3] =(uint8_t)(getPut&0xFF);
        output[12] = (uint8_t)(addrs[i] & 0xFF);//src_dir和dst_dir
        output[13] = (uint8_t)( (addrs[i] >>8) & 0xFF);
        output[14] = (uint8_t)( (addrs[i] >>16) & 0xFF);
        output[15] =  (uint8_t)( (addrs[i] >>24) & 0xFF);
        uint32_t cksm = generateCheckSum();//After first 20 generated, CHECKED
        output[10] = (uint8_t)((cksm >> 8) & 0xFF);
        output[11] = (uint8_t)(cksm & 0xFF);
        macaddr_t groupmac;
        if (HAL_ArpGetMacAddress(i, 0x090000e0, groupmac) == 0)
        {
          HAL_SendIPPacket(i, output, rip_len + 20 + 8, groupmac);
          //printf("update response!!!\n");
        }
        else
          printf("WRONG! DST_MAC NOT FOUND!");
            } 
        }
        printRouter();
        }
      }
    } else {
      printf("SHOULD FORWARD!\n");
      uint32_t nxthop, dest_if, metric;
      if (query(dst_addr, &nxthop, &dest_if) ){
        // found
        macaddr_t dest_mac;
        // direct routing
        if (nxthop == 0) {// 如果是直连路由
          nxthop = dst_addr;// 改为目的地址
        }
        printf("dest_if = %u, nexthop = %x\n", dest_if, nxthop);
        if (HAL_ArpGetMacAddress(dest_if, nxthop, dest_mac) == 0) {//如果找到下一条的话
          // found
          memcpy(output, packet, res);
          if (!validateIPChecksum(packet, res) ) {
            printf("Invalid IP Checksum\n");
            continue;
          }
          if (!validateIPChecksum(output, res) ) {
            printf("Invalid IP Checksum output\n");
            continue;
          }
          bool ok = forward(output, res);//更新完成了?
          if(!ok){
            printf("ERROR! checksum wrong or TTL = 0");
						continue;
          }else{//forwarding不用改
            HAL_SendIPPacket(dest_if, output, res, dest_mac);
          }
        } else {
          printf("ARP not found for %x\n", nxthop);
        }
      } else {
        // not found
        // optionally you can send ICMP Host Unreachable
        printf("IP not found for %x\n", src_addr);
      }
    }
  }
  return 0;
}