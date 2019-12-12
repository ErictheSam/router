#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(response) and 0(request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系，Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  uint8_t first = packet[0]&0x0F;
  int len_head = first * 4;
  uint32_t len_tot = (uint32_t)packet[3]+(uint32_t)(packet[2]<<8);
  //printf("%d %d ",len_tot,len);
  if(len_tot > len)
    return false;
  //printf("%hx %hx\n",packet[len_head+8],packet[len_head+9]);
  if(packet[len_head+8] != 2 && packet[len_head+8] != 1)
    return false;
  output->command = packet[len_head + 8];
  if(packet[len_head+9] != 2)
    return false;
  //printf("%hx %hx ",packet[len_head+10],packet[len_head+10]);
  if(packet[len_head+10] != 0 || packet[len_head+11] != 0)
    return false;
  int times = (len_tot - 32)/20;
  uint8_t token = packet[len_head + 8];
  int len_out = len_head + 12;
  uint32_t addr1 = 0;
  uint32_t mask1 = 0;
  uint32_t nexthop = 0;
  uint32_t metrics = 0;
  uint32_t addr1_family = 0;
  for(int i = 0; i < times; i ++){
    //printf("%hx %hx\n",packet[len_out],packet[len_out+1]);
    if(token == 1 && (packet[len_out]!=0 || packet[len_out+1]!=0))
      return false;
    if(token == 2 && (packet[len_out]!=0 || packet[len_out+1]!=2))
      return false;
    
    for( int t = len_out+8; t < len_out+12; t ++){
      //printf("%hx\n",packet[t]);
      if(packet[t] != 0xff && packet[t] != 0)
        return false;
    }
    
    if(packet[len_out+16]!= 0 || packet[len_out+17]!= 0 ||packet[len_out+18]!= 0 || (packet[len_out+19] ==0 || packet[len_out+19] > 16))
      return false;
    len_out = len_out+20;
  }
  output->numEntries = times;
  output->command = token;
  len_out = len_head + 12;
  for(int i = 0; i < times; i ++){
    addr1_family += ((uint32_t)packet[len_out+0])<<8;
    addr1_family += ((uint32_t)packet[len_out+1]);
    addr1 += ((uint32_t)packet[len_out+7]) << 24;
    addr1 += ((uint32_t)packet[len_out+6]) << 16;
    addr1 += ((uint32_t)packet[len_out+5]) << 8;
    addr1 += ((uint32_t)packet[len_out+4]);
    mask1 += ((uint32_t)packet[len_out+11]) << 24;
    mask1 += ((uint32_t)packet[len_out+10]) << 16;
    mask1 += ((uint32_t)packet[len_out+9]) << 8;
    mask1 += ((uint32_t)packet[len_out+8]);
    nexthop += ((uint32_t)packet[len_out+15]) << 24;
    nexthop += ((uint32_t)packet[len_out+14]) << 16;
    nexthop += ((uint32_t)packet[len_out+13]) << 8;
    nexthop += ((uint32_t)packet[len_out+12]);
    metrics = ((uint32_t)packet[len_out+19])<<24;
    output->entries[i].addr = addr1;
    output->entries[i].mask = mask1;
    output->entries[i].nexthop = nexthop;
    output->entries[i].metric = metrics;
    output->entries[i].addr_family = addr1_family;
    addr1_family = 0;
    addr1 = 0;
    mask1 = 0;
    nexthop = 0;
    metrics = 0;
    len_out = len_out + 20;
  }
  return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  //printf("%d Entry",rip->numEntries);
  uint32_t t = 0;
  buffer[t] = rip->command;
  buffer[t+1] = 2;
  int choose = rip->command;
  buffer[t+2] = 0; buffer[t+3] = 0;
  t = t + 4;
  for( int i = 0; i < rip->numEntries; i ++ ){
    buffer[t] = 0;
    if(choose == 1)//addr_family不用管
      buffer[t+1] = 0;
    else
    {
      buffer[t+1] = 2;
    }
    buffer[t+2] = 0; buffer[t+3] = 0;
    uint32_t addr = rip->entries[i].addr;
    buffer[t+7] = (uint8_t)((addr >> 24) & 0xFF);
    buffer[t+6] = (uint8_t)((addr >> 16) & 0xFF);
    buffer[t+5] = (uint8_t)((addr >> 8) & 0xFF);
    buffer[t+4] = (uint8_t)(addr & 0xFF);
    uint32_t mask = rip->entries[i].mask;
    buffer[t+11] = (uint8_t)((mask >> 24) & 0xFF);
    buffer[t+10] = (uint8_t)((mask >> 16) & 0xFF);
    buffer[t+9] = (uint8_t)((mask >> 8) & 0xFF);
    buffer[t+8] = (uint8_t)(mask & 0xFF);
    uint32_t nexthop = rip->entries[i].nexthop;
    buffer[t+15] = (uint8_t)((nexthop >> 24) & 0xFF);
    buffer[t+14] = (uint8_t)((nexthop >> 16) & 0xFF);
    buffer[t+13] = (uint8_t)((nexthop >> 8) & 0xFF);
    buffer[t+12] = (uint8_t)(nexthop & 0xFF);
    uint32_t mtc = rip->entries[i].metric;
    buffer[t+19] = (uint8_t)((mtc >> 24) & 0xFF);
    buffer[t+18] = (uint8_t)((mtc >> 16) & 0xFF);
    buffer[t+17] = (uint8_t)((mtc >> 8) & 0xFF);
    buffer[t+16] = (uint8_t)(mtc & 0xFF);
    t = t + 20;
  }
  return 4 + rip->numEntries*20;
}