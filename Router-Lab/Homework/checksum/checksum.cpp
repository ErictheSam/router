#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
  // TODO:
  uint8_t first = packet[0]&0x0F;
  int len2 = first * 4;
  //printf("%hd",len2);
  uint32_t sum = 0;
  for( int i = 0; i < len2; i += 2){
    sum += (((uint32_t)packet[i]) << 8);
    sum += ((uint32_t)packet[i+1]);
    //printf("%x ",sum);
  }
  while( (sum >> 16) != 0 ){
    sum = (sum >> 16) + (sum & 0xFFFF);
  }
  //printf("%x",sum);
  if(sum == 0xFFFF)
    return true;
  else
  {
    return false;
  }
  
  
}