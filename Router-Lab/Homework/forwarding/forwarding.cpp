#include <stdint.h>
#include <stdlib.h>

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
  uint8_t first = packet[0]&0x0F;
  int len2 = first * 4;
  //printf("%hd",len2);
  uint32_t sum = 0;
  for( int i = 0; i < len2; i += 2){
    sum += (((uint32_t)packet[i]) << 8);
    sum += ((uint32_t)packet[i+1]);

  }
  while( (sum >> 16) != 0 ){
    sum = (sum >> 16) + (sum & 0xFFFF);
  }
  if(sum != 0xFFFF){
    return false;
  }
  if(packet[8] == 0){
    return false;
  }
  packet[8] = packet[8] - 1;
  sum = 0;
  for( int i = 0; i < len2; i += 2){
    sum += (((uint32_t)packet[i]) << 8);
    sum += ((uint32_t)packet[i+1]);
    //printf("%x ",sum);
  }
  sum -= (((uint32_t)packet[10])<<8);
  sum -= ((uint32_t)packet[11]);
  while( (sum >> 16) != 0 ){
    sum = (sum >> 16) + (sum & 0xFFFF);
  }
  uint32_t newCheckSum = 0xFFFF - sum;
  packet[10] = (uint8_t)(newCheckSum >> 8);
  packet[11] = (uint8_t)(newCheckSum & 0xFF);
  return true;
}