#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <list>
#include <map>
using namespace std;

list<uint32_t> lst_addr;
list<uint32_t> lst_len;

list<uint32_t> lst_if_index;
list<uint32_t> lst_nexthop;

list<uint32_t> lst_metric;

/*RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;
  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

uint32_t Mask(uint32_t len)
{
  if(len == 32){
    return 0xffffffff;
  }
  return (1 << len) - 1;
}
/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 * 
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 */
void update(bool insert, RoutingTableEntry entry) {
  uint32_t add = entry.addr;
  uint32_t leng = entry.len;
  list<uint32_t>::iterator it1 = lst_addr.begin();
  list<uint32_t>::iterator it2 = lst_len.begin();
  list<uint32_t>::iterator it3 = lst_if_index.begin();
  list<uint32_t>::iterator it4 = lst_nexthop.begin();
  list<uint32_t>::iterator it5 = lst_metric.begin();
  
  for( ; it1 != lst_addr.end();  ){
    int en_addr = *it1;
    int en_len = *it2;
    if( (en_addr& Mask(entry.len)) == (add & Mask(entry.len)) && en_len == leng){
      if(insert == true){
        *it3 = entry.if_index;
        *it4 = entry.nexthop;
        *it5 = entry.metric;
      }else{
        it1 = lst_addr.erase(it1);
        it2 = lst_len.erase(it2);
        it3 = lst_if_index.erase(it3);
        it4 = lst_nexthop.erase(it4);
        it5 = lst_nexthop.erase(it5);
      }
      return;
    }
    it1 ++; it2 ++; it3 ++; it4 ++;it5 ++;
  }if(insert == true){
    lst_addr.push_back(entry.addr);
    lst_len.push_back(entry.len);
    lst_if_index.push_back(entry.if_index);
    lst_nexthop.push_back(entry.nexthop);
    lst_metric.push_back(entry.metric);
  }
  // TODO:
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
  // TODO:
  *nexthop = 0;
  *if_index = 0;
  bool find = false;
  list<uint32_t>::iterator it1 = lst_addr.begin();
  list<uint32_t>::iterator it2 = lst_len.begin();
  list<uint32_t>::iterator it3 = lst_if_index.begin();
  list<uint32_t>::iterator it4 = lst_nexthop.begin();
  int sht = -1;
  int maxEqu = 0;
  uint32_t formerlen = 0;
  for( ; it1 != lst_addr.end(); ){

    
    uint32_t address = *it1;
    uint32_t len = *it2;

    if( (Mask(len) & address) == (Mask(len)&addr) ){
      if(find == false){
        find = true;
        *nexthop = *it4;
        *if_index = *it3;
        formerlen = len;
      }else if ( len > formerlen ){
        formerlen = len;
        *nexthop = *it4;
        *if_index = *it3;
      }
    }
    it1 ++; it2 ++; it3 ++; it4 ++;
  }
  return find;
}