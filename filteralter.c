#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/swab.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

int classifier(struct __sk_buff *skb)
{
  __u32 random = 0xc109053a;
  __be16 port = __constant_cpu_to_be16(12445);
  void *data_end = (void *)(unsigned long long)skb->data_end;
  void *data = (void *)(unsigned long long)skb->data;
  int data_offset = 0;
  struct ethhdr *eth = data + data_offset;
  data_offset += sizeof(struct ethhdr);
  if (data + data_offset > data_end) {
    return TC_ACT_SHOT; // packet shorter than an ethernet header
  }

  if (eth->h_proto != ___constant_swab16(ETH_P_IP)) {
    return TC_ACT_OK; // not an ipv4 packet
  }

  struct iphdr *ip = data + data_offset;
  if (data + data_offset + sizeof(struct iphdr) > data_end) {
    return TC_ACT_SHOT; // packet shorter than an ip header (without options)
  }

  data_offset += ip->ihl * 4;
  if (data + data_offset > data_end) {
    return TC_ACT_SHOT; // packet shorter than an ip header
  }

  if (ip->protocol != IPPROTO_UDP) {
    return TC_ACT_OK; // not a udp packet
  }

  if (data + data_offset + sizeof(struct udphdr) > data_end) {
    return TC_ACT_SHOT; // packet shorter than a udp header
  }

  struct udphdr *udp = data + data_offset;
  int udp_offset = data_offset;
  data_offset += sizeof(struct udphdr);

  if (udp->dest == port || udp->source == port) {
    __le32 head = 0;
    if (bpf_skb_load_bytes(skb, data_offset, &head, sizeof(head)) != 0) {
      return TC_ACT_OK;
    }

    __le32 nhead = head ^ random;
    bpf_l4_csum_replace(skb, udp_offset + offsetof(struct udphdr, check), head, nhead, sizeof(nhead));
    bpf_skb_store_bytes(skb, data_offset, &nhead, sizeof(nhead), 0);
  }

  return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";

