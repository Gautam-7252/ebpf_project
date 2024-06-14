#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <netinet/in.h>
#include "bpf/bpf_helpers.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} blocked_port SEC(".maps");

SEC("xdp")
int drop_tcp_packets(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    if (ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
    if ((void *)(tcp + 1) > data_end) {
        return XDP_PASS;
    }

    __u32 index = 0;
    __u32 *port = bpf_map_lookup_elem(&blocked_port, &index);
    if (port && *port == htons(tcp->dest)) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
