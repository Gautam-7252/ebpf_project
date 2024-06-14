#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TASK_COMM_LEN 16
#define PORT 4040
#define IPPROTO_TCP 6

SEC("xdp")
int filter(struct __sk_buff *skb) {
    char comm[TASK_COMM_LEN] = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct pid *pid = task->pid;
    struct pid *tgid = task->tgid;
    struct task_struct *task_ptr;
    struct task_struct *task_ptr_tgid;

    bpf_probe_read_kernel(&task_ptr, sizeof(task_ptr), (void *)&pid->tasks);
    bpf_probe_read_kernel(&task_ptr_tgid, sizeof(task_ptr_tgid), (void *)&tgid->tasks);

    bpf_probe_read_kernel(&comm, sizeof(comm), (void *)task_ptr->comm);

    if (comm[0] == 'm' && comm[1] == 'y' && comm[2] == 'p' && comm[3] == 'r' &&
        comm[4] == 'o' && comm[5] == 'c' && comm[6] == 'e' && comm[7] == 's' &&
        comm[8] == 's' && comm[9] == 0) {
        
        void *data = (void *)(long)(skb->data);
        void *data_end = (void *)(long)(skb->data_end);

        if (data + sizeof(struct ethhdr) > data_end)
            return XDP_DROP;

        struct ethhdr *eth = data;
        if (eth->h_proto != bpf_htons(ETH_P_IP))
            return XDP_PASS;

        struct iphdr *ip = (struct iphdr *)(data + sizeof(struct ethhdr));
        if ((void *)(ip + 1) > data_end)
            return XDP_DROP;

        if (ip->protocol != IPPROTO_TCP)
            return XDP_PASS;

        struct tcphdr *tcp = (struct tcphdr *)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;

        if (bpf_ntohs(tcp->dest) == PORT)
            return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
