// network_sensor.bpf.c

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define ETH_P_IP 0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

char LICENSE[] SEC("license") = "GPL";

struct net_event {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u8 protocol;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} net_events SEC(".maps");

SEC("xdp")
int xdp_network_monitor(struct xdp_md *ctx) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *ip = (void *)eth + sizeof(*eth);

	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;

	int ip_hdr_len = ip->ihl * 4;

	struct net_event *event;

	event = bpf_ringbuf_reserve(&net_events, sizeof(*event), 0);
	if (!event)
		return XDP_PASS;

	event->src_ip = ip->saddr;
	event->dst_ip = ip->daddr;
	event->protocol = ip->protocol;

	event->src_port = 0;
	event->dst_port = 0;

	if (ip->protocol == IPPROTO_TCP) {

		struct tcphdr *tcp = (void *)ip + ip_hdr_len;

		if ((void *)(tcp + 1) > data_end) {
			bpf_ringbuf_discard(event, 0);
			return XDP_PASS;
		}

		/* Only log new TCP connections (SYN packets) */
		if (!(tcp->syn) || tcp->ack) {
			bpf_ringbuf_discard(event, 0);
			return XDP_PASS;
		}

		event->src_port = bpf_ntohs(tcp->source);
		event->dst_port = bpf_ntohs(tcp->dest);

	} else if (ip->protocol == IPPROTO_UDP) {

		struct udphdr *udp = (void *)ip + ip_hdr_len;

		if ((void *)(udp + 1) > data_end) {
			bpf_ringbuf_discard(event, 0);
			return XDP_PASS;
		}

		event->src_port = bpf_ntohs(udp->source);
		event->dst_port = bpf_ntohs(udp->dest);

		/* Always capture DNS */
		if (event->dst_port == 53 || event->src_port == 53) {
			// keep it
		} else {
			/* Apply sampling only to non-critical traffic */
			if (bpf_get_prandom_u32() % 10 != 0) {
				bpf_ringbuf_discard(event, 0);
				return XDP_PASS;
			}
		}
	}

	bpf_ringbuf_submit(event, 0);

	return XDP_PASS;
}
