/* ==========================================================================
 * eBPF 采集程序（由 EBPFSource 通过 BCC 加载，内核态按流聚合）
 * 目标：把"每包一次用户态拷贝"变成"每 tick 一次哈希表读取"，CPU 占用 <1%。
 * 依赖：Linux >= 4.9（lock_xadd 需要 4.9+）、内核头文件、root 或 CAP_BPF+CAP_PERFMON。
 * ========================================================================== */
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct flow_key_t {
    u32 saddr;      /* 源地址（网络字节序） */
    u32 daddr;      /* 目的地址（网络字节序） */
    u16 sport;      /* 源端口（主机字节序） */
    u16 dport;      /* 目的端口（主机字节序） */
    u8  proto;      /* 6=TCP, 17=UDP */
    u8  pad[3];
};

BPF_HASH(flows, struct flow_key_t, u64, 8192);   /* 每流累计字节数 */
BPF_HASH(stats, u32, u64, 4);                    /* 0=总包数, 1=总字节数 */

static inline void account_flow(struct sock *sk, u64 bytes, u8 proto) {
    u32 saddr = 0, daddr = 0;
    u16 sport = 0, dport = 0;
    bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

    struct flow_key_t key = {};
    key.saddr = saddr;
    key.daddr = daddr;
    key.sport = sport;
    key.dport = ntohs(dport);
    key.proto = proto;

    u64 zero = 0;
    u64 *val = flows.lookup_or_try_init(&key, &zero);
    if (val) {
        lock_xadd(val, bytes);
    }

    u32 kp = 0, kb = 1;
    u64 one = 1;
    u64 *pv = stats.lookup_or_try_init(&kp, &zero);
    u64 *bv = stats.lookup_or_try_init(&kb, &zero);
    if (pv) { lock_xadd(pv, one); }
    if (bv) { lock_xadd(bv, bytes); }
}

/* 出站：应用层写 socket（含 TCP 重传后再次进入 sendmsg 的情况） */
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    account_flow(sk, size, 6);
    return 0;
}

/* 入站：内核把数据拷贝给用户态时计入，copied>0 才是一次有效接收 */
int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied) {
    if (copied > 0) {
        account_flow(sk, copied, 6);
    }
    return 0;
}

/* UDP 出站 */
int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len) {
    account_flow(sk, len, 17);
    return 0;
}
