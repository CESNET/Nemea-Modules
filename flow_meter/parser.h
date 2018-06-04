#ifndef _P4_GEN_HEADER_
#define _P4_GEN_HEADER_
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

enum fpp_errorCodes {
    NoError,
    PacketTooShort,
    NoMatch,
    StackOutOfBounds,
    HeaderTooShort,
    ParserTimeout,
    ParserDefaultReject,
    OutOfMemory
};

#define FPP_MASK(t, w) ((((t)(1)) << (w)) - (t)1)
#define BYTES(w) ((w) / 8)
#define load_byte(ptr, bytes) (*(const uint8_t *)((const uint8_t *)(ptr) + bytes))
#define load_half(ptr, bytes) (*(const uint16_t *)((const uint8_t *)(ptr) + bytes))
#define load_word(ptr, bytes) (*(const uint32_t *)((const uint8_t *)(ptr) + bytes))
#define load_dword(ptr, bytes) (*(const uint64_t *)((const uint8_t *)(ptr) + bytes))

enum fpp_headers {
    fpp_unknown_hdr,
    fpp_ethernet_h,
    fpp_ieee802_1q_h,
    fpp_ieee802_1ah_h,
    fpp_etherip_h,
    fpp_mpls_h,
    fpp_eompls_h,
    fpp_trill_h,
    fpp_pppoe_h,
    fpp_pptp_comp_h,
    fpp_pptp_uncomp_h,
    fpp_pptp_uncomp_proto_h,
    fpp_pptp_comp_proto_h,
    fpp_ipv4_h,
    fpp_ipv6_h,
    fpp_ipv6_hop_opt_h,
    fpp_ipv6_dst_opt_h,
    fpp_ipv6_routing_h,
    fpp_ipv6_fragment_h,
    fpp_ipv6_ah_h,
    fpp_gre_h,
    fpp_gre_sre_h,
    fpp_l2f_h,
    fpp_l2tp_h,
    fpp_vxlan_h,
    fpp_sctp_h,
    fpp_icmp_h,
    fpp_icmpv6_h,
    fpp_tcp_h,
    fpp_udp_h,
    fpp_igmp_v2_h,
    fpp_igmp_v3_h,
    fpp_gtp_v0_h,
    fpp_gtp_v1_h,
    fpp_gtp_v1_next_hdr_h,
    fpp_gtp_v2_h,
    fpp_teredo_auth_h,
    fpp_teredo_origin_h,
    fpp_genv_h,
    fpp_genv_opt_a_h,
    fpp_genv_opt_b_h,
    fpp_genv_opt_c_h,
    fpp_payload_h,
    fpp_headers_s
}
;

struct ethernet_h {
    uint8_t dst_addr[6]; /* bit<48> */
    uint8_t src_addr[6]; /* bit<48> */
    uint16_t ethertype; /* bit<16> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct ieee802_1q_h {
    uint8_t pcp; /* bit<3> */
    uint8_t cfi; /* bit<1> */
    uint16_t vid; /* bit<12> */
    uint16_t ethertype; /* bit<16> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct ieee802_1ah_h {
    uint8_t prio; /* bit<3> */
    uint8_t drop; /* bit<1> */
    uint8_t nca; /* bit<1> */
    uint8_t res1; /* bit<1> */
    uint8_t res2; /* bit<2> */
    uint32_t isid; /* bit<24> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct etherip_h {
    uint8_t version; /* bit<4> */
    uint16_t reserved; /* bit<12> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct mpls_h {
    uint32_t label; /* bit<20> */
    uint8_t tc; /* bit<3> */
    uint8_t bos; /* bit<1> */
    uint8_t ttl; /* bit<8> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct eompls_h {
    uint8_t zero; /* bit<4> */
    uint16_t res; /* bit<12> */
    uint16_t seq_num; /* bit<16> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct trill_h {
    uint8_t version; /* bit<2> */
    uint8_t res; /* bit<2> */
    uint8_t m; /* bit<1> */
    uint8_t op_len; /* bit<5> */
    uint8_t hop_cnt; /* bit<6> */
    uint16_t egress_nick; /* bit<16> */
    uint16_t ingress_nick; /* bit<16> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct pppoe_h {
    uint8_t version; /* bit<4> */
    uint8_t type; /* bit<4> */
    uint8_t code; /* bit<8> */
    uint16_t sid; /* bit<16> */
    uint16_t len; /* bit<16> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct pptp_comp_h {
    uint16_t proto; /* bit<16> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct pptp_uncomp_h {
    uint8_t address; /* bit<8> */
    uint8_t cntrl; /* bit<8> */
    uint16_t proto; /* bit<16> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct pptp_uncomp_proto_h {
    uint16_t proto; /* bit<16> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct pptp_comp_proto_h {
    uint8_t proto; /* bit<8> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct ipv4_h {
    uint8_t version; /* bit<4> */
    uint8_t ihl; /* bit<4> */
    uint8_t diffserv; /* bit<8> */
    uint16_t total_len; /* bit<16> */
    uint16_t identification; /* bit<16> */
    uint8_t flags; /* bit<3> */
    uint16_t frag_offset; /* bit<13> */
    uint8_t ttl; /* bit<8> */
    uint8_t protocol; /* bit<8> */
    uint16_t hdr_checksum; /* bit<16> */
    uint32_t src_addr; /* bit<32> */
    uint32_t dst_addr; /* bit<32> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct ipv6_h {
    uint8_t version; /* bit<4> */
    uint8_t traffic_class; /* bit<8> */
    uint32_t flow_label; /* bit<20> */
    uint16_t payload_len; /* bit<16> */
    uint8_t next_hdr; /* bit<8> */
    uint8_t hop_limit; /* bit<8> */
    uint8_t src_addr[16]; /* bit<128> */
    uint8_t dst_addr[16]; /* bit<128> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct ipv6_hop_opt_h {
    uint8_t next_hdr; /* bit<8> */
    uint8_t hdr_len; /* bit<8> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct ipv6_dst_opt_h {
    uint8_t next_hdr; /* bit<8> */
    uint8_t hdr_len; /* bit<8> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct ipv6_routing_h {
    uint8_t next_hdr; /* bit<8> */
    uint8_t hdr_len; /* bit<8> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct ipv6_fragment_h {
    uint8_t next_hdr; /* bit<8> */
    uint8_t res1; /* bit<8> */
    uint16_t frag_offset; /* bit<13> */
    uint8_t res2; /* bit<2> */
    uint8_t m; /* bit<1> */
    uint32_t id; /* bit<32> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct ipv6_ah_h {
    uint8_t next_hdr; /* bit<8> */
    uint8_t len; /* bit<8> */
    uint16_t res; /* bit<16> */
    uint32_t spi; /* bit<32> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct gre_h {
    uint8_t C; /* bit<1> */
    uint8_t R; /* bit<1> */
    uint8_t K; /* bit<1> */
    uint8_t S; /* bit<1> */
    uint8_t s; /* bit<1> */
    uint8_t recur; /* bit<3> */
    uint8_t A; /* bit<1> */
    uint8_t flags; /* bit<4> */
    uint8_t ver; /* bit<3> */
    uint16_t proto; /* bit<16> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct gre_sre_h {
    uint16_t addr_family; /* bit<16> */
    uint8_t offset; /* bit<8> */
    uint8_t length; /* bit<8> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct l2f_h {
    uint8_t F; /* bit<1> */
    uint8_t K; /* bit<1> */
    uint8_t P; /* bit<1> */
    uint8_t S; /* bit<1> */
    uint8_t res; /* bit<8> */
    uint8_t C; /* bit<1> */
    uint8_t version; /* bit<3> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct l2tp_h {
    uint8_t type; /* bit<1> */
    uint8_t length; /* bit<1> */
    uint8_t res1; /* bit<2> */
    uint8_t seq; /* bit<1> */
    uint8_t res2; /* bit<1> */
    uint8_t offset; /* bit<1> */
    uint8_t priority; /* bit<1> */
    uint8_t res3; /* bit<4> */
    uint8_t version; /* bit<4> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct vxlan_h {
    uint8_t gbp_ext; /* bit<1> */
    uint8_t res1; /* bit<3> */
    uint8_t vni_flag; /* bit<1> */
    uint8_t res2; /* bit<4> */
    uint8_t dont_learn; /* bit<1> */
    uint8_t res3; /* bit<2> */
    uint8_t policy_applied; /* bit<1> */
    uint8_t res4; /* bit<3> */
    uint16_t gpolicy_id; /* bit<16> */
    uint32_t vni; /* bit<24> */
    uint8_t res5; /* bit<8> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct sctp_h {
    uint16_t src_port; /* bit<16> */
    uint16_t dst_port; /* bit<16> */
    uint32_t verif_tag; /* bit<32> */
    uint32_t checksum; /* bit<32> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct icmp_h {
    uint8_t type_; /* bit<8> */
    uint8_t code; /* bit<8> */
    uint16_t hdr_checksum; /* bit<16> */
    uint32_t rest; /* bit<32> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct icmpv6_h {
    uint8_t type_; /* bit<8> */
    uint8_t code; /* bit<8> */
    uint16_t hdr_checksum; /* bit<16> */
    uint32_t rest; /* bit<32> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct tcp_h {
    uint16_t src_port; /* bit<16> */
    uint16_t dst_port; /* bit<16> */
    uint32_t seq_num; /* bit<32> */
    uint32_t ack_num; /* bit<32> */
    uint8_t data_offset; /* bit<4> */
    uint8_t res; /* bit<4> */
    uint8_t flags; /* bit<8> */
    uint16_t window; /* bit<16> */
    uint16_t checksum; /* bit<16> */
    uint16_t urgent_ptr; /* bit<16> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct udp_h {
    uint16_t src_port; /* bit<16> */
    uint16_t dst_port; /* bit<16> */
    uint16_t len; /* bit<16> */
    uint16_t checksum; /* bit<16> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct igmp_v2_h {
    uint8_t type; /* bit<8> */
    uint8_t max_resp_time; /* bit<8> */
    uint16_t checksum; /* bit<16> */
    uint32_t group_addr; /* bit<32> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct igmp_v3_h {
    uint8_t res; /* bit<4> */
    uint8_t S; /* bit<1> */
    uint8_t QRV; /* bit<3> */
    uint8_t QQIC; /* bit<8> */
    uint16_t N; /* bit<16> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct gtp_v0_h {
    uint8_t version; /* bit<3> */
    uint8_t proto_type; /* bit<1> */
    uint8_t res1; /* bit<3> */
    uint8_t snn; /* bit<1> */
    uint8_t type; /* bit<8> */
    uint16_t length; /* bit<16> */
    uint16_t seq_num; /* bit<16> */
    uint16_t flow_label; /* bit<16> */
    uint8_t sndcp_num; /* bit<8> */
    uint32_t res2; /* bit<24> */
    uint8_t tid[8]; /* bit<64> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct gtp_v1_h {
    uint8_t version; /* bit<3> */
    uint8_t proto_type; /* bit<1> */
    uint8_t res; /* bit<1> */
    uint8_t E; /* bit<1> */
    uint8_t S; /* bit<1> */
    uint8_t PN; /* bit<1> */
    uint8_t type; /* bit<8> */
    uint16_t length; /* bit<16> */
    uint32_t TEID; /* bit<32> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct gtp_v1_next_hdr_h {
    uint8_t next_hdr; /* bit<8> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct gtp_v2_h {
    uint8_t version; /* bit<3> */
    uint8_t piggy_flag; /* bit<1> */
    uint8_t TEID_flag; /* bit<1> */
    uint8_t spare; /* bit<3> */
    uint8_t type; /* bit<8> */
    uint16_t length; /* bit<16> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct teredo_auth_h {
    uint8_t zero; /* bit<8> */
    uint8_t type; /* bit<8> */
    uint8_t id_len; /* bit<8> */
    uint8_t auth_len; /* bit<8> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct teredo_origin_h {
    uint8_t zero; /* bit<8> */
    uint8_t type; /* bit<8> */
    uint16_t port; /* bit<16> */
    uint32_t ip; /* bit<32> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct genv_h {
    uint8_t version; /* bit<2> */
    uint8_t opt_len; /* bit<6> */
    uint8_t oam; /* bit<1> */
    uint8_t critical; /* bit<1> */
    uint8_t res1; /* bit<6> */
    uint16_t proto; /* bit<16> */
    uint32_t vni; /* bit<24> */
    uint8_t res2; /* bit<8> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct genv_opt_a_h {
    uint16_t opt_class; /* bit<16> */
    uint8_t opt_type; /* bit<8> */
    uint8_t res; /* bit<3> */
    uint8_t opt_len; /* bit<5> */
    uint32_t data; /* bit<32> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct genv_opt_b_h {
    uint16_t opt_class; /* bit<16> */
    uint8_t opt_type; /* bit<8> */
    uint8_t res; /* bit<3> */
    uint8_t opt_len; /* bit<5> */
    uint8_t data[8]; /* bit<64> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct genv_opt_c_h {
    uint16_t opt_class; /* bit<16> */
    uint8_t opt_type; /* bit<8> */
    uint8_t res; /* bit<3> */
    uint8_t opt_len; /* bit<5> */
    uint32_t data; /* bit<32> */

    uint32_t header_offset;
    uint8_t header_valid;
};

struct payload_h {

    uint32_t header_offset;
    uint8_t header_valid;
};

struct headers_s {
    struct ethernet_h eth; /* ethernet_h */
    struct ipv4_h ipv4; /* ipv4_h */
    struct ipv6_h ipv6; /* ipv6_h */
    struct ipv6_hop_opt_h ipv6_hop_opt; /* ipv6_hop_opt_h */
    struct ipv6_dst_opt_h ipv6_dst_opt; /* ipv6_dst_opt_h */
    struct ipv6_routing_h ipv6_routing; /* ipv6_routing_h */
    struct ipv6_fragment_h ipv6_fragment; /* ipv6_fragment_h */
    struct ipv6_ah_h ipv6_ah; /* ipv6_ah_h */
    struct tcp_h tcp; /* tcp_h */
    struct udp_h udp; /* udp_h */
    struct icmp_h icmp; /* icmp_h */
    struct icmpv6_h icmpv6; /* icmpv6_h */
    struct payload_h payload; /* payload_h */
};

typedef struct packet_hdr_s {
    enum fpp_headers type;
    void *hdr;
    struct packet_hdr_s *next;
}
packet_hdr_t;

int fpp_parse_packet(const uint8_t *packet, uint32_t packet_len, packet_hdr_t **out);
#endif
