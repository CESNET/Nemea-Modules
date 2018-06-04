#include "parser.h"
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>

int fpp_parse_packet(const uint8_t *packet, uint32_t packet_len, packet_hdr_t **out){
    packet_hdr_t *last_hdr = NULL;
    packet_hdr_t *hdr = NULL;
    const uint8_t *fpp_packetStart = packet;
    const uint8_t *fpp_packetEnd = packet + packet_len;
    uint64_t fpp_packetOffsetInBits = 0;
    enum fpp_errorCodes fpp_errorCode = ParserDefaultReject;

    struct etherip_h etherip;
    struct ieee802_1q_h vlan_q;
    struct ieee802_1q_h vlan_ad;
    struct ieee802_1ah_h vlan_ah;
    struct mpls_h mpls;
    struct eompls_h eompls;
    struct trill_h trill;
    struct pppoe_h pppoe;
    struct gre_h gre;
    struct gre_sre_h gre_sre;
    struct l2tp_h l2tp;
    struct vxlan_h vxlan;
    struct genv_h genv;
    struct gtp_v0_h gtp_v0;
    struct gtp_v1_h gtp_v1;
    struct gtp_v2_h gtp_v2;
    struct gtp_v1_next_hdr_h gtp_v1_next_hdr;
    struct teredo_auth_h teredo_auth;
    struct teredo_origin_h teredo_origin;
    struct pptp_uncomp_proto_h pptp_uncomp_proto;
    struct pptp_comp_proto_h pptp_comp_proto;
    uint16_t udp_src_port;
    uint8_t tmp_19;
    uint16_t tmp_20;
    uint8_t tmp_21;
    uint8_t tmp_22;
    uint8_t tmp_23;
    uint8_t tmp_24;
    uint16_t tmp_25;
    uint32_t tmp_26;
    uint32_t tmp_27;
    uint32_t tmp_28;
    uint8_t tmp_29;
    uint8_t tmp_30;
    uint32_t tmp_31;
    int32_t tmp_32;
    uint32_t tmp_33;
    uint8_t tmp_34;
    uint8_t tmp_35;
    uint16_t tmp_36;
    uint8_t tmp_37;
    uint8_t tmp_38;

    (void) etherip;
    (void) vlan_q;
    (void) vlan_ad;
    (void) vlan_ah;
    (void) mpls;
    (void) eompls;
    (void) trill;
    (void) pppoe;
    (void) gre;
    (void) gre_sre;
    (void) l2tp;
    (void) vxlan;
    (void) genv;
    (void) gtp_v0;
    (void) gtp_v1;
    (void) gtp_v2;
    (void) gtp_v1_next_hdr;
    (void) teredo_auth;
    (void) teredo_origin;
    (void) pptp_uncomp_proto;
    (void) pptp_comp_proto;
    (void) udp_src_port;
    (void) tmp_19;
    (void) tmp_20;
    (void) tmp_21;
    (void) tmp_22;
    (void) tmp_23;
    (void) tmp_24;
    (void) tmp_25;
    (void) tmp_26;
    (void) tmp_27;
    (void) tmp_28;
    (void) tmp_29;
    (void) tmp_30;
    (void) tmp_31;
    (void) tmp_32;
    (void) tmp_33;
    (void) tmp_34;
    (void) tmp_35;
    (void) tmp_36;
    (void) tmp_37;
    (void) tmp_38;

    *out = NULL;

    goto start;
    start: {
        goto parse_ethernet;
    }
    parse_ethernet: {
/* extract(headers[0])*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 112)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        struct ethernet_h *headers = (struct ethernet_h *) malloc(sizeof(struct ethernet_h));
        if (headers == NULL) { fpp_errorCode = OutOfMemory; goto fpp_end; }
        hdr = (packet_hdr_t *) malloc(sizeof(packet_hdr_t));
        if (hdr == NULL) { free(headers); fpp_errorCode = OutOfMemory; goto fpp_end; }
        
        hdr->type = fpp_ethernet_h;
        hdr->hdr = headers;
        hdr->next = NULL;

        if (*out == NULL) {
                *out = hdr;
                last_hdr = hdr;
        } else {
                last_hdr->next = hdr;
                last_hdr = hdr;
        }

        headers->header_offset = fpp_packetOffsetInBits / 8;

        headers[0].dst_addr[0] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 0) >> 0));
        headers[0].dst_addr[1] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 1) >> 0));
        headers[0].dst_addr[2] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 2) >> 0));
        headers[0].dst_addr[3] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 3) >> 0));
        headers[0].dst_addr[4] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 4) >> 0));
        headers[0].dst_addr[5] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 5) >> 0));
        fpp_packetOffsetInBits += 48;

        headers[0].src_addr[0] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 0) >> 0));
        headers[0].src_addr[1] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 1) >> 0));
        headers[0].src_addr[2] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 2) >> 0));
        headers[0].src_addr[3] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 3) >> 0));
        headers[0].src_addr[4] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 4) >> 0));
        headers[0].src_addr[5] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 5) >> 0));
        fpp_packetOffsetInBits += 48;

        headers[0].ethertype = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        headers[0].header_valid = 1;
        switch (headers[0].ethertype) {
            case 2048: goto parse_ipv4;
            case 34525: goto parse_ipv6;
            case 34887: goto parse_mpls;
            case 34888: goto parse_mpls;
            case 33024: goto parse_vlan_q;
            case 34984: goto parse_vlan_ad;
            case 35047: goto parse_vlan_ah;
            case 8947: goto parse_trill;
            case 34916: goto parse_pppoe;
            case 34915: goto reject;
            default: goto parse_payload;
        }
    }
    parse_vlan_q: {
/* extract(vlan_q)*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 32)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        vlan_q.pcp = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 5) & FPP_MASK(uint8_t, 3)));
        fpp_packetOffsetInBits += 3;

        vlan_q.cfi = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 4) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        vlan_q.vid = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits))) & FPP_MASK(uint16_t, 12)));
        fpp_packetOffsetInBits += 12;

        vlan_q.ethertype = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        vlan_q.header_valid = 1;
        switch (vlan_q.ethertype) {
            case 2048: goto parse_ipv4;
            case 34525: goto parse_ipv6;
            case 34887: goto parse_mpls;
            case 34888: goto parse_mpls;
            case 33024: goto parse_vlan_q;
            case 34984: goto parse_vlan_ad;
            case 8947: goto parse_trill;
            case 34916: goto parse_pppoe;
            case 34915: goto reject;
            default: goto reject;
        }
    }
    parse_vlan_ad: {
/* extract(vlan_ad)*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 32)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        vlan_ad.pcp = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 5) & FPP_MASK(uint8_t, 3)));
        fpp_packetOffsetInBits += 3;

        vlan_ad.cfi = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 4) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        vlan_ad.vid = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits))) & FPP_MASK(uint16_t, 12)));
        fpp_packetOffsetInBits += 12;

        vlan_ad.ethertype = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        vlan_ad.header_valid = 1;
        switch (vlan_ad.ethertype) {
            case 2048: goto parse_ipv4;
            case 34525: goto parse_ipv6;
            case 34887: goto parse_mpls;
            case 34888: goto parse_mpls;
            case 33024: goto parse_vlan_q;
            case 35047: goto parse_vlan_ah;
            case 8947: goto parse_trill;
            case 34916: goto parse_pppoe;
            case 34915: goto reject;
            default: goto reject;
        }
    }
    parse_vlan_ah: {
/* extract(vlan_ah)*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 32)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        vlan_ah.prio = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 5) & FPP_MASK(uint8_t, 3)));
        fpp_packetOffsetInBits += 3;

        vlan_ah.drop = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 4) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        vlan_ah.nca = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 3) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        vlan_ah.res1 = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 2) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        vlan_ah.res2 = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits))) & FPP_MASK(uint8_t, 2)));
        fpp_packetOffsetInBits += 2;

        vlan_ah.isid = ntohl((uint32_t)((load_word(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 8) & FPP_MASK(uint32_t, 24)));
        fpp_packetOffsetInBits += 24;

        vlan_ah.header_valid = 1;
        goto parse_ethernet;
    }
    parse_trill: {
/* extract(trill)*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 48)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        trill.version = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 6) & FPP_MASK(uint8_t, 2)));
        fpp_packetOffsetInBits += 2;

        trill.res = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 4) & FPP_MASK(uint8_t, 2)));
        fpp_packetOffsetInBits += 2;

        trill.m = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 3) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        trill.op_len = ntohs((uint8_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 6) & FPP_MASK(uint8_t, 5)));
        fpp_packetOffsetInBits += 5;

        trill.hop_cnt = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits))) & FPP_MASK(uint8_t, 6)));
        fpp_packetOffsetInBits += 6;

        trill.egress_nick = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        trill.ingress_nick = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        trill.header_valid = 1;
/* advance((((uint32_t)trill.op_len) << 5))*/
        fpp_packetOffsetInBits += (((uint32_t)trill.op_len) << 5);
        goto parse_ethernet;
    }
    parse_mpls: {
/* extract(mpls)*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 32)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        mpls.label = ntohl((uint32_t)((load_word(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 12) & FPP_MASK(uint32_t, 20)));
        fpp_packetOffsetInBits += 20;

        mpls.tc = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 1) & FPP_MASK(uint8_t, 3)));
        fpp_packetOffsetInBits += 3;

        mpls.bos = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits))) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        mpls.ttl = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        mpls.header_valid = 1;
        switch (mpls.bos) {
            case 0: goto parse_mpls;
            case 1: goto parse_mpls_end;
            default: goto reject;
        }
    }
    parse_mpls_end: {
tmp_19 = /* lookahead()*/
        ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 4) & FPP_MASK(uint8_t, 4)));
;        switch (tmp_19) {
            case 4: goto parse_ipv4;
            case 6: goto parse_ipv6;
            case 0: goto parse_eompls;
            default: goto reject;
        }
    }
    parse_eompls: {
/* extract(eompls)*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 32)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        eompls.zero = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 4) & FPP_MASK(uint8_t, 4)));
        fpp_packetOffsetInBits += 4;

        eompls.res = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits))) & FPP_MASK(uint16_t, 12)));
        fpp_packetOffsetInBits += 12;

        eompls.seq_num = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        eompls.header_valid = 1;
        goto parse_ethernet;
    }
    parse_pppoe: {
/* extract(pppoe)*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 48)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        pppoe.version = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 4) & FPP_MASK(uint8_t, 4)));
        fpp_packetOffsetInBits += 4;

        pppoe.type = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits))) & FPP_MASK(uint8_t, 4)));
        fpp_packetOffsetInBits += 4;

        pppoe.code = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        pppoe.sid = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        pppoe.len = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        pppoe.header_valid = 1;
        switch (pppoe.code) {
            case 0: goto parse_pptp;
            default: goto reject;
        }
    }
    parse_pptp: {
tmp_20 = /* lookahead()*/
        ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
;        switch (tmp_20) {
            case 65283: goto parse_pptp_uncomp_addr_cntrl;
            default: goto parse_pptp_comp_addr_cntrl;
        }
    }
    parse_pptp_uncomp_addr_cntrl: {
/* advance(16)*/
        fpp_packetOffsetInBits += 16;
tmp_21 = /* lookahead()*/
        ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
;tmp_22 = (tmp_21 & 1);        switch (tmp_22) {
            case 0: goto parse_pptp_uncomp_proto;
            case 1: goto parse_pptp_comp_proto;
            default: goto reject;
        }
    }
    parse_pptp_comp_addr_cntrl: {
tmp_23 = /* lookahead()*/
        ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
;tmp_24 = (tmp_23 & 1);        switch (tmp_24) {
            case 0: goto parse_pptp_uncomp_proto;
            case 1: goto parse_pptp_comp_proto;
            default: goto reject;
        }
    }
    parse_pptp_uncomp_proto: {
/* extract(pptp_uncomp_proto)*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 16)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        pptp_uncomp_proto.proto = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        pptp_uncomp_proto.header_valid = 1;
        switch (pptp_uncomp_proto.proto) {
            case 33: goto parse_ipv4;
            case 87: goto parse_ipv6;
            case 253: goto accept;
            case 49185: goto accept;
            default: goto reject;
        }
    }
    parse_pptp_comp_proto: {
/* extract(pptp_comp_proto)*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 8)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        pptp_comp_proto.proto = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        pptp_comp_proto.header_valid = 1;
        switch (((uint16_t)pptp_comp_proto.proto)) {
            case 33: goto parse_ipv4;
            case 87: goto parse_ipv6;
            case 253: goto accept;
            case 49185: goto accept;
            default: goto reject;
        }
    }
    parse_ipv4: {
/* extract(headers[0])*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 160)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        struct ipv4_h *headers = (struct ipv4_h *) malloc(sizeof(struct ipv4_h));
        if (headers == NULL) { fpp_errorCode = OutOfMemory; goto fpp_end; }
        hdr = (packet_hdr_t *) malloc(sizeof(packet_hdr_t));
        if (hdr == NULL) { free(headers); fpp_errorCode = OutOfMemory; goto fpp_end; }
        
        hdr->type = fpp_ipv4_h;
        hdr->hdr = headers;
        hdr->next = NULL;

        if (*out == NULL) {
                *out = hdr;
                last_hdr = hdr;
        } else {
                last_hdr->next = hdr;
                last_hdr = hdr;
        }

        headers->header_offset = fpp_packetOffsetInBits / 8;

        headers[0].version = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 4) & FPP_MASK(uint8_t, 4)));
        fpp_packetOffsetInBits += 4;

        headers[0].ihl = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits))) & FPP_MASK(uint8_t, 4)));
        fpp_packetOffsetInBits += 4;

        headers[0].diffserv = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        headers[0].total_len = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        headers[0].identification = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        headers[0].flags = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 5) & FPP_MASK(uint8_t, 3)));
        fpp_packetOffsetInBits += 3;

        headers[0].frag_offset = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits))) & FPP_MASK(uint16_t, 13)));
        fpp_packetOffsetInBits += 13;

        headers[0].ttl = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        headers[0].protocol = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        headers[0].hdr_checksum = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        headers[0].src_addr = ntohl((uint32_t)((load_word(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 32;

        headers[0].dst_addr = ntohl((uint32_t)((load_word(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 32;

        headers[0].header_valid = 1;
/* advance(((uint32_t)((((int32_t)((uint32_t)headers[0].ihl)) + -5) << 5)))*/
        fpp_packetOffsetInBits += ((uint32_t)((((int32_t)((uint32_t)headers[0].ihl)) + -5) << 5));
        switch (headers[0].protocol) {
            case 6: goto parse_tcp;
            case 17: goto parse_udp;
            case 1: goto parse_icmp;
            case 47: goto parse_gre;
            case 4: goto parse_ipv4;
            case 41: goto parse_ipv6;
            case 97: goto parse_etherip;
            case 137: goto parse_mpls;
            default: goto reject;
        }
    }
    parse_ipv6: {
/* extract(headers[0])*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 320)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        struct ipv6_h *headers = (struct ipv6_h *) malloc(sizeof(struct ipv6_h));
        if (headers == NULL) { fpp_errorCode = OutOfMemory; goto fpp_end; }
        hdr = (packet_hdr_t *) malloc(sizeof(packet_hdr_t));
        if (hdr == NULL) { free(headers); fpp_errorCode = OutOfMemory; goto fpp_end; }
        
        hdr->type = fpp_ipv6_h;
        hdr->hdr = headers;
        hdr->next = NULL;

        if (*out == NULL) {
                *out = hdr;
                last_hdr = hdr;
        } else {
                last_hdr->next = hdr;
                last_hdr = hdr;
        }

        headers->header_offset = fpp_packetOffsetInBits / 8;

        headers[0].version = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 4) & FPP_MASK(uint8_t, 4)));
        fpp_packetOffsetInBits += 4;

        headers[0].traffic_class = ntohs((uint8_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 4) & FPP_MASK(uint8_t, 8)));
        fpp_packetOffsetInBits += 8;

        headers[0].flow_label = ntohl((uint32_t)((load_word(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 8) & FPP_MASK(uint32_t, 20)));
        fpp_packetOffsetInBits += 20;

        headers[0].payload_len = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        headers[0].next_hdr = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        headers[0].hop_limit = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        headers[0].src_addr[0] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 0) >> 0));
        headers[0].src_addr[1] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 1) >> 0));
        headers[0].src_addr[2] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 2) >> 0));
        headers[0].src_addr[3] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 3) >> 0));
        headers[0].src_addr[4] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 4) >> 0));
        headers[0].src_addr[5] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 5) >> 0));
        headers[0].src_addr[6] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 6) >> 0));
        headers[0].src_addr[7] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 7) >> 0));
        headers[0].src_addr[8] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 8) >> 0));
        headers[0].src_addr[9] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 9) >> 0));
        headers[0].src_addr[10] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 10) >> 0));
        headers[0].src_addr[11] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 11) >> 0));
        headers[0].src_addr[12] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 12) >> 0));
        headers[0].src_addr[13] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 13) >> 0));
        headers[0].src_addr[14] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 14) >> 0));
        headers[0].src_addr[15] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 15) >> 0));
        fpp_packetOffsetInBits += 128;

        headers[0].dst_addr[0] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 0) >> 0));
        headers[0].dst_addr[1] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 1) >> 0));
        headers[0].dst_addr[2] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 2) >> 0));
        headers[0].dst_addr[3] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 3) >> 0));
        headers[0].dst_addr[4] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 4) >> 0));
        headers[0].dst_addr[5] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 5) >> 0));
        headers[0].dst_addr[6] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 6) >> 0));
        headers[0].dst_addr[7] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 7) >> 0));
        headers[0].dst_addr[8] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 8) >> 0));
        headers[0].dst_addr[9] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 9) >> 0));
        headers[0].dst_addr[10] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 10) >> 0));
        headers[0].dst_addr[11] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 11) >> 0));
        headers[0].dst_addr[12] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 12) >> 0));
        headers[0].dst_addr[13] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 13) >> 0));
        headers[0].dst_addr[14] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 14) >> 0));
        headers[0].dst_addr[15] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 15) >> 0));
        fpp_packetOffsetInBits += 128;

        headers[0].header_valid = 1;
        switch (headers[0].next_hdr) {
            case 6: goto parse_tcp;
            case 17: goto parse_udp;
            case 58: goto parse_icmpv6;
            case 4: goto parse_ipv4;
            case 41: goto parse_ipv6;
            case 47: goto parse_gre;
            case 97: goto parse_etherip;
            case 137: goto parse_mpls;
            case 0: goto parse_ipv6_hop_opt;
            case 60: goto parse_ipv6_dst_opt;
            case 43: goto parse_ipv6_routing;
            case 44: goto parse_ipv6_fragment;
            case 51: goto parse_ipv6_ah;
            case 59: goto accept;
            default: goto reject;
        }
    }
    parse_ipv6_hop_opt: {
/* extract(headers[0])*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 16)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        struct ipv6_hop_opt_h *headers = (struct ipv6_hop_opt_h *) malloc(sizeof(struct ipv6_hop_opt_h));
        if (headers == NULL) { fpp_errorCode = OutOfMemory; goto fpp_end; }
        hdr = (packet_hdr_t *) malloc(sizeof(packet_hdr_t));
        if (hdr == NULL) { free(headers); fpp_errorCode = OutOfMemory; goto fpp_end; }
        
        hdr->type = fpp_ipv6_hop_opt_h;
        hdr->hdr = headers;
        hdr->next = NULL;

        if (*out == NULL) {
                *out = hdr;
                last_hdr = hdr;
        } else {
                last_hdr->next = hdr;
                last_hdr = hdr;
        }

        headers->header_offset = fpp_packetOffsetInBits / 8;

        headers[0].next_hdr = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        headers[0].hdr_len = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        headers[0].header_valid = 1;
/* advance(((((uint32_t)headers[0].hdr_len) << 6) + 48))*/
        fpp_packetOffsetInBits += ((((uint32_t)headers[0].hdr_len) << 6) + 48);
        switch (headers[0].next_hdr) {
            case 6: goto parse_tcp;
            case 17: goto parse_udp;
            case 58: goto parse_icmpv6;
            case 4: goto parse_ipv4;
            case 41: goto parse_ipv6;
            case 47: goto parse_gre;
            case 97: goto parse_etherip;
            case 137: goto parse_mpls;
            case 0: goto parse_ipv6_hop_opt;
            case 60: goto parse_ipv6_dst_opt;
            case 43: goto parse_ipv6_routing;
            case 44: goto parse_ipv6_fragment;
            case 51: goto parse_ipv6_ah;
            case 59: goto accept;
            default: goto reject;
        }
    }
    parse_ipv6_dst_opt: {
/* extract(headers[0])*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 16)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        struct ipv6_dst_opt_h *headers = (struct ipv6_dst_opt_h *) malloc(sizeof(struct ipv6_dst_opt_h));
        if (headers == NULL) { fpp_errorCode = OutOfMemory; goto fpp_end; }
        hdr = (packet_hdr_t *) malloc(sizeof(packet_hdr_t));
        if (hdr == NULL) { free(headers); fpp_errorCode = OutOfMemory; goto fpp_end; }
        
        hdr->type = fpp_ipv6_dst_opt_h;
        hdr->hdr = headers;
        hdr->next = NULL;

        if (*out == NULL) {
                *out = hdr;
                last_hdr = hdr;
        } else {
                last_hdr->next = hdr;
                last_hdr = hdr;
        }

        headers->header_offset = fpp_packetOffsetInBits / 8;

        headers[0].next_hdr = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        headers[0].hdr_len = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        headers[0].header_valid = 1;
/* advance(((((uint32_t)headers[0].hdr_len) << 6) + 48))*/
        fpp_packetOffsetInBits += ((((uint32_t)headers[0].hdr_len) << 6) + 48);
        switch (headers[0].next_hdr) {
            case 6: goto parse_tcp;
            case 17: goto parse_udp;
            case 58: goto parse_icmpv6;
            case 4: goto parse_ipv4;
            case 41: goto parse_ipv6;
            case 47: goto parse_gre;
            case 97: goto parse_etherip;
            case 137: goto parse_mpls;
            case 0: goto parse_ipv6_hop_opt;
            case 60: goto parse_ipv6_dst_opt;
            case 43: goto parse_ipv6_routing;
            case 44: goto parse_ipv6_fragment;
            case 51: goto parse_ipv6_ah;
            case 59: goto accept;
            default: goto reject;
        }
    }
    parse_ipv6_routing: {
/* extract(headers[0])*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 16)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        struct ipv6_routing_h *headers = (struct ipv6_routing_h *) malloc(sizeof(struct ipv6_routing_h));
        if (headers == NULL) { fpp_errorCode = OutOfMemory; goto fpp_end; }
        hdr = (packet_hdr_t *) malloc(sizeof(packet_hdr_t));
        if (hdr == NULL) { free(headers); fpp_errorCode = OutOfMemory; goto fpp_end; }
        
        hdr->type = fpp_ipv6_routing_h;
        hdr->hdr = headers;
        hdr->next = NULL;

        if (*out == NULL) {
                *out = hdr;
                last_hdr = hdr;
        } else {
                last_hdr->next = hdr;
                last_hdr = hdr;
        }

        headers->header_offset = fpp_packetOffsetInBits / 8;

        headers[0].next_hdr = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        headers[0].hdr_len = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        headers[0].header_valid = 1;
/* advance(((((uint32_t)headers[0].hdr_len) << 6) + 48))*/
        fpp_packetOffsetInBits += ((((uint32_t)headers[0].hdr_len) << 6) + 48);
        switch (headers[0].next_hdr) {
            case 6: goto parse_tcp;
            case 17: goto parse_udp;
            case 58: goto parse_icmpv6;
            case 4: goto parse_ipv4;
            case 41: goto parse_ipv6;
            case 47: goto parse_gre;
            case 97: goto parse_etherip;
            case 137: goto parse_mpls;
            case 0: goto parse_ipv6_hop_opt;
            case 60: goto parse_ipv6_dst_opt;
            case 43: goto parse_ipv6_routing;
            case 44: goto parse_ipv6_fragment;
            case 51: goto parse_ipv6_ah;
            case 59: goto accept;
            default: goto reject;
        }
    }
    parse_ipv6_fragment: {
/* extract(headers[0])*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 64)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        struct ipv6_fragment_h *headers = (struct ipv6_fragment_h *) malloc(sizeof(struct ipv6_fragment_h));
        if (headers == NULL) { fpp_errorCode = OutOfMemory; goto fpp_end; }
        hdr = (packet_hdr_t *) malloc(sizeof(packet_hdr_t));
        if (hdr == NULL) { free(headers); fpp_errorCode = OutOfMemory; goto fpp_end; }
        
        hdr->type = fpp_ipv6_fragment_h;
        hdr->hdr = headers;
        hdr->next = NULL;

        if (*out == NULL) {
                *out = hdr;
                last_hdr = hdr;
        } else {
                last_hdr->next = hdr;
                last_hdr = hdr;
        }

        headers->header_offset = fpp_packetOffsetInBits / 8;

        headers[0].next_hdr = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        headers[0].res1 = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        headers[0].frag_offset = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 3) & FPP_MASK(uint16_t, 13)));
        fpp_packetOffsetInBits += 13;

        headers[0].res2 = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 1) & FPP_MASK(uint8_t, 2)));
        fpp_packetOffsetInBits += 2;

        headers[0].m = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits))) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        headers[0].id = ntohl((uint32_t)((load_word(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 32;

        headers[0].header_valid = 1;
        goto accept;
    }
    parse_ipv6_ah: {
/* extract(headers[0])*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 64)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        struct ipv6_ah_h *headers = (struct ipv6_ah_h *) malloc(sizeof(struct ipv6_ah_h));
        if (headers == NULL) { fpp_errorCode = OutOfMemory; goto fpp_end; }
        hdr = (packet_hdr_t *) malloc(sizeof(packet_hdr_t));
        if (hdr == NULL) { free(headers); fpp_errorCode = OutOfMemory; goto fpp_end; }
        
        hdr->type = fpp_ipv6_ah_h;
        hdr->hdr = headers;
        hdr->next = NULL;

        if (*out == NULL) {
                *out = hdr;
                last_hdr = hdr;
        } else {
                last_hdr->next = hdr;
                last_hdr = hdr;
        }

        headers->header_offset = fpp_packetOffsetInBits / 8;

        headers[0].next_hdr = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        headers[0].len = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        headers[0].res = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        headers[0].spi = ntohl((uint32_t)((load_word(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 32;

        headers[0].header_valid = 1;
/* advance((((uint32_t)headers[0].len) << 5))*/
        fpp_packetOffsetInBits += (((uint32_t)headers[0].len) << 5);
        switch (headers[0].next_hdr) {
            case 6: goto parse_tcp;
            case 17: goto parse_udp;
            case 58: goto parse_icmpv6;
            case 4: goto parse_ipv4;
            case 41: goto parse_ipv6;
            case 47: goto parse_gre;
            case 97: goto parse_etherip;
            case 137: goto parse_mpls;
            case 0: goto parse_ipv6_hop_opt;
            case 60: goto parse_ipv6_dst_opt;
            case 43: goto parse_ipv6_routing;
            case 44: goto parse_ipv6_fragment;
            case 51: goto parse_ipv6_ah;
            case 59: goto accept;
            default: goto reject;
        }
    }
    parse_etherip: {
/* extract(etherip)*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 16)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        etherip.version = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 4) & FPP_MASK(uint8_t, 4)));
        fpp_packetOffsetInBits += 4;

        etherip.reserved = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits))) & FPP_MASK(uint16_t, 12)));
        fpp_packetOffsetInBits += 12;

        etherip.header_valid = 1;
        switch (etherip.version) {
            case 3: goto parse_ethernet;
            default: goto reject;
        }
    }
    parse_gre: {
/* extract(gre)*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 32)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        gre.C = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 7) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        gre.R = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 6) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        gre.K = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 5) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        gre.S = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 4) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        gre.s = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 3) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        gre.recur = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits))) & FPP_MASK(uint8_t, 3)));
        fpp_packetOffsetInBits += 3;

        gre.A = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 7) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        gre.flags = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 3) & FPP_MASK(uint8_t, 4)));
        fpp_packetOffsetInBits += 4;

        gre.ver = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits))) & FPP_MASK(uint8_t, 3)));
        fpp_packetOffsetInBits += 3;

        gre.proto = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        gre.header_valid = 1;
        switch (gre.ver) {
            case 0: goto parse_gre_v0;
            case 1: goto parse_gre_v1;
            default: goto reject;
        }
    }
    parse_gre_v0: {
/* advance(((((uint32_t)gre.C) | ((uint32_t)gre.R)) << 5))*/
        fpp_packetOffsetInBits += ((((uint32_t)gre.C) | ((uint32_t)gre.R)) << 5);
/* advance((((uint32_t)gre.K) << 5))*/
        fpp_packetOffsetInBits += (((uint32_t)gre.K) << 5);
/* advance((((uint32_t)gre.S) << 5))*/
        fpp_packetOffsetInBits += (((uint32_t)gre.S) << 5);
        switch (gre.R) {
            case 1: goto parse_gre_sre;
            case 0: goto parse_gre_v0_fin;
            default: goto reject;
        }
    }
    parse_gre_v0_fin: {
        switch (gre.proto) {
            case 2048: goto parse_ipv4;
            case 34525: goto parse_ipv6;
            case 34827: goto parse_pptp;
            case 25944: goto parse_ethernet;
            case 34887: goto parse_mpls;
            case 34888: goto parse_mpls;
            default: goto reject;
        }
    }
    parse_gre_v1: {
/* advance(32)*/
        fpp_packetOffsetInBits += 32;
/* advance((((uint32_t)gre.S) << 5))*/
        fpp_packetOffsetInBits += (((uint32_t)gre.S) << 5);
/* advance((((uint32_t)gre.A) << 5))*/
        fpp_packetOffsetInBits += (((uint32_t)gre.A) << 5);
        switch (gre.proto) {
            case 2048: goto parse_ipv4;
            case 34525: goto parse_ipv6;
            case 34827: goto parse_pptp;
            case 25944: goto parse_ethernet;
            case 34887: goto parse_mpls;
            case 34888: goto parse_mpls;
            default: goto reject;
        }
    }
    parse_gre_sre: {
/* extract(gre_sre)*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 32)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        gre_sre.addr_family = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        gre_sre.offset = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        gre_sre.length = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        gre_sre.header_valid = 1;
/* advance(((uint32_t)gre_sre.length))*/
        fpp_packetOffsetInBits += ((uint32_t)gre_sre.length);
        switch (gre_sre.length) {
            case 0: goto parse_gre_v0_fin;
            default: goto parse_gre_sre;
        }
    }
    parse_l2tp: {
/* extract(l2tp)*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 16)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        l2tp.type = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 7) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        l2tp.length = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 6) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        l2tp.res1 = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 4) & FPP_MASK(uint8_t, 2)));
        fpp_packetOffsetInBits += 2;

        l2tp.seq = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 3) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        l2tp.res2 = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 2) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        l2tp.offset = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 1) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        l2tp.priority = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits))) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        l2tp.res3 = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 4) & FPP_MASK(uint8_t, 4)));
        fpp_packetOffsetInBits += 4;

        l2tp.version = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits))) & FPP_MASK(uint8_t, 4)));
        fpp_packetOffsetInBits += 4;

        l2tp.header_valid = 1;
        switch (l2tp.version) {
            case 2: goto parse_l2tp_v2;
            default: goto reject;
        }
    }
    parse_l2tp_v2: {
/* advance((((uint32_t)l2tp.length) << 4))*/
        fpp_packetOffsetInBits += (((uint32_t)l2tp.length) << 4);
/* advance(32)*/
        fpp_packetOffsetInBits += 32;
/* advance((((uint32_t)l2tp.seq) << 5))*/
        fpp_packetOffsetInBits += (((uint32_t)l2tp.seq) << 5);
tmp_25 = /* lookahead()*/
        ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
;tmp_26 = (((uint32_t)l2tp.offset) * ((uint32_t)tmp_25));tmp_27 = (tmp_26 << 3);tmp_28 = tmp_27;/* advance(tmp_28)*/
        fpp_packetOffsetInBits += tmp_28;
/* advance((((uint32_t)l2tp.offset) << 4))*/
        fpp_packetOffsetInBits += (((uint32_t)l2tp.offset) << 4);
        switch (l2tp.type) {
            case 0: goto parse_pptp;
            default: goto reject;
        }
    }
    parse_gtp: {
tmp_29 = /* lookahead()*/
        ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 5) & FPP_MASK(uint8_t, 3)));
;        switch (tmp_29) {
            case 0: goto parse_gtp_v0;
            case 1: goto parse_gtp_v1;
            case 2: goto parse_gtp_v2;
            default: goto reject;
        }
    }
    parse_gtp_v0: {
/* extract(gtp_v0)*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 160)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        gtp_v0.version = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 5) & FPP_MASK(uint8_t, 3)));
        fpp_packetOffsetInBits += 3;

        gtp_v0.proto_type = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 4) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        gtp_v0.res1 = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 1) & FPP_MASK(uint8_t, 3)));
        fpp_packetOffsetInBits += 3;

        gtp_v0.snn = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits))) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        gtp_v0.type = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        gtp_v0.length = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        gtp_v0.seq_num = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        gtp_v0.flow_label = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        gtp_v0.sndcp_num = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        gtp_v0.res2 = ntohl((uint32_t)((load_word(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 8) & FPP_MASK(uint32_t, 24)));
        fpp_packetOffsetInBits += 24;

        gtp_v0.tid[0] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 0) >> 0));
        gtp_v0.tid[1] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 1) >> 0));
        gtp_v0.tid[2] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 2) >> 0));
        gtp_v0.tid[3] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 3) >> 0));
        gtp_v0.tid[4] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 4) >> 0));
        gtp_v0.tid[5] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 5) >> 0));
        gtp_v0.tid[6] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 6) >> 0));
        gtp_v0.tid[7] = (uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits) + 7) >> 0));
        fpp_packetOffsetInBits += 64;

        gtp_v0.header_valid = 1;
        switch (gtp_v0.type) {
            case 255: goto parse_gtp_fin;
            default: goto reject;
        }
    }
    parse_gtp_v1: {
/* extract(gtp_v1)*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 64)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        gtp_v1.version = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 5) & FPP_MASK(uint8_t, 3)));
        fpp_packetOffsetInBits += 3;

        gtp_v1.proto_type = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 4) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        gtp_v1.res = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 3) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        gtp_v1.E = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 2) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        gtp_v1.S = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 1) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        gtp_v1.PN = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits))) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        gtp_v1.type = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        gtp_v1.length = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        gtp_v1.TEID = ntohl((uint32_t)((load_word(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 32;

        gtp_v1.header_valid = 1;
        switch (((((uint32_t)gtp_v1.E) | ((uint32_t)gtp_v1.S)) | ((uint32_t)gtp_v1.PN))) {
            case 1: goto parse_gtp_v1_opt;
            case 0: goto parse_gtp_v1_check_type;
            default: goto reject;
        }
    }
    parse_gtp_v1_check_type: {
        switch (gtp_v1.type) {
            case 255: goto parse_gtp_fin;
            default: goto reject;
        }
    }
    parse_gtp_v1_opt: {
/* advance(24)*/
        fpp_packetOffsetInBits += 24;
        switch (gtp_v1.E) {
            case 1: goto parse_gtp_v1_next_hdr;
            case 0: goto parse_gtp_v1_skip_nexthdr;
            default: goto reject;
        }
    }
    parse_gtp_v1_next_hdr: {
tmp_30 = /* lookahead()*/
        ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
;tmp_31 = (((uint32_t)tmp_30) << 5);tmp_32 = (((int32_t)tmp_31) + -8);tmp_33 = ((uint32_t)tmp_32);/* advance(tmp_33)*/
        fpp_packetOffsetInBits += tmp_33;
/* extract(gtp_v1_next_hdr)*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 8)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        gtp_v1_next_hdr.next_hdr = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        gtp_v1_next_hdr.header_valid = 1;
        switch (gtp_v1_next_hdr.next_hdr) {
            case 0: goto parse_gtp_v1_check_type;
            default: goto parse_gtp_v1_next_hdr;
        }
    }
    parse_gtp_v1_skip_nexthdr: {
/* advance(8)*/
        fpp_packetOffsetInBits += 8;
        switch (gtp_v1.type) {
            case 255: goto parse_gtp_fin;
            default: goto reject;
        }
    }
    parse_gtp_v2: {
/* extract(gtp_v2)*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 32)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        gtp_v2.version = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 5) & FPP_MASK(uint8_t, 3)));
        fpp_packetOffsetInBits += 3;

        gtp_v2.piggy_flag = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 4) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        gtp_v2.TEID_flag = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 3) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        gtp_v2.spare = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits))) & FPP_MASK(uint8_t, 3)));
        fpp_packetOffsetInBits += 3;

        gtp_v2.type = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        gtp_v2.length = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        gtp_v2.header_valid = 1;
/* advance((((uint32_t)gtp_v2.TEID_flag) << 5))*/
        fpp_packetOffsetInBits += (((uint32_t)gtp_v2.TEID_flag) << 5);
/* advance(32)*/
        fpp_packetOffsetInBits += 32;
        switch (gtp_v2.type) {
            case 255: goto parse_gtp_fin;
            default: goto reject;
        }
    }
    parse_gtp_fin: {
tmp_34 = /* lookahead()*/
        ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 4) & FPP_MASK(uint8_t, 4)));
;        switch (tmp_34) {
            case 4: goto parse_ipv4;
            case 6: goto parse_ipv6;
            default: goto reject;
        }
    }
    parse_teredo: {
tmp_35 = /* lookahead()*/
        ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 4) & FPP_MASK(uint8_t, 4)));
;        switch (tmp_35) {
            case 6: goto parse_ipv6;
            case 0: goto parse_teredo_hdr;
            default: goto reject;
        }
    }
    parse_teredo_hdr: {
tmp_36 = /* lookahead()*/
        ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
;        switch (tmp_36) {
            case 1: goto parse_teredo_auth_hdr;
            case 0: goto parse_teredo_origin_hdr;
            default: goto reject;
        }
    }
    parse_teredo_auth_hdr: {
/* extract(teredo_auth)*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 32)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        teredo_auth.zero = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        teredo_auth.type = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        teredo_auth.id_len = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        teredo_auth.auth_len = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        teredo_auth.header_valid = 1;
/* advance((((((uint32_t)teredo_auth.id_len) << 3) + (((uint32_t)teredo_auth.auth_len) << 3)) + 72))*/
        fpp_packetOffsetInBits += (((((uint32_t)teredo_auth.id_len) << 3) + (((uint32_t)teredo_auth.auth_len) << 3)) + 72);
tmp_37 = /* lookahead()*/
        ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 4) & FPP_MASK(uint8_t, 4)));
;        switch (tmp_37) {
            case 6: goto parse_ipv6;
            case 0: goto parse_teredo_hdr;
            default: goto reject;
        }
    }
    parse_teredo_origin_hdr: {
/* extract(teredo_origin)*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 64)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        teredo_origin.zero = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        teredo_origin.type = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        teredo_origin.port = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        teredo_origin.ip = ntohl((uint32_t)((load_word(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 32;

        teredo_origin.header_valid = 1;
tmp_38 = /* lookahead()*/
        ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 4) & FPP_MASK(uint8_t, 4)));
;        switch (tmp_38) {
            case 6: goto parse_ipv6;
            case 0: goto parse_teredo_hdr;
            default: goto reject;
        }
    }
    parse_vxlan: {
/* extract(vxlan)*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 64)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        vxlan.gbp_ext = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 7) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        vxlan.res1 = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 4) & FPP_MASK(uint8_t, 3)));
        fpp_packetOffsetInBits += 3;

        vxlan.vni_flag = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 3) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        vxlan.res2 = ntohs((uint8_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 7) & FPP_MASK(uint8_t, 4)));
        fpp_packetOffsetInBits += 4;

        vxlan.dont_learn = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 6) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        vxlan.res3 = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 4) & FPP_MASK(uint8_t, 2)));
        fpp_packetOffsetInBits += 2;

        vxlan.policy_applied = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 3) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        vxlan.res4 = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits))) & FPP_MASK(uint8_t, 3)));
        fpp_packetOffsetInBits += 3;

        vxlan.gpolicy_id = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        vxlan.vni = ntohl((uint32_t)((load_word(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 8) & FPP_MASK(uint32_t, 24)));
        fpp_packetOffsetInBits += 24;

        vxlan.res5 = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        vxlan.header_valid = 1;
        goto parse_ethernet;
    }
    parse_genv: {
/* extract(genv)*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 64)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        genv.version = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 6) & FPP_MASK(uint8_t, 2)));
        fpp_packetOffsetInBits += 2;

        genv.opt_len = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits))) & FPP_MASK(uint8_t, 6)));
        fpp_packetOffsetInBits += 6;

        genv.oam = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 7) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        genv.critical = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 6) & FPP_MASK(uint8_t, 1)));
        fpp_packetOffsetInBits += 1;

        genv.res1 = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits))) & FPP_MASK(uint8_t, 6)));
        fpp_packetOffsetInBits += 6;

        genv.proto = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        genv.vni = ntohl((uint32_t)((load_word(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 8) & FPP_MASK(uint32_t, 24)));
        fpp_packetOffsetInBits += 24;

        genv.res2 = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        genv.header_valid = 1;
/* advance((((uint32_t)genv.opt_len) << 5))*/
        fpp_packetOffsetInBits += (((uint32_t)genv.opt_len) << 5);
        switch (genv.proto) {
            case 25944: goto parse_ethernet;
            case 34888: goto parse_mpls;
            case 34887: goto parse_mpls;
            default: goto reject;
        }
    }
    parse_icmp: {
/* extract(headers[0])*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 64)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        struct icmp_h *headers = (struct icmp_h *) malloc(sizeof(struct icmp_h));
        if (headers == NULL) { fpp_errorCode = OutOfMemory; goto fpp_end; }
        hdr = (packet_hdr_t *) malloc(sizeof(packet_hdr_t));
        if (hdr == NULL) { free(headers); fpp_errorCode = OutOfMemory; goto fpp_end; }
        
        hdr->type = fpp_icmp_h;
        hdr->hdr = headers;
        hdr->next = NULL;

        if (*out == NULL) {
                *out = hdr;
                last_hdr = hdr;
        } else {
                last_hdr->next = hdr;
                last_hdr = hdr;
        }

        headers->header_offset = fpp_packetOffsetInBits / 8;

        headers[0].type_ = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        headers[0].code = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        headers[0].hdr_checksum = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        headers[0].rest = ntohl((uint32_t)((load_word(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 32;

        headers[0].header_valid = 1;
        goto accept;
    }
    parse_icmpv6: {
/* extract(headers[0])*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 64)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        struct icmpv6_h *headers = (struct icmpv6_h *) malloc(sizeof(struct icmpv6_h));
        if (headers == NULL) { fpp_errorCode = OutOfMemory; goto fpp_end; }
        hdr = (packet_hdr_t *) malloc(sizeof(packet_hdr_t));
        if (hdr == NULL) { free(headers); fpp_errorCode = OutOfMemory; goto fpp_end; }
        
        hdr->type = fpp_icmpv6_h;
        hdr->hdr = headers;
        hdr->next = NULL;

        if (*out == NULL) {
                *out = hdr;
                last_hdr = hdr;
        } else {
                last_hdr->next = hdr;
                last_hdr = hdr;
        }

        headers->header_offset = fpp_packetOffsetInBits / 8;

        headers[0].type_ = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        headers[0].code = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        headers[0].hdr_checksum = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        headers[0].rest = ntohl((uint32_t)((load_word(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 32;

        headers[0].header_valid = 1;
        goto accept;
    }
    parse_tcp: {
/* extract(headers[0])*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 160)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        struct tcp_h *headers = (struct tcp_h *) malloc(sizeof(struct tcp_h));
        if (headers == NULL) { fpp_errorCode = OutOfMemory; goto fpp_end; }
        hdr = (packet_hdr_t *) malloc(sizeof(packet_hdr_t));
        if (hdr == NULL) { free(headers); fpp_errorCode = OutOfMemory; goto fpp_end; }
        
        hdr->type = fpp_tcp_h;
        hdr->hdr = headers;
        hdr->next = NULL;

        if (*out == NULL) {
                *out = hdr;
                last_hdr = hdr;
        } else {
                last_hdr->next = hdr;
                last_hdr = hdr;
        }

        headers->header_offset = fpp_packetOffsetInBits / 8;

        headers[0].src_port = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        headers[0].dst_port = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        headers[0].seq_num = ntohl((uint32_t)((load_word(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 32;

        headers[0].ack_num = ntohl((uint32_t)((load_word(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 32;

        headers[0].data_offset = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)) >> 4) & FPP_MASK(uint8_t, 4)));
        fpp_packetOffsetInBits += 4;

        headers[0].res = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits))) & FPP_MASK(uint8_t, 4)));
        fpp_packetOffsetInBits += 4;

        headers[0].flags = ((uint8_t)((load_byte(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 8;

        headers[0].window = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        headers[0].checksum = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        headers[0].urgent_ptr = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        headers[0].header_valid = 1;
/* advance(((uint32_t)((((int32_t)((uint32_t)headers[0].data_offset)) + -5) << 5)))*/
        fpp_packetOffsetInBits += ((uint32_t)((((int32_t)((uint32_t)headers[0].data_offset)) + -5) << 5));
        goto parse_payload;
    }
    parse_udp: {
/* extract(headers[0])*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 64)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        struct udp_h *headers = (struct udp_h *) malloc(sizeof(struct udp_h));
        if (headers == NULL) { fpp_errorCode = OutOfMemory; goto fpp_end; }
        hdr = (packet_hdr_t *) malloc(sizeof(packet_hdr_t));
        if (hdr == NULL) { free(headers); fpp_errorCode = OutOfMemory; goto fpp_end; }
        
        hdr->type = fpp_udp_h;
        hdr->hdr = headers;
        hdr->next = NULL;

        if (*out == NULL) {
                *out = hdr;
                last_hdr = hdr;
        } else {
                last_hdr->next = hdr;
                last_hdr = hdr;
        }

        headers->header_offset = fpp_packetOffsetInBits / 8;

        headers[0].src_port = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        headers[0].dst_port = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        headers[0].len = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        headers[0].checksum = ntohs((uint16_t)((load_half(fpp_packetStart, BYTES(fpp_packetOffsetInBits)))));
        fpp_packetOffsetInBits += 16;

        headers[0].header_valid = 1;
udp_src_port = headers[0].src_port;        switch (headers[0].dst_port) {
            case 1701: goto parse_l2tp;
            case 1723: goto parse_pptp;
            case 2123: goto parse_gtp;
            case 2152: goto parse_gtp;
            case 3386: goto parse_gtp;
            case 3544: goto parse_teredo;
            case 4789: goto parse_vxlan;
            case 6081: goto parse_genv;
            default: goto parse_udp_2;
        }
    }
    parse_udp_2: {
        switch (udp_src_port) {
            case 1701: goto parse_l2tp;
            case 1723: goto parse_pptp;
            case 2123: goto parse_gtp;
            case 2152: goto parse_gtp;
            case 3386: goto parse_gtp;
            case 3544: goto parse_teredo;
            case 4789: goto parse_vxlan;
            case 6081: goto parse_genv;
            default: goto parse_payload;
        }
    }
    parse_payload: {
/* extract(headers[0])*/
        if (fpp_packetEnd < fpp_packetStart + BYTES(fpp_packetOffsetInBits + 0)) {
            fpp_errorCode = PacketTooShort;
            goto reject;
        }
        struct payload_h *headers = (struct payload_h *) malloc(sizeof(struct payload_h));
        if (headers == NULL) { fpp_errorCode = OutOfMemory; goto fpp_end; }
        hdr = (packet_hdr_t *) malloc(sizeof(packet_hdr_t));
        if (hdr == NULL) { free(headers); fpp_errorCode = OutOfMemory; goto fpp_end; }
        
        hdr->type = fpp_payload_h;
        hdr->hdr = headers;
        hdr->next = NULL;

        if (*out == NULL) {
                *out = hdr;
                last_hdr = hdr;
        } else {
                last_hdr->next = hdr;
                last_hdr = hdr;
        }

        headers->header_offset = fpp_packetOffsetInBits / 8;

        headers[0].header_valid = 1;
        goto accept;
    }

    reject: { return fpp_errorCode; }

    accept:
    {
        return NoError;
    }
    fpp_end:
    return fpp_errorCode
;
}
