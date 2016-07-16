/**
 * \file sipplugin.cpp
 * \author Tomas Jansky <janskto1@fit.cvut.cz>
 * \date 2015
 */
/*
 * Copyright (C) 2015 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */

#ifndef SIPPLUGIN_H
#define SIPPLUGIN_H

#include <cstdlib>
#include <stdio.h>
#include <iostream>
#include <fields.h>

#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "flow_meter.h"

#define SIP_FIELD_LEN				256

#define SIP_MSG_TYPE_INVALID     0
#define SIP_MSG_TYPE_INVITE      1
#define SIP_MSG_TYPE_ACK         2
#define SIP_MSG_TYPE_CANCEL      3
#define SIP_MSG_TYPE_BYE         4
#define SIP_MSG_TYPE_REGISTER	   5
#define SIP_MSG_TYPE_OPTIONS	   6
#define SIP_MSG_TYPE_PUBLISH	   7
#define SIP_MSG_TYPE_NOTIFY      8
#define SIP_MSG_TYPE_INFO        9
#define SIP_MSG_TYPE_SUBSCRIBE   10
#define SIP_MSG_TYPE_STATUS      99

#define SIP_MSG_TYPE_TRYING         100
#define SIP_MSG_TYPE_DIAL_ESTABL	   101
#define SIP_MSG_TYPE_RINGING  	   180
#define SIP_MSG_TYPE_SESSION_PROGR  183
#define SIP_MSG_TYPE_OK	            200
#define SIP_MSG_TYPE_BAD_REQ        400
#define SIP_MSG_TYPE_UNAUTHORIZED   401
#define SIP_MSG_TYPE_FORBIDDEN      403
#define SIP_MSG_TYPE_NOT_FOUND      404
#define SIP_MSG_TYPE_PROXY_AUT_REQ  407
#define SIP_MSG_TYPE_BUSY_HERE      486
#define SIP_MSG_TYPE_REQ_CANCELED   487
#define SIP_MSG_TYPE_INTERNAL_ERR   500
#define SIP_MSG_TYPE_DECLINE        603
#define SIP_MSG_TYPE_UNDEFINED      999

/* Mininum length of SIP message: */
#define SIP_MIN_MSG_LEN     64

/*
 * SIP identification table - these are all patterns that must be contained
 * at the beginning of the SIP packet. They are folded in the same group if
 * they have same the letter on the same position.
 */
/* ** The first pattern test group: ** */
/*                                     v    */
#define SIP_INVITE		0x49564e49	/* IVNI */
#define SIP_REGISTER	0x49474552	/* IGER */
/*                                     vv   */
#define SIP_NOTIFY		0x49544f4e	/* ITON */
#define SIP_OPTIONS		0x4954504f	/* ITPO */
/*                                       v  */
#define SIP_CANCEL		0x434e4143	/* CNAC */
/*                                        v */
#define SIP_INFO		0x4f464e49	/* OFNI */

/* ** Test second pattern test group: ** */
/*                                     v    */
#define SIP_ACK			0x204b4341	/*  KCA */
#define SIP_BYE			0x20455942	/*  EYB */

/*                                      v   */
#define SIP_PUBLISH		0x4c425550	/* LBUP */
#define SIP_SUBSCRIBE	0x53425553	/* SBUS */
/*                                       vv */
#define SIP_REPLY	    0x2f504953	/* /PIS */

/* If one of the bytes in the tested packet equals to byte in the
 * test pattern, the packet *could* begin with the strings which
 * where used to make the test pattern.
 */
#define SIP_TEST_1      0x49544149	/* ITAI */
#define SIP_TEST_2      0x20424953	/*  BIS */

/* MS SSDP notify header for detecting false SIP packets: */
#define SIP_NOT_NOTIFY1 0x2a205946	/* * YF */
#define SIP_NOT_NOTIFY2 0x54544820	/* TTH  */

#define SIP_NOT_OPTIONS1 0x20534e4f	/*  SNO */
#define SIP_NOT_OPTIONS2 0x3a706973	/* :sip */
/*
 * SIP fields table - these patterns are used to quickly
 * detect necessary SIP fields.
 */
/* This macro converts low ASCII characters to upper case. Colon changes to 0x1a character: */
#define SIP_UCFOUR(A)   ((A) & 0xdfdfdfdf)
#define SIP_UCTWO(A)    ((A) & 0x0000dfdf)
#define SIP_UCTHREE(A)  ((A) & 0x00dfdfdf)
/* Encoded SIP field names - long and short alternatives. The trailing number means the number of bytes to compare: */
#define SIP_VIA4        0x1a414956	/* :AIV */
#define SIP_VIA2        0x00001a56	/*   :V */
#define SIP_FROM4       0x4d4f5246	/* MORF */
#define SIP_FROM2       0x00001a46	/*   :F */
#define SIP_TO3         0x001a4f54	/*  :OT */
#define SIP_TO2         0x00001a54	/*   :T */
#define SIP_CALLID4     0x4c4c4143	/* LLAC */
#define SIP_CALLID2     0x00001a49	/*   :I */
#define SIP_CSEQ4       0x51455343	/* QESC */
#define SIP_CONT4       0x544e4f43	/* TNOC */
#define SIP_CONT2       0x00001a43	/*   :C */
#define SIP_USERAGENT4  0x52455355	/* RESU */
#define SIP_CONT_SDP3   0x00504453	/*  PDS */
/* Encoded SDP field names: */
#define SDP_MAUDIO      0x55411d4d	/* UA=M */
#define SDP_MVIDEO      0x49561d4d	/* IV=M */
#define SDP_CONNECT     0x4e491d43	/* NI=C */

/* Encoded SIP URI start: */
#define SIP_URI         0x1a504953	/* :PIS */
#define SIP_URI_LEN     3
#define SIP_URIS        0x1a535049	/* :SPI */
#define SIP_URIS_LEN    4

/* Length of initial characters to skip in some of SIP or SDP fields: */
#define SIP_STATUS_PAD  8	/* Skip SIP/2.0 */
#define SDP_AUDIO_PAD   8	/* Skip m=audio */
#define SDP_VIDEO_PAD   8	/* Skip m=video */
#define SDP_CONN_PAD    7	/* Skip c=IN IP */
#define SDP_CONN_IP_PAD 9	/* Skip c=IN IP4 */

/*
 * Bits 31, 24, 16, and 8 of this number are zero.  Call these bits
 * the "holes."  Note that there is a hole just to the left of
 * each byte, with an extra at the end:
 *
 * bits:  01111110 11111110 11111110 11111111
 * bytes: AAAAAAAA BBBBBBBB CCCCCCCC DDDDDDDD
 *
 * The 1-bits make sure that carries propagate to the next 0-bit.
 * The 0-bits provide holes for carries to fall into.
 * The magic bits are added to the inspected part of string.
 * If the string contains zero byte, the corresponding hole
 * remains empty. Otherwise it is set to zero due of overflow.
 */

#ifdef __amd64__
#define MAGIC_INT       uint64_t
#define MAGIC_BITS      0x7efefefe7efefeffL
#define MAGIC_BITS_NEG  0x8101010181010100L
#else
#define MAGIC_INT       uint32_t
#define MAGIC_BITS      0x7efefeffL
#define MAGIC_BITS_NEG  0x81010100L
#endif

struct parser_strtok_t {
   parser_strtok_t()
   {
      separator_mask = 0;
      saveptr = NULL;
      separator = 0;
      instrlen = 0;
   }

   MAGIC_INT separator_mask;
   const unsigned char *saveptr;
   char separator;
   unsigned int instrlen;
};

struct FlowRecordExtSIP : FlowRecordExt {
   uint16_t msg_type;                  /* SIP message code (register, invite) < 100 or SIP response status > 100 */
   uint16_t status_code;
   char call_id[SIP_FIELD_LEN];	      /* Call id. For sevice SIP traffic call id = 0 */
   char calling_party[SIP_FIELD_LEN];	/* Calling party (ie. from) uri */
   char called_party[SIP_FIELD_LEN];	/* Called party (ie. to) uri */
   char via[SIP_FIELD_LEN];            /* Via field of SIP packet */
   char user_agent[SIP_FIELD_LEN];     /* User-Agent field of SIP packet */
   char cseq[SIP_FIELD_LEN];           /* CSeq field of SIP packet */
   char request_uri[SIP_FIELD_LEN];    /* Request-URI of SIP request */

   FlowRecordExtSIP() : FlowRecordExt(sip)
   {
      msg_type = 0;
      status_code = 0;
      call_id[0] = 0;
      calling_party[0] = 0;
      called_party[0] = 0;
      via[0] = 0;
      user_agent[0] = 0;
      cseq[0] = 0;
      request_uri[0] = 0;
   }

   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
      ur_set(tmplt, record, F_SIP_MSG_TYPE, msg_type);
      ur_set(tmplt, record, F_SIP_STATUS_CODE, status_code);
      ur_set_string(tmplt, record, F_SIP_CSEQ, cseq);
      ur_set_string(tmplt, record, F_SIP_CALLING_PARTY, calling_party);
      ur_set_string(tmplt, record, F_SIP_CALLED_PARTY, called_party);
      ur_set_string(tmplt, record, F_SIP_CALL_ID, call_id);
      ur_set_string(tmplt, record, F_SIP_USER_AGENT, user_agent);
      ur_set_string(tmplt, record, F_SIP_REQUEST_URI, request_uri);
      ur_set_string(tmplt, record, F_SIP_VIA, via);
   }
};

class SIPPlugin : public FlowCachePlugin {
public:
   SIPPlugin(const options_t &module_options);
   SIPPlugin(const options_t &module_options, vector<plugin_opt> plugin_options);
   int post_create(FlowRecord &rec, const Packet &pkt);
   int pre_update(FlowRecord &rec, Packet &pkt);
   void finish();
   std::string get_unirec_field_string();

private:
   uint16_t parse_msg_type(const Packet &pkt);
   const unsigned char *parser_strtok(const unsigned char *str, unsigned int instrlen, char separator, unsigned int *strlen, parser_strtok_t *nst);
   int parser_process_sip(const Packet &pkt, FlowRecordExtSIP *sip_data);
   void parser_field_uri(const unsigned char *line, int linelen, int skip, char *dst, unsigned int dstlen);
   void parser_field_value(const unsigned char *line, int linelen, int skip, char *dst, unsigned int dstlen);

   bool statsout;
   bool flush_flow;
   uint32_t requests;
   uint32_t responses;
   uint32_t total;
};

#endif
