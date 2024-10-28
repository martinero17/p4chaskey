/*
	P4Chaskey: Chaskey8 MAC algorithm in P4
	Copyright (C) 2024  Martim Francisco & Salvatore Signorello, Universidade de Lisboa
	mfrancisco [at] lasige.di.fc.ul.pt

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <core.p4>
#include <t2na.p4>

#include "chaskey8.p4"

typedef bit<48> mac_addr_t;
typedef bit<16> ether_type_t;

header ethernet_h {
	mac_addr_t  dst_addr;
	mac_addr_t  src_addr;
	bit<16>     ether_type;
}

header ipv6_h {
    bit<4>      version;
    bit<8>      traffic_class;
    bit<20>     flow_label;
    bit<16>     payload_length;
    bit<8>      next_header;
    bit<8>      hop_limit;
    bit<128>    src_addr;
    bit<128>    dst_addr;
}

struct header_t {
	ethernet_h  ethernet;
    ipv6_h      ipv6;
	chaskey_h   chaskey;
}

struct ig_metadata_t {

}

struct eg_metadata_t {

}

/*************************************************************************
*********************** P A R S E R  ************************************
*************************************************************************/

parser TofinoIngressParser(
		packet_in pkt,
		inout ig_metadata_t ig_md,
		out ingress_intrinsic_metadata_t ig_intr_md) {
			
	state start {
		pkt.extract(ig_intr_md);
		transition select(ig_intr_md.resubmit_flag) {
			1 : parse_resubmit;
			0 : parse_port_metadata;
		}
	}

	state parse_resubmit {
		transition reject;
	}

	state parse_port_metadata {
		pkt.advance(PORT_METADATA_SIZE); 
		transition accept;
	}
}

parser SwitchIngressParser(
		packet_in pkt,
		out header_t hdr,
		out ig_metadata_t ig_md,
		out ingress_intrinsic_metadata_t ig_intr_md) {

	TofinoIngressParser() tofino_parser;

	state start {
        tofino_parser.apply(pkt, ig_md, ig_intr_md);
		transition parse_ethernet;
	}

	state parse_ethernet {
		pkt.extract(hdr.ethernet);
		transition parse_ipv6;
	}

    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        transition accept;
    }
}

parser TofinoEgressParser(
		packet_in pkt,
		out egress_intrinsic_metadata_t eg_intr_md) {

	state start {
		pkt.extract(eg_intr_md);
		transition accept;
	}
}

parser SwitchEgressParser(
		packet_in pkt,
		out header_t hdr,
		out eg_metadata_t eg_md,
		out egress_intrinsic_metadata_t eg_intr_md) {

	TofinoEgressParser() tofino_parser;

	state start {
        tofino_parser.apply(pkt, eg_intr_md);
		transition parse_ethernet;
	}

	state parse_ethernet {
		pkt.extract(hdr.ethernet);
		transition parse_ipv6;
	}

    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        transition parse_chaskey;
    }

    state parse_chaskey {
        pkt.extract(hdr.chaskey);
        transition accept;
    }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control SwitchIngress(
		inout header_t hdr,
		inout ig_metadata_t ig_md,
		in ingress_intrinsic_metadata_t ig_intr_md,
		in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
		inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
		inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    action swap_mac(){
        mac_addr_t tmp;
        tmp = hdr.ethernet.src_addr;
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = tmp;
    }

    action fwd_decision(){
        ig_intr_tm_md.ucast_egress_port = ig_intr_md.ingress_port;
    }

    action init_chaskey() {
        hdr.chaskey.curr_round = 0;
        hdr.chaskey.v_0 = hdr.ipv6.src_addr[127:96];
        hdr.chaskey.v_1 = hdr.ipv6.src_addr[95:64];
        hdr.chaskey.v_2 = hdr.ipv6.src_addr[63:32];
        hdr.chaskey.v_3 = hdr.ipv6.src_addr[31:0];
    }

    ChaskeyIngress() chsk_ingress;

	apply {
        hdr.chaskey.setValid();
        
        init_chaskey();
        chsk_ingress.apply(hdr.chaskey);

        swap_mac();
        fwd_decision();
	}
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control SwitchEgress(
		inout header_t hdr,
		inout eg_metadata_t eg_md,
		in egress_intrinsic_metadata_t eg_intr_md,
		in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
		inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
		inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

    action drop(){
		eg_intr_md_for_dprsr.drop_ctl = 0x1; // Drop packet.
	}

    table tbl_verify_mac {
        key = {
            hdr.chaskey.v_0: exact;
            hdr.chaskey.v_1: exact;
            hdr.chaskey.v_2: exact;
            hdr.chaskey.v_3: exact;
        }
        actions = {
            drop;
            NoAction;
        }
        size = 1;
        default_action = drop;
        const entries = {
            (0xf947b90e, 0x1792b283, 0xdbce758f, 0xe8e753a6): NoAction();
        }
    }

    ChaskeyEgress() chsk_egress;

	apply {
        chsk_egress.apply(hdr.chaskey);

        tbl_verify_mac.apply();

        hdr.chaskey.setValid();
	}
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control SwitchIngressDeparser(
		packet_out pkt,
		inout header_t hdr,
		in ig_metadata_t ig_md,
		in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

	apply {
		pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv6);
        pkt.emit(hdr.chaskey);
	}
}

control SwitchEgressDeparser(
		packet_out pkt,
		inout header_t hdr,
		in eg_metadata_t eg_md,
		in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
	
	apply {
		pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv6);
	}
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

Pipeline(SwitchIngressParser(),
		SwitchIngress(),
		SwitchIngressDeparser(),
		SwitchEgressParser(),
		SwitchEgress(),
		SwitchEgressDeparser()
	) pipe;

Switch(pipe) main;
