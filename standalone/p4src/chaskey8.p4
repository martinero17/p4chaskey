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

#define CHSK_PORT 5555
#define RECIRCULATION_PORT 68 
#define CHSK_KEY_SLICE3 0xfe9db95c
#define CHSK_KEY_SLICE2 0x4d8c84b4
#define CHSK_KEY_SLICE1 0xa03eeaec
#define CHSK_KEY_SLICE0 0x729a1a25
#define CHSK_KEY_1_SLICE3 0xfd3b72b8
#define CHSK_KEY_1_SLICE2 0x9b190969
#define CHSK_KEY_1_SLICE1 0x407dd5d8
#define CHSK_KEY_1_SLICE0 0xe534344b

#include "loops_macro.h"

#include <core.p4>

#if TNA
	#include <tna.p4>
	#define NUM_TNA_ROUNDS 2
#elif T2NA
	#include <t2na.p4>
	#define NUM_T2NA_ROUNDS 4
#endif

typedef bit<48> mac_addr_t;
typedef bit<16> ether_type_t;
// We are repurposing the ether_type in this version
// to illustrate our algorithm through a simpler example
const ether_type_t ETHERTYPE_START = 16w0x0;
const ether_type_t ETHERTYPE_RECIRC = 16w0x1;
const ether_type_t ETHERTYPE_FIN = 16w0x2;

header ethernet_h {
	mac_addr_t dst_addr;
	mac_addr_t src_addr;
	bit<16> ether_type;
}

// the parser extract a 128-bit input block into 4 32-bit variables
header chaskey_h {
	bit<32> m_0;
	bit<32> m_1;
	bit<32> m_2;
	bit<32> m_3;
}

// Info to be transmitted across pipelines:
// Internal Chaskey state v_i & current round, fwd decision
header chaskey_meta_h {
	bit<32> v_0;
	bit<32> v_1;
	bit<32> v_2;
	bit<32> v_3;
	bit<16> out_port;
	bit<8>  curr_round;
}

struct header_t {
	ethernet_h ethernet;
	chaskey_meta_h chsk_meta;
	chaskey_h chsk_input;
}

//Temp variables for a permutation round
header chaskey_tmp_h {
	bit<32> a_0;
	bit<32> a_1;
	bit<32> a_2;
	bit<32> a_3;
	bit<32> b_0;
	bit<32> b_1;
	bit<32> b_2;
	bit<32> b_3;
}

struct ig_metadata_t {
	#if TNA
	bit<9> recirc_port;
	#endif
	chaskey_tmp_h chsk_tmp;
}

struct eg_metadata_t {
	chaskey_tmp_h chsk_tmp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
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

		ig_md = {
			#if TNA
			recirc_port = RECIRCULATION_PORT,
			#endif
			chsk_tmp = {
				a_0 = 0,
				a_1 = 0,
				a_2 = 0,
				a_3 = 0,
				b_0 = 0,
				b_1 = 0,
				b_2 = 0,
				b_3 = 0
			}
		};
		
		tofino_parser.apply(pkt, ig_md, ig_intr_md);
		transition parse_ethernet;
	}

	state parse_ethernet {
		pkt.extract(hdr.ethernet);
		transition select (hdr.ethernet.ether_type) {
			ETHERTYPE_START: parse_chaskey;
			ETHERTYPE_RECIRC: parse_chaskey_meta;
			default : reject;
		}
	}

	state parse_chaskey {
		pkt.extract(hdr.chsk_input);
		transition accept;
	}

	state parse_chaskey_meta {
		pkt.extract(hdr.chsk_meta);
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

		eg_md = {
			chsk_tmp = {
				a_0 = 0,
				a_1 = 0,
				a_2 = 0,
				a_3 = 0,
				b_0 = 0,
				b_1 = 0,
				b_2 = 0,
				b_3 = 0
			}
		};

		transition parse_ethernet;
	}

	state parse_ethernet {
		pkt.extract(hdr.ethernet);
		transition parse_chaskey_meta;
	}

	state parse_chaskey_meta {
		pkt.extract(hdr.chsk_meta);
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

	action fwd_decision(){
		hdr.chsk_meta.out_port=(bit<16>) ig_intr_md.ingress_port;
	}

	action fwd_to(bit<9> port){
		ig_intr_tm_md.ucast_egress_port=port;
	}

	action set_next_round(bit<8> next_round){
		hdr.chsk_meta.curr_round = next_round;
	}
	
	
	#if TNA
	action tna_recirc(bit<8> next_round){
		set_next_round(next_round);
		hdr.ethernet.ether_type = ETHERTYPE_RECIRC;
		hdr.chsk_input.setInvalid();
		fwd_to(ig_md.recirc_port);
	}
	#endif

	action do_not_recirc(bit<8> next_round){
		set_next_round(next_round);
		hdr.chsk_input.setInvalid();
		fwd_to((bit<9>)hdr.chsk_meta.out_port);
	}
	
	table tb_fwd_decision {
		key = {
			hdr.chsk_meta.curr_round: exact;
		}
		actions = {
			#if TNA
			tna_recirc;
			#endif
			do_not_recirc;
			NoAction;
		}
		size = 2;

		const entries = {
			//Decides if the pkt will be recirculated after egress based on the architecture
			#if TNA
				(0): tna_recirc(2);
				(4): do_not_recirc(6); // this is a rule for the recirculated pkt in ingress
			#elif T2NA
				(0): do_not_recirc(4);
			#endif
		}

		default_action = NoAction;
	}

	//**************** Permutation Round Actions ***************************//

	// **** START STAGE i ****
	action perm_stage1_a0_ig(){
		//a_0 = v_0 + v_1
		ig_md.chsk_tmp.a_0 = hdr.chsk_meta.v_0 + hdr.chsk_meta.v_1;
	}

	action perm_stage1_a1_ig(){
		//a_1 = v_1 << 5
		@in_hash { ig_md.chsk_tmp.a_1 = hdr.chsk_meta.v_1[26:0] ++ hdr.chsk_meta.v_1[31:27]; }
	}

	action perm_stage1_a2_ig(){
		//a_2 = v_2 + v_3
		ig_md.chsk_tmp.a_2 = hdr.chsk_meta.v_2 + hdr.chsk_meta.v_3;
	}

	action perm_stage1_a3_ig(){
		//a_3 = v_3 << 8
		@in_hash { ig_md.chsk_tmp.a_3 = hdr.chsk_meta.v_3[23:0] ++ hdr.chsk_meta.v_3[31:24]; }	
	}
	// **** END STAGE i ****

	// **** START STAGE i+1 ****
	action perm_stage2_b0_ig(){
		//b_0 = a_0 << 16
		@in_hash { ig_md.chsk_tmp.b_0 = ig_md.chsk_tmp.a_0[15:0] ++ ig_md.chsk_tmp.a_0[31:16]; }
	}

	action perm_stage2_b1_ig(){
		//b_1 = a_1 ^ a_0
		ig_md.chsk_tmp.b_1 = ig_md.chsk_tmp.a_1 ^ ig_md.chsk_tmp.a_0;
	}

	action perm_stage2_b2_ig(){
		//b_2 = a_2
		ig_md.chsk_tmp.b_2 = ig_md.chsk_tmp.a_2;
	}

	action perm_stage2_b3_ig(){
		//b_3 = a_3 ^ a_2
		ig_md.chsk_tmp.b_3 = ig_md.chsk_tmp.a_3 ^ ig_md.chsk_tmp.a_2;
	}
	// **** END STAGE i+1 ****

	// **** START STAGE i+2 ****
	action perm_stage3_a0_ig(){
		//a_0 = b_0 + b_3
		ig_md.chsk_tmp.a_0 = ig_md.chsk_tmp.b_0 + ig_md.chsk_tmp.b_3;
	}

	action perm_stage3_a1_ig(){
		//a_1 = b_1 << 7
		@in_hash { ig_md.chsk_tmp.a_1 = ig_md.chsk_tmp.b_1[24:0] ++ ig_md.chsk_tmp.b_1[31:25]; }
	}

	action perm_stage3_a2_ig(){
		//a_2 = b_2 + b_1
		ig_md.chsk_tmp.a_2 = ig_md.chsk_tmp.b_2 + ig_md.chsk_tmp.b_1;
	}

	action perm_stage3_a3_ig(){
		//a_3 = b_3 << 13
		@in_hash { ig_md.chsk_tmp.a_3 = ig_md.chsk_tmp.b_3[18:0] ++ ig_md.chsk_tmp.b_3[31:19]; }
	}
	// **** END STAGE i+2 ****

	// **** START STAGE i+3 ****
	action perm_stage4_v0_ig(){
		//v_0 = a_0
		hdr.chsk_meta.v_0 = ig_md.chsk_tmp.a_0;
	}

	action perm_stage4_v1_ig(){
		//v_1 = a_1 ^ a_2
		hdr.chsk_meta.v_1 = ig_md.chsk_tmp.a_1 ^ ig_md.chsk_tmp.a_2;
	}

	action perm_stage4_v2_ig(){
		//v_2 = v_2 << 16
		@in_hash { hdr.chsk_meta.v_2 = ig_md.chsk_tmp.a_2[15:0] ++ ig_md.chsk_tmp.a_2[31:16]; }
	}
	
	action perm_stage4_v3_ig(){
		//v_3 = v_3 ^ v_0 i
		hdr.chsk_meta.v_3 = ig_md.chsk_tmp.a_3 ^ ig_md.chsk_tmp.a_0;
	}
	// **** END STAGE i+3 ****

	
	//*********************************************************************************//

	action start_final_perm(bit<32> chsk_key_slice3, bit<32> chsk_key_slice2, bit<32> chsk_key_slice1, bit<32> chsk_key_slice0){
		hdr.chsk_meta.v_0 = hdr.chsk_meta.v_0 ^ chsk_key_slice3;
		hdr.chsk_meta.v_1 = hdr.chsk_meta.v_1 ^ chsk_key_slice2;
		hdr.chsk_meta.v_2 = hdr.chsk_meta.v_2 ^ chsk_key_slice1;
		hdr.chsk_meta.v_3 = hdr.chsk_meta.v_3 ^ chsk_key_slice0;
	}

	table tb_start_perm {
		key = {
			hdr.chsk_meta.curr_round: exact;
		}
		size = 2;
		actions = {
			start_final_perm;
			NoAction;
		}
		default_action = NoAction;
		const entries = {
			(0) : start_final_perm(CHSK_KEY_1_SLICE3, CHSK_KEY_1_SLICE2, CHSK_KEY_1_SLICE1, CHSK_KEY_1_SLICE0);
		}
	}

	action chaskey_init(bit<32> chsk_key_slice3, bit<32> chsk_key_slice2, bit<32> chsk_key_slice1, bit<32> chsk_key_slice0){
		// Activate chaskey header
		hdr.chsk_meta.setValid();
		// start counting permutation rounds
		hdr.chsk_meta.curr_round = 0;

		// Algorithm's Internal state v_i set-up
		hdr.chsk_meta.v_0 = chsk_key_slice3 ^ hdr.chsk_input.m_0;
		hdr.chsk_meta.v_1 = chsk_key_slice2 ^ hdr.chsk_input.m_1;
		hdr.chsk_meta.v_2 = chsk_key_slice1 ^ hdr.chsk_input.m_2;
		hdr.chsk_meta.v_3 = chsk_key_slice0 ^ hdr.chsk_input.m_3;

		fwd_decision();
	}

	//Table for the preparation of the first permutation round
	table tb_init {
		key = {
			hdr.chsk_meta.isValid(): exact;
		}
		size = 2;
		actions = {
			chaskey_init;
			NoAction;
		}

 		const entries = {
            		( true ) : NoAction();
            		( false ) : chaskey_init(CHSK_KEY_SLICE3, CHSK_KEY_SLICE2, CHSK_KEY_SLICE1, CHSK_KEY_SLICE0);
        	}

		default_action = NoAction;
	}

	apply {
		tb_init.apply();
		tb_start_perm.apply();

		#define perm_rounds_ig(i) perm_stage1_a0_ig(); perm_stage1_a1_ig(); perm_stage1_a2_ig(); perm_stage1_a3_ig(); \
		perm_stage2_b0_ig(); perm_stage2_b1_ig(); perm_stage2_b2_ig(); perm_stage2_b3_ig(); \
		perm_stage3_a0_ig(); perm_stage3_a1_ig(); perm_stage3_a2_ig(); perm_stage3_a3_ig(); \
		perm_stage4_v0_ig(); perm_stage4_v1_ig(); perm_stage4_v2_ig(); perm_stage4_v3_ig();

		#if TNA
			__LOOP(NUM_TNA_ROUNDS,perm_rounds_ig)
		#elif T2NA
			__LOOP(NUM_T2NA_ROUNDS,perm_rounds_ig)
		#endif

		tb_fwd_decision.apply();
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

	action final_xor(bit<32> chsk_key_slice3, bit<32> chsk_key_slice2, bit<32> chsk_key_slice1, bit<32> chsk_key_slice0){
		hdr.chsk_meta.v_0 = hdr.chsk_meta.v_0 ^ chsk_key_slice3;
		hdr.chsk_meta.v_1 = hdr.chsk_meta.v_1 ^ chsk_key_slice2;	
		hdr.chsk_meta.v_2 = hdr.chsk_meta.v_2 ^ chsk_key_slice1;	
		hdr.chsk_meta.v_3 = hdr.chsk_meta.v_3 ^ chsk_key_slice0;

		//Clean remaining metadata
		hdr.chsk_meta.out_port = 0;
		hdr.chsk_meta.curr_round = 0;

		//Set ether_type to FIN
		hdr.ethernet.ether_type = ETHERTYPE_FIN;
	}

	action set_next_round(bit<8> next_round){
		hdr.chsk_meta.curr_round = next_round;
	}

	table tb_chaskey_fin {
		key = {
			hdr.chsk_meta.curr_round: exact;
		}
		actions = {
			final_xor;
			set_next_round;
			NoAction;
		}
		size = 2;
		default_action = NoAction;
		const entries = {
			#if TNA
				(2) : set_next_round(4);
				(6) : final_xor(CHSK_KEY_1_SLICE3, CHSK_KEY_1_SLICE2, CHSK_KEY_1_SLICE1, CHSK_KEY_1_SLICE0);
			#elif T2NA
				(4) : final_xor(CHSK_KEY_1_SLICE3, CHSK_KEY_1_SLICE2, CHSK_KEY_1_SLICE1, CHSK_KEY_1_SLICE0);
			#endif
		}
	}


	//**************** Permutation Round Actions ***************************//

	// **** START STAGE i ****
	action perm_stage1_a0_eg(){
		//a_0 = v_0 + v_1
		eg_md.chsk_tmp.a_0 = hdr.chsk_meta.v_0 + hdr.chsk_meta.v_1;
	}

	action perm_stage1_a1_eg(){
		//a_1 = v_1 << 5
		@in_hash { eg_md.chsk_tmp.a_1 = hdr.chsk_meta.v_1[26:0] ++ hdr.chsk_meta.v_1[31:27]; }
	}

	action perm_stage1_a2_eg(){
		//a_2 = v_2 + v_3
		eg_md.chsk_tmp.a_2 = hdr.chsk_meta.v_2 + hdr.chsk_meta.v_3;
	}

	action perm_stage1_a3_eg(){
		//a_3 = v_3 << 8
		@in_hash { eg_md.chsk_tmp.a_3 = hdr.chsk_meta.v_3[23:0] ++ hdr.chsk_meta.v_3[31:24]; }	
	}
	// **** END STAGE i ****

	// **** START STAGE i+1 ****
	action perm_stage2_b0_eg(){
		//b_0 = a_0 << 16
		@in_hash { eg_md.chsk_tmp.b_0 = eg_md.chsk_tmp.a_0[15:0] ++ eg_md.chsk_tmp.a_0[31:16]; }
	}

	action perm_stage2_b1_eg(){
		//b_1 = a_1 ^ a_0
		eg_md.chsk_tmp.b_1 = eg_md.chsk_tmp.a_1 ^ eg_md.chsk_tmp.a_0;
	}

	action perm_stage2_b2_eg(){
		//b_2 = a_2
		eg_md.chsk_tmp.b_2 = eg_md.chsk_tmp.a_2;
	}

	action perm_stage2_b3_eg(){
		//b_3 = a_3 ^ a_2
		eg_md.chsk_tmp.b_3 = eg_md.chsk_tmp.a_3 ^ eg_md.chsk_tmp.a_2;
	}
	// **** END STAGE i+1 ****

	// **** START STAGE i+2 ****
	action perm_stage3_a0_eg(){
		//a_0 = b_0 + b_3
		eg_md.chsk_tmp.a_0 = eg_md.chsk_tmp.b_0 + eg_md.chsk_tmp.b_3;
	}

	action perm_stage3_a1_eg(){
		//a_1 = b_1 << 7
		@in_hash { eg_md.chsk_tmp.a_1 = eg_md.chsk_tmp.b_1[24:0] ++ eg_md.chsk_tmp.b_1[31:25]; }
	}

	action perm_stage3_a2_eg(){
		//a_2 = b_2 + b_1
		eg_md.chsk_tmp.a_2 = eg_md.chsk_tmp.b_2 + eg_md.chsk_tmp.b_1;
	}

	action perm_stage3_a3_eg(){
		//a_3 = b_3 << 13
		@in_hash { eg_md.chsk_tmp.a_3 = eg_md.chsk_tmp.b_3[18:0] ++ eg_md.chsk_tmp.b_3[31:19]; }
	}
	// **** END STAGE i+2 ****

	// **** START STAGE i+3 ****
	action perm_stage4_v0_eg(){
		//v_0 = a_0
		hdr.chsk_meta.v_0 = eg_md.chsk_tmp.a_0;
	}

	action perm_stage4_v1_eg(){
		//v_1 = a_1 ^ a_2
		hdr.chsk_meta.v_1 = eg_md.chsk_tmp.a_1 ^ eg_md.chsk_tmp.a_2;
	}

	action perm_stage4_v2_eg(){
		//v_2 = v_2 << 16
		@in_hash { hdr.chsk_meta.v_2 = eg_md.chsk_tmp.a_2[15:0] ++ eg_md.chsk_tmp.a_2[31:16]; }
	}
	
	action perm_stage4_v3_eg(){
		//v_3 = v_3 ^ v_0 i
		hdr.chsk_meta.v_3 = eg_md.chsk_tmp.a_3 ^ eg_md.chsk_tmp.a_0;
	}
	// **** END STAGE i+3 ****

	
	//*********************************************************************************//

	apply {
		//Setup
		if(hdr.chsk_meta.isValid()) {

			#define perm_rounds_eg(i) perm_stage1_a0_eg(); perm_stage1_a1_eg(); perm_stage1_a2_eg(); perm_stage1_a3_eg(); \
			perm_stage2_b0_eg(); perm_stage2_b1_eg(); perm_stage2_b2_eg(); perm_stage2_b3_eg(); \
			perm_stage3_a0_eg(); perm_stage3_a1_eg(); perm_stage3_a2_eg(); perm_stage3_a3_eg(); \
			perm_stage4_v0_eg(); perm_stage4_v1_eg(); perm_stage4_v2_eg(); perm_stage4_v3_eg();

			#if TNA
				__LOOP(NUM_TNA_ROUNDS,perm_rounds_eg)
			#elif T2NA
				__LOOP(NUM_T2NA_ROUNDS,perm_rounds_eg)
			#endif

			// Chaskey Finish Table
			tb_chaskey_fin.apply();
		}
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
		pkt.emit(hdr.chsk_meta);
	}
}

control SwitchEgressDeparser(
		packet_out pkt,
		inout header_t hdr,
		in eg_metadata_t eg_md,
		in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
	
	apply {
		pkt.emit(hdr.ethernet);
		pkt.emit(hdr.chsk_meta);
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
