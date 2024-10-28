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

#include <t2na.p4>
#define NUM_T2NA_ROUNDS 4

header chaskey_h {
	bit<32> v_0;
	bit<32> v_1;
	bit<32> v_2;
	bit<32> v_3;
	bit<8>  curr_round;
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control ChaskeyIngress(
		inout chaskey_h chsk
	) {

	action set_next_round(bit<8> next_round){
		chsk.curr_round = next_round;
	}
	
	table tb_update_round {
		key = {
			chsk.curr_round: exact;
		}
		actions = {
			set_next_round;
			NoAction;
		}
		size = 2;

		const entries = {
			(0): set_next_round(4);
		}

		default_action = NoAction;
	}

	//**************** Permutation Round Actions ***************************//

	//******************* Chaskey Permutation Round - Temporary Variables ***************************//
	bit<32> a_0;
	bit<32> a_1;
	bit<32> a_2;
	bit<32> a_3;
	bit<32> b_0;
	bit<32> b_1;
	bit<32> b_2;
	bit<32> b_3;
	//*********************************************************************************//

	// **** START STAGE i ****
	action perm_stage1_a0_ig(){
		//a_0 = v_0 + v_1
		a_0 = chsk.v_0 + chsk.v_1;
	}

	action perm_stage1_a1_ig(){
		//a_1 = v_1 << 5
		@in_hash { a_1 = chsk.v_1[26:0] ++ chsk.v_1[31:27]; }
	}

	action perm_stage1_a2_ig(){
		//a_2 = v_2 + v_3
		a_2 = chsk.v_2 + chsk.v_3;
	}

	action perm_stage1_a3_ig(){
		//a_3 = v_3 << 8
		@in_hash { a_3 = chsk.v_3[23:0] ++ chsk.v_3[31:24]; }	
	}
	// **** END STAGE i ****

	// **** START STAGE i+1 ****
	action perm_stage2_b0_ig(){
		//b_0 = a_0 << 16
		@in_hash { b_0 = a_0[15:0] ++ a_0[31:16]; }
	}

	action perm_stage2_b1_ig(){
		//b_1 = a_1 ^ a_0
		b_1 = a_1 ^ a_0;
	}

	action perm_stage2_b2_ig(){
		//b_2 = a_2
		b_2 = a_2;
	}

	action perm_stage2_b3_ig(){
		//b_3 = a_3 ^ a_2
		b_3 = a_3 ^ a_2;
	}
	// **** END STAGE i+1 ****

	// **** START STAGE i+2 ****
	action perm_stage3_a0_ig(){
		//a_0 = b_0 + b_3
		a_0 = b_0 + b_3;
	}

	action perm_stage3_a1_ig(){
		//a_1 = b_1 << 7
		@in_hash { a_1 = b_1[24:0] ++ b_1[31:25]; }
	}

	action perm_stage3_a2_ig(){
		//a_2 = b_2 + b_1
		a_2 = b_2 + b_1;
	}

	action perm_stage3_a3_ig(){
		//a_3 = b_3 << 13
		@in_hash { a_3 = b_3[18:0] ++ b_3[31:19]; }
	}
	// **** END STAGE i+2 ****

	// **** START STAGE i+3 ****
	action perm_stage4_v0_ig(){
		//v_0 = a_0
		chsk.v_0 = a_0;
	}

	action perm_stage4_v1_ig(){
		//v_1 = a_1 ^ a_2
		chsk.v_1 = a_1 ^ a_2;
	}

	action perm_stage4_v2_ig(){
		//v_2 = v_2 << 16
		@in_hash { chsk.v_2 = a_2[15:0] ++ a_2[31:16]; }
	}
	
	action perm_stage4_v3_ig(){
		//v_3 = v_3 ^ v_0 i
		chsk.v_3 = a_3 ^ a_0;
	}
	// **** END STAGE i+3 ****

	
	//*********************************************************************************//

	action start_final_perm(bit<32> chsk_key_slice3, bit<32> chsk_key_slice2, bit<32> chsk_key_slice1, bit<32> chsk_key_slice0){
		chsk.v_0 = chsk.v_0 ^ chsk_key_slice3;
		chsk.v_1 = chsk.v_1 ^ chsk_key_slice2;
		chsk.v_2 = chsk.v_2 ^ chsk_key_slice1;
		chsk.v_3 = chsk.v_3 ^ chsk_key_slice0;
	}

	table tb_start_perm {
		key = {
			chsk.curr_round: exact;
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
		chsk.setValid();
		// start counting permutation rounds
		chsk.curr_round = 0;

		// Algorithm's Internal state v_i set-up
		chsk.v_0 = chsk_key_slice3 ^ chsk.v_0;
		chsk.v_1 = chsk_key_slice2 ^ chsk.v_1;
		chsk.v_2 = chsk_key_slice1 ^ chsk.v_2;
		chsk.v_3 = chsk_key_slice0 ^ chsk.v_3;
	}

	//Table for the preparation of the first permutation round
	table tb_init {
		key = {
			chsk.isValid(): exact;
		}
		size = 2;
		actions = {
			chaskey_init;
			NoAction;
		}

 		const entries = {
            		( true ) : chaskey_init(CHSK_KEY_SLICE3, CHSK_KEY_SLICE2, CHSK_KEY_SLICE1, CHSK_KEY_SLICE0);
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

		__LOOP(NUM_T2NA_ROUNDS,perm_rounds_ig)

		tb_update_round.apply();
	}
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control ChaskeyEgress(
		inout chaskey_h chsk
	) {

	action final_xor(bit<32> chsk_key_slice3, bit<32> chsk_key_slice2, bit<32> chsk_key_slice1, bit<32> chsk_key_slice0){
		chsk.v_0 = chsk.v_0 ^ chsk_key_slice3;
		chsk.v_1 = chsk.v_1 ^ chsk_key_slice2;	
		chsk.v_2 = chsk.v_2 ^ chsk_key_slice1;	
		chsk.v_3 = chsk.v_3 ^ chsk_key_slice0;

		//Clean remaining metadata
		chsk.curr_round = 0;
	}

	action set_next_round(bit<8> next_round){
		chsk.curr_round = next_round;
	}

	table tb_chaskey_fin {
		key = {
			chsk.curr_round: exact;
		}
		actions = {
			final_xor;
			NoAction;
		}
		size = 2;
		default_action = NoAction;
		const entries = {
			(4) : final_xor(CHSK_KEY_1_SLICE3, CHSK_KEY_1_SLICE2, CHSK_KEY_1_SLICE1, CHSK_KEY_1_SLICE0);
		}
	}


	//**************** Permutation Round Actions ***************************//

	//******************* Chaskey Permutation Round - Temporary Variables ***************************//
	bit<32> a_0;
	bit<32> a_1;
	bit<32> a_2;
	bit<32> a_3;
	bit<32> b_0;
	bit<32> b_1;
	bit<32> b_2;
	bit<32> b_3;
	//*********************************************************************************//

	// **** START STAGE i ****
	action perm_stage1_a0_eg(){
		//a_0 = v_0 + v_1
		a_0 = chsk.v_0 + chsk.v_1;
	}

	action perm_stage1_a1_eg(){
		//a_1 = v_1 << 5
		@in_hash { a_1 = chsk.v_1[26:0] ++ chsk.v_1[31:27]; }
	}

	action perm_stage1_a2_eg(){
		//a_2 = v_2 + v_3
		a_2 = chsk.v_2 + chsk.v_3;
	}

	action perm_stage1_a3_eg(){
		//a_3 = v_3 << 8
		@in_hash { a_3 = chsk.v_3[23:0] ++ chsk.v_3[31:24]; }	
	}
	// **** END STAGE i ****

	// **** START STAGE i+1 ****
	action perm_stage2_b0_eg(){
		//b_0 = a_0 << 16
		@in_hash { b_0 = a_0[15:0] ++ a_0[31:16]; }
	}

	action perm_stage2_b1_eg(){
		//b_1 = a_1 ^ a_0
		b_1 = a_1 ^ a_0;
	}

	action perm_stage2_b2_eg(){
		//b_2 = a_2
		b_2 = a_2;
	}

	action perm_stage2_b3_eg(){
		//b_3 = a_3 ^ a_2
		b_3 = a_3 ^ a_2;
	}
	// **** END STAGE i+1 ****

	// **** START STAGE i+2 ****
	action perm_stage3_a0_eg(){
		//a_0 = b_0 + b_3
		a_0 = b_0 + b_3;
	}

	action perm_stage3_a1_eg(){
		//a_1 = b_1 << 7
		@in_hash { a_1 = b_1[24:0] ++ b_1[31:25]; }
	}

	action perm_stage3_a2_eg(){
		//a_2 = b_2 + b_1
		a_2 = b_2 + b_1;
	}

	action perm_stage3_a3_eg(){
		//a_3 = b_3 << 13
		@in_hash { a_3 = b_3[18:0] ++ b_3[31:19]; }
	}
	// **** END STAGE i+2 ****

	// **** START STAGE i+3 ****
	action perm_stage4_v0_eg(){
		//v_0 = a_0
		chsk.v_0 = a_0;
	}

	action perm_stage4_v1_eg(){
		//v_1 = a_1 ^ a_2
		chsk.v_1 = a_1 ^ a_2;
	}

	action perm_stage4_v2_eg(){
		//v_2 = v_2 << 16
		@in_hash { chsk.v_2 = a_2[15:0] ++ a_2[31:16]; }
	}
	
	action perm_stage4_v3_eg(){
		//v_3 = v_3 ^ v_0 i
		chsk.v_3 = a_3 ^ a_0;
	}
	// **** END STAGE i+3 ****

	
	//*********************************************************************************//

	apply {
		//Setup
		if(chsk.isValid()) {

			#define perm_rounds_eg(i) perm_stage1_a0_eg(); perm_stage1_a1_eg(); perm_stage1_a2_eg(); perm_stage1_a3_eg(); \
			perm_stage2_b0_eg(); perm_stage2_b1_eg(); perm_stage2_b2_eg(); perm_stage2_b3_eg(); \
			perm_stage3_a0_eg(); perm_stage3_a1_eg(); perm_stage3_a2_eg(); perm_stage3_a3_eg(); \
			perm_stage4_v0_eg(); perm_stage4_v1_eg(); perm_stage4_v2_eg(); perm_stage4_v3_eg();

			__LOOP(NUM_T2NA_ROUNDS,perm_rounds_eg)

			// Chaskey Finish Table
			tb_chaskey_fin.apply();
		}
	}
}