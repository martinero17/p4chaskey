# P4Chaskey: Tofino implementation of Chaskey

This repository contains the P4 implementation of the Chaskey Message Authentication Code (MAC) algorithm for the Intel Tofino programmable switch architectures (TNA/T2NA).

P4Chaskey computes a MAC of a 16-byte input message.

## Compiling and running the P4 code

To compile the P4 code using Intel's P4 compiler please use the following commands:

- TNA architecture: `bf-p4c --std p4_16 -DTNA chaskey8_ingressegress.p4`
- T2NA architecture: `bf-p4c --std p4_16 --arch t2na --target tofino2 -DT2NA chaskey8_ingressegress.p4`

Please be aware that compilation may take some time.

To run P4Chaskey using the Tofino model please use the following commands:

- Compilation:
  - TNA: `p4_build.sh chaskey8_ingressegress.p4 -DTNA P4_VERSION=p4_16 P4_ARCHITECTURE=tna`
  - T2NA: `p4_build.sh chaskey8_ingressegress.p4 -DT2NA P4_VERSION=p4_16 P4_ARCHITECTURE=t2na`
- Switch driver:
  - TNA: `$SDE/run_switchd.sh -p chaskey8_ingressegress`
  - T2NA: `$SDE/run_switchd.sh --arch tf2 -p chaskey8_ingressegress`
- Switch model:
  - TNA: `$SDE/run_tofino_model.sh -p chaskey8_ingressegress`
  - T2NA: `$SDE/run_tofino_model.sh --arch tf2 -p chaskey8_ingressegress`

## Hash key

Chaskey’s subkeys must be pre-computed off-line. At the beginning of the ingress control flow, the main key and the subkeys are loaded through match-action table entries before processing the input block. Thus, the algorithm's keys can be changed dynamically by simply updating the related table entries.

## Usage

You can run the following command in Scapy to send a simple Ethernet frame with the following 128-bit payload 0x`9cf8c676bbef37aa0daa2f3332ae506a`:
`sendp(Ether(type=0x0)/b"\x9c\xf8\xc6\x76\xbb\xef\x37\xaa\x0d\xaa\x2f\x33\x32\xae\x50\x6a", iface="veth0")`

You can examine the MAC computed by P4Chaskey by sniffing the output packet produced by the Tofino model, with the following command in Scapy:
`sniff(iface="veth0", count=2, prn=lambda p: print(f"Packet (Hex): {bytes(p).hex()}"))`

## Testing

To verify the output obtained with P4Chaskey a test program is provided where a tag is calculated using Chaskey's reference C implementation (available [here](https://mouha.be/chaskey/)). This implementation needed to be slightly modified for the following reasons:

- The program is configured to compute tags according to the Chaskey-12 variant, because of this we changed the permutation block to execute the 8 rounds needed for Chaskey-8
- We also needed to add some logic to receive as an argument the 16Byte message and key

To compile the test program use the following command: `gcc -o chaskey chaskey.c`

To run the test program for the input `9cf8c676bbef37aa0daa2f3332ae506a` and key `fe9db95c4d8c84b4a03eeaec729a1a25` use the following command: `./chaskey.c 9cf8c676bbef37aa0daa2f3332ae506a fe9db95c4d8c84b4a03eeaec729a1a25`
