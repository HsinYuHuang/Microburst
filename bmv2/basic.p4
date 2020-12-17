/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>


#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_GO_ABSORB 0xBF01
#define ETHERTYPE_NO_ABSORB 0xBF02
#define ETHERTYPE_BOUNCE 0xBF03
#define ETHERTYPE_QLEN 0xBF04
#define IP_PROTOCOLS_TCP 6
#define THRESHOLD 20000

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header vlan_tag_t {
    bit<3>  pcp;
    bit<1>  cfi;
    bit<12> vid;
    bit<16> etherType;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header go_absorb_t {
    bit<7>  padding;
    bit<9>  port_num;
    bit<32> deq_timedelta;
    bit<48> ingress_global;
    bit<48> egress_global;
}

header no_absorb_t {
    bit<7>  padding;
    bit<9>  port_num;
    bit<32> deq_timedelta;
    bit<48> ingress_global;
    bit<48> egress_global;
}

header bounce_sequence_t {
    bit<32> seq_num;
}

header queue_length_t {
    bit<5>  has_bounce_seq;
    bit<19> qlen;
}

header local_meta_t {
    bit<19> qlen;
    bit<5>  _pad1;
    bit<12>  q_predicate;
    bit<4>  gate_predicate;
    bit<8>  need_bounce;
    bit<48> timestamp;
    bit<32> flowlet_ts;
    bit<16> hash_temp;
    // bit<1>  _pad2;
    bit<32> sequence_1;
    bit<32> sequence_2;
    bit<32> new_seq;
    bit<1> after_flowlet;
    bit<1>  new_flowlet;
    bit<1>  prev_full;
    bit<5>  _pad3;
    bit<19> prev_qlen;
    bit<5>  _pad4;
    bit<9>  ig_port;
    bit<7>  _pad5;
    bit<9>  bounce_port;
    bit<7>  _pad6;
    bit<9>  min_port;
    bit<7>  _pad7;
    bit<32> update_port;
}

header mirror_meta_t {
    bit<1>  m_type;
    bit<7>  _pad1;
    bit<9>  m_port;
    bit<7>  _pad2;
    bit<48> ing_tstamp;
    bit<48> eg_tstamp;
    bit<32> qlen;
}

struct metadata {
    local_meta_t    local_meta;
    mirror_meta_t   mirror_meta;
}

struct headers {
    ethernet_t          ethernet;
    vlan_tag_t          vlan_tag;
    ipv4_t              ipv4;
    tcp_t               tcp;
    go_absorb_t         go_absorb;
    no_absorb_t         no_absorb;
    bounce_sequence_t   bounce_sequence;
    queue_length_t      queue_length;
}
/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in pkt,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_VLAN :        parse_vlan_tag;
            ETHERTYPE_IPV4 :        parse_ipv4;
            ETHERTYPE_GO_ABSORB:    parse_go_absorb;
            ETHERTYPE_NO_ABSORB:    parse_no_absorb;
            ETHERTYPE_BOUNCE:       parse_bounce_sequence;
            ETHERTYPE_QLEN:         parse_queue_length;
            default: accept;
        }
    }

    state parse_vlan_tag {
        pkt.extract(hdr.vlan_tag);
        transition select(hdr.vlan_tag.etherType) {
            // ETHERTYPE_IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_go_absorb {
        pkt.extract(hdr.go_absorb);
        transition parse_ipv4;
    }

    state parse_no_absorb {
        pkt.extract(hdr.no_absorb);
        transition parse_ipv4;
    }

    state parse_bounce_sequence {
        pkt.extract(hdr.bounce_sequence);
        transition parse_ipv4;
    }

    state parse_queue_length {
        pkt.extract(hdr.queue_length);
        transition select(hdr.queue_length.has_bounce_seq) {
            1: parse_bounce_sequence;
            default: parse_ipv4;
        }
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    register<bit<8>>(511)   stat;
    register<bit<32>>(1)    min_quene;
    register<bit<16>>(1)    min_port;
    register<bit<32>>(65536)    flowlet_state;
    register<bit<1>>(65535)     flowlet_ver;
    register<bit<32>>(65536)    check_seq_flowlet;
    register<bit<32>>(65536)    seq_receive;
    register<bit<32>>(65536)    sequence_sent;
    bit<32> check_quene;
    bit<16> check_port;
    bit<8> check_bounce;
    bit<32> check_flowlet;
    bit<32> check_flowlet2;
    bit<32> check_seq;
    bit<32> check_seq2;
    bit<32> seq_count;
    bit<1>  check_flowlet_ver;
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action set_egr(egressSpec_t port) {
        standard_metadata.egress_spec = port;
        // hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table forward {
        key = {
            standard_metadata.ingress_port : exact;
            hdr.ethernet.dstAddr : exact;
        }
        actions = {
            set_egr;
            NoAction;
        }
        // default_action = drop;
    }

    action _test2() {
        standard_metadata.egress_spec = 137;
    }

    table test2 {
        actions = {
            _test2;
        }
        default_action = _test2;
    }

    action _set_default_bounce_port() {
        meta.local_meta.prev_qlen = hdr.queue_length.qlen;
        meta.local_meta.ig_port = standard_metadata.ingress_port;
        meta.local_meta.bounce_port = standard_metadata.ingress_port;
    }

    table set_default_bounce_port {
        actions = { _set_default_bounce_port; }
        default_action = _set_default_bounce_port;
    }

    action _get_bounce_port_prepare() {
        hdr.queue_length.setInvalid();
        hdr.ethernet.etherType = ETHERTYPE_IPV4;
    }

    table get_bounce_port_prepare {
        actions = { _get_bounce_port_prepare; }
        default_action = _get_bounce_port_prepare;
    }

    action _bounce_to_min() {
        meta.local_meta.bounce_port = meta.local_meta.min_port;
    }

    table bounce_to_min {
        actions = { _bounce_to_min; }
        default_action = _bounce_to_min;
    }

    action set_flowlet_ts() {
        meta.local_meta.flowlet_ts = (bit<32>)meta.local_meta.timestamp;
    }

    table flowlet_prepare2 {
        actions = { set_flowlet_ts; }
        default_action = set_flowlet_ts;
    }

    action _read_seq_from_header() {
        meta.local_meta.sequence_1 = hdr.bounce_sequence.seq_num;
    }
    table read_seq_from_header {
        actions = { _read_seq_from_header; }
        default_action = _read_seq_from_header;
    }

    action _remove_sequence() {
        hdr.bounce_sequence.setInvalid();
        hdr.ethernet.etherType = ETHERTYPE_IPV4;
        hdr.ethernet.dstAddr = (bit<48>)meta.local_meta.bounce_port;
        hdr.ethernet.srcAddr = (bit<48>)hdr.queue_length.qlen;
    }

    table remove_sequence {
        actions = {
            _remove_sequence;
        }
        default_action = _remove_sequence;
    }

    action _bounce() {
        hdr.ethernet.etherType = ETHERTYPE_BOUNCE;
        standard_metadata.egress_spec = meta.local_meta.bounce_port;
    }

    table bounce {
        actions = {
            _bounce;
        }
        default_action = _bounce;
    }

    action _add_seq2() {
        hdr.bounce_sequence.setValid();
        hdr.bounce_sequence.seq_num = meta.local_meta.sequence_2;
        hdr.ethernet.etherType = ETHERTYPE_BOUNCE;
    }

    table add_seq2 {
        actions = { _add_seq2; }
        default_action = _add_seq2;
    }

    action _rm() {
        hdr.queue_length.setInvalid();
        hdr.ethernet.etherType = ETHERTYPE_IPV4;
    }

    table remove_queue_length {
        actions = { _rm; }
        default_action = _rm;
    }
    
    apply {
        forward.apply();
        if (hdr.go_absorb.isValid()) {
            if (standard_metadata.ingress_port == standard_metadata.egress_spec) { }
            else {
                stat.write((bit<32>)hdr.go_absorb.port_num, 1);
                test2.apply();
            }
        } else if(hdr.no_absorb.isValid()) {
            if (standard_metadata.ingress_port == standard_metadata.egress_spec) { }
            else {
                stat.write((bit<32>)hdr.no_absorb.port_num, 0);
                test2.apply();
            }
        } else {
            set_default_bounce_port.apply();
            if(hdr.queue_length.isValid()) {
                get_bounce_port_prepare.apply();
                min_quene.read(check_quene, 1);
                min_port.read(check_port, 1);
                if(meta.local_meta.prev_qlen<=(bit<19>)check_quene||meta.local_meta.ig_port==(bit<9>)check_port){
                    min_quene.write(1, (bit<32>)meta.local_meta.prev_qlen);
                    min_port.write(1, (bit<16>)meta.local_meta.ig_port);
                } else { }
                if(meta.local_meta.prev_qlen > 20000) {
                    bounce_to_min.apply();
                } else { }
            } else { }

            if(standard_metadata.egress_spec==137) {
                stat.read(check_bounce, (bit<32>)standard_metadata.egress_spec);
                meta.local_meta.need_bounce = check_bounce;
                meta.local_meta.timestamp = standard_metadata.ingress_global_timestamp;
                hash(meta.local_meta.hash_temp, HashAlgorithm.crc16, (bit<16>)0, {
                    hdr.ipv4.protocol,
                    hdr.ipv4.srcAddr,
                    hdr.ipv4.dstAddr,
                    hdr.tcp.srcPort,
                    hdr.tcp.dstPort},
                                                           (bit<16>)65536);
                flowlet_prepare2.apply();

                if(hdr.bounce_sequence.isValid()) {
                    read_seq_from_header.apply();
                } else {
                    flowlet_state.read(check_flowlet, (bit<32>)meta.local_meta.hash_temp);
                    if(meta.local_meta.flowlet_ts - check_flowlet > 500000){
                        flowlet_state.write((bit<32>)meta.local_meta.hash_temp, meta.local_meta.flowlet_ts);
                        meta.local_meta.new_flowlet = 1;
                    } else {
                        meta.local_meta.new_flowlet = 0;
                    }
                }

                if(meta.local_meta.need_bounce == 1) {
                    flowlet_ver.write((bit<32>)meta.local_meta.hash_temp, 0);
                    if(hdr.bounce_sequence.isValid()){
                        check_seq_flowlet.read(check_flowlet2, (bit<32>)meta.local_meta.hash_temp);
                        seq_receive.read(check_seq, (bit<32>)meta.local_meta.hash_temp);
                        if(meta.local_meta.sequence_1==check_seq&&meta.local_meta.flowlet_ts-check_flowlet2>500000){
                            check_seq_flowlet.write((bit<32>)meta.local_meta.hash_temp, meta.local_meta.flowlet_ts);
                            seq_receive.write((bit<32>)meta.local_meta.hash_temp, check_seq+1);
                            remove_sequence.apply();
                        } else {
                            bounce.apply();
                        }
                    } else {
                        sequence_sent.read(seq_count, (bit<32>)meta.local_meta.hash_temp);
                        meta.local_meta.sequence_2 = seq_count +1 ;
                        sequence_sent.write((bit<32>)meta.local_meta.hash_temp, meta.local_meta.sequence_2);
                        add_seq2.apply();
                        bounce.apply();
                    }
                } else {
                    if(hdr.bounce_sequence.isValid()) {
                        seq_receive.read(check_seq2, (bit<32>)meta.local_meta.hash_temp);
                        if(meta.local_meta.sequence_1 == check_seq2){
                            meta.local_meta.new_seq = check_seq2+1;
                            seq_receive.write((bit<32>)meta.local_meta.hash_temp, check_seq2+1);
                        } else {
                            bounce.apply();
                        }
                    } else {
                        if(meta.local_meta.new_flowlet == 1){
                            meta.local_meta.after_flowlet = 1;
                            flowlet_ver.write((bit<32>)meta.local_meta.hash_temp, 1);
                        } else {
                            flowlet_ver.read(check_flowlet_ver, (bit<32>)meta.local_meta.hash_temp);
                            meta.local_meta.after_flowlet = check_flowlet_ver;
                            if(meta.local_meta.after_flowlet == 1) { }
                            else {
                                sequence_sent.read(seq_count, (bit<32>)meta.local_meta.hash_temp);
                                meta.local_meta.sequence_2 = seq_count +1 ;
                                sequence_sent.write((bit<32>)meta.local_meta.hash_temp, meta.local_meta.sequence_2);
                                add_seq2.apply();
                                bounce.apply();
                            }
                        }
                    }
                }
            } else {
                if(hdr.queue_length.isValid()){
                    remove_queue_length.apply();
                }
            }
        }


    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
