/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>
/* This is a more elaborate version of the basic program discussed in the 
 * class and available in p4src disrectory. It can be compiled in a number
 * of variants (profiles) with the parameters specified on the command
 * line.
 *
 * -DIPV4_HOST_SIZE=131072   -- Set the size of IPv4 host table
 * -DIPV4_LPM_SIZE=400000    -- Set the size of IPv4 LPM table
 * -DPARSER_OPT              -- Optimize the number of parser states
 * -DBYPASS_EGRESS           -- Bypass egress processing completely
 * -DONE_STAGE               -- Allow ipv4_host and ipv4_lpm to share a stage
 * -DUSE_ALPM                -- Use ALPM implementation for ipv4_lpm table
 * -DUSE_ALPM_NEW            -- Use ALPM implementation for ipv4_lpm table,
 *                              coded in a new style (as an extern)
 * -DALPM_NAME               -- Define ALPM extern separately and not inside
 *                              the table (use with -DUSE_ALPM_NEW)
 */

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_GO_ABSORB 0xBF01
#define ETHERTYPE_NO_ABSORB 0xBF02
#define ETHERTYPE_BOUNCE 0xBF03
#define ETHERTYPE_QLEN 0xBF04
#define IP_PROTOCOLS_TCP 6
#define THRESHOLD 20000
// #ifdef __TARGET_TOFINO__
// #include <tofino/intrinsic_metadata.p4>
// #include <tofino/constants.p4>
// #include <tofino/primitives.p4>
// #include <tofino/stateful_alu_blackbox.p4>
// #else
// #error This program is intended to compile for Tofino P4 architecture only
// #endif
/* Table Sizes */
#ifndef IPV4_HOST_SIZE
  #define IPV4_HOST_SIZE 65536
#endif

const int IPV4_HOST_TABLE_SIZE = IPV4_HOST_SIZE;

struct pair {
    bit<32>     first;
    bit<32>     second;
}

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */

header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

header vlan_tag_h {
    bit<3>   pcp;
    bit<1>   cfi;
    bit<12>  vid;
    bit<16>  ether_type;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
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
    bit<7>    padding;
    bit<9>    port_num;
    bit<32>   deq_timedelta;
    bit<48>   ingress_global;
    bit<48>   egress_global;
}

header no_absorb_t {
    bit<7>    padding;
    bit<9>    port_num;
    bit<32>   deq_timedelta;
    bit<48>   ingress_global;
    bit<48>   egress_global;
}

header bounce_sequence_t {
    bit<32>   seq_num;
}

header queue_length_t {
    bit<5>    has_bounce_seq;
    bit<19>   qlen;
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


/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    ethernet_h          ethernet;
    vlan_tag_h          vlan_tag;
    ipv4_h              ipv4;
    tcp_t               tcp;
    go_absorb_t         go_absorb;
    no_absorb_t         no_absorb;
    bounce_sequence_t   bounce_sequence;
    queue_length_t      queue_length;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    local_meta_t    local_meta;
}

    /***********************  P A R S E R  **************************/
parser IngressParser(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }


    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
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
        transition select(hdr.vlan_tag.ether_type) {
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

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    // action send(PortId_t port) {
    //     ig_tm_md.ucast_egress_port = port;
    // }

    // action drop() {
    //     ig_dprsr_md.drop_ctl = 1;
    // }

    // table ipv4_host {
    //     key = { hdr.ipv4.dst_addr : exact; }
    //     actions = {
    //         send; drop;
    //     }
    //     size = IPV4_HOST_TABLE_SIZE;
    // }
    
    action set_egr() {
        ig_tm_md.ucast_egress_port = 20;
    }

    // action set_egr(PortId_t port) {
    //     ig_tm_md.ucast_egress_port = port;
    // }
    action nop() {
    }

    table forward {
        key = {
            ig_intr_md.ingress_port : exact;
            hdr.ethernet.dst_addr : exact;
        }
        actions = {
            set_egr; nop;
        }
    }

    action _test2() {
        ig_tm_md.ucast_egress_port = 137;
    }

    table test2 {
        actions = {
            _test2;
        }
        default_action = _test2;
    }

    Register<bit<8>, bit<9>>(511) stat;
    RegisterAction<bit<8>, bit<9>, bit<8>>(stat)
    set_stat = {
        void apply(inout bit<8> register_data){
            register_data = 1;
        }
    };
    RegisterAction<bit<8>, bit<9>, bit<8>>(stat) 
    clr_stat = {
        void apply(inout bit<8>register_data){
            register_data = 0;
        }
    };

    RegisterAction<bit<8>, bit<9>, bit<8>>(stat) 
    check_stat = {
        void apply(inout bit<8>register_data, out bit<8> result){
            result = register_data;
        }
    };

    action _set_default_bounce_port() {
        meta.local_meta.prev_qlen = hdr.queue_length.qlen;
        meta.local_meta.ig_port = ig_intr_md.ingress_port;
        meta.local_meta.bounce_port = ig_intr_md.ingress_port;
    }

    table set_default_bounce_port {
        actions = { _set_default_bounce_port; }
        default_action = _set_default_bounce_port;
    }

    action _get_bounce_port_prepare() {
        hdr.queue_length.setInvalid();
        hdr.ethernet.ether_type = ETHERTYPE_IPV4;
    }

    table get_bounce_port_prepare {
        actions = { _get_bounce_port_prepare; }
        default_action = _get_bounce_port_prepare;
    }

    Register<pair, bit<1>>(1) min_quene;
    RegisterAction<pair, bit<1>, bit<32>>(min_quene)
    _min_quene = {
        void apply(inout pair register_data, out bit<32> result){
            if(meta.local_meta.prev_qlen<=register_data.first[18:0]||meta.local_meta.ig_port==register_data.second[8:0]) {
                register_data.first = (bit<32>)meta.local_meta.prev_qlen;
                register_data.second = (bit<32>)meta.local_meta.ig_port;
                result = 1;
            } else {
                result = 0;
            }
        }
    };

    Register<bit<16>, bit<1>>(1) min_port;
    RegisterAction<bit<16>, bit<1>, bit<16>>(min_port)
    update_min_port = {
        void apply(inout bit<16> register_data){
            register_data = (bit<16>)meta.local_meta.ig_port;
            
        }
    };

    RegisterAction<bit<16>, bit<1>, bit<16>>(min_port)
    get_min_port = {
        void apply(inout bit<16> register_data, out bit<16> result){
            result = register_data;
        }
    };

    Register<bit<32>, bit<1>>(1) qlen_comp_alu;
    RegisterAction<bit<32>, bit<1>, bit<32>>(qlen_comp_alu)
    qlen_comp = {
        void apply(inout bit<32> register_data, out bit<32> result){
            // if((register_data << 2) > 20000) {
            //     result = 1;
            // }
            if(meta.local_meta.prev_qlen > 20000) {
                result = 1;
            } else {
                result = 0;
            }
        }
    };

    action _bounce_to_min() {
        //modify_field(local_meta.bounce_port, 140);

        //modify_field(local_meta.bounce_port, 136);
        //modify_field(ethernet.srcAddr, local_meta.prev_qlen);
        //modify_field(ethernet.dstAddr, local_meta.min_port);
        //modify_field(ipv4.dstAddr, local_meta.prev_qlen);
        meta.local_meta.bounce_port = meta.local_meta.min_port;
        //drop();
    }

    table bounce_to_min {
        actions = { _bounce_to_min; }
        default_action = _bounce_to_min;
    }

    Hash<bit<16>>(HashAlgorithm_t.CRC32) hash1;

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

    Register<bit<32>, bit<16>>(65535) flowlet_alu;
    RegisterAction<bit<32>, bit<16>, bit<32>>(flowlet_alu)
    flowlet_state = {
        void apply(inout bit<32> register_data, out bit<32> result){
            if(meta.local_meta.flowlet_ts - register_data > 500000) {
                register_data = meta.local_meta.flowlet_ts;
                result = 1;
            } else {
                result = 0;
            }
        }
    };

    Register<bit<8>, bit<16>>(65535) _flowlet_ver;
    RegisterAction<bit<8>, bit<16>, bit<8>>(_flowlet_ver)
    set_flowlet_ver = {
        void apply(inout bit<8> register_data){
            register_data = 0;
        }
    };
    RegisterAction<bit<8>, bit<16>, bit<8>>(_flowlet_ver)
    com_flowlet_ver = {
        void apply(inout bit<8> register_data, out bit<8> result){
            if(meta.local_meta.new_flowlet == 1){
                result = 1;
            } else {
                result = 0;
            }
        }
    };

    // Register<bit<32>, bit<1>>(1) _sequence_received;
    // RegisterAction<bit<32>, bit<1>, bit<32>>(_sequence_received)
    // check_seq_alu = {
    //     void apply(inout bit<32> register_data, out bit<32> result){
    //         register_data = 0;
    //     }
    // };

    Register<bit<32>, bit<16>>(65535) add_seq_alu;
    RegisterAction<bit<32>, bit<16>, bit<32>>(add_seq_alu)
    add_seq = {
        void apply(inout bit<32> register_data, out bit<32> result){
            register_data = register_data + 1;
            result = register_data;
        }
    };

    action _add_seq2() {
        hdr.bounce_sequence.setValid();
        hdr.bounce_sequence.seq_num = meta.local_meta.sequence_2;
        hdr.ethernet.ether_type = ETHERTYPE_BOUNCE;
    }

    table add_seq2 {
        actions = { _add_seq2; }
        default_action = _add_seq2;
    }

    action _bounce() {
        hdr.ethernet.ether_type = ETHERTYPE_BOUNCE;

        //modify_field(ig_intr_md_for_tm.ucast_egress_port, ig_intr_md.ingress_port);
        ig_tm_md.ucast_egress_port = meta.local_meta.bounce_port;
    }

    table bounce {
        actions = {
            _bounce;
        }
        default_action = _bounce;
    }

    action _rm() {
        hdr.queue_length.setInvalid();
        hdr.ethernet.ether_type = ETHERTYPE_IPV4;
    }

    table remove_queue_length {
        actions = { _rm; }
        default_action = _rm;
    }


    apply {
        // meta.local_meta.q_predicate = 1;
        // meta.local_meta.q_predicate = meta.local_meta.q_predicate << 2;
        forward.apply();
        if(hdr.go_absorb.isValid()){
            if (ig_intr_md.ingress_port == ig_tm_md.ucast_egress_port) { }
            else {
                set_stat.execute(hdr.go_absorb.port_num);
                //apply(drop);
                test2.apply();
            }
        } else if (hdr.no_absorb.isValid()){
            if(ig_intr_md.ingress_port == ig_tm_md.ucast_egress_port) { }
            else {
                clr_stat.execute(hdr.go_absorb.port_num);
            }
        } else {
            set_default_bounce_port.apply();
            if (hdr.queue_length.isValid()) {          
                get_bounce_port_prepare.apply();
                meta.local_meta.update_port = _min_quene.execute(0);
                if(meta.local_meta.update_port == 1){
                    update_min_port.execute(0);
                    meta.local_meta.min_port = meta.local_meta.ig_port;
                    // meta.local_meta.min_port = meta.local_meta.ig_port << 2;
                } else {
                    meta.local_meta.min_port = (bit<9>)get_min_port.execute(0);
                }
                meta.local_meta.prev_full = (bit<1>)qlen_comp.execute(0);
                if (meta.local_meta.prev_full == 1) {
                    bounce_to_min.apply();
                }
            } else {}

            if(ig_tm_md.ucast_egress_port == 137) {//137 is decided by topology or for debug
                meta.local_meta.need_bounce = check_stat.execute(ig_tm_md.ucast_egress_port);
                meta.local_meta.timestamp = ig_prsr_md.global_tstamp;
                meta.local_meta.hash_temp = hash1.get({
                    hdr.ipv4.protocol,
                    hdr.ipv4.src_addr,
                    hdr.ipv4.dst_addr,
                    hdr.tcp.srcPort,
                    hdr.tcp.dstPort
                });
                flowlet_prepare2.apply();

                if(hdr.bounce_sequence.isValid()){
                    read_seq_from_header.apply();
                } else {
                    meta.local_meta.new_flowlet = (bit<1>)flowlet_state.execute(meta.local_meta.hash_temp);
                }

                if(meta.local_meta.need_bounce == 1) {
                    set_flowlet_ver.execute(meta.local_meta.hash_temp);

                    if(hdr.bounce_sequence.isValid()){
                        // check_seq_alu.execute(meta.local_meta.hash_temp);
//----------------------------------------------------------------------------------------------------------
                        if(meta.local_meta.need_bounce == 0){

                        } else {
                            bounce.apply();
                        }
                    } else {
                        meta.local_meta.sequence_2 = add_seq.execute(meta.local_meta.hash_temp);
                        add_seq2.apply();
                        bounce.apply();
                    }
                } else {
                    if(hdr.bounce_sequence.isValid()){
                        // check_seq2
//----------------------------------------------------------------------------------------------------------
                        if(meta.local_meta.need_bounce == 0){

                        } else {
                            bounce.apply();
                        }
                    } else {
                        meta.local_meta.after_flowlet = (bit<1>)com_flowlet_ver.execute(meta.local_meta.hash_temp);
                        if(meta.local_meta.after_flowlet == 1) {}
                        else {
                            meta.local_meta.sequence_2 = add_seq.execute(meta.local_meta.hash_temp);
                            add_seq2.apply();
                            bounce.apply();
                        }
                    }
                }
            } else {
                if(hdr.queue_length.isValid()) {
                    remove_queue_length.apply();
                }
            }
        } 
    }
}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
    ethernet_h   ethernet;
    vlan_tag_h   vlan_tag;
    ipv4_h       ipv4;
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
    mirror_meta_t mirror_meta;
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition parse_ethernet;
    }

#ifdef PARSER_OPT
    @critical
#endif
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_VLAN:  parse_vlan_tag;
            ETHERTYPE_IPV4:  parse_ipv4;
            default: accept;
        }
    }

#ifdef PARSER_OPT
    @critical
#endif
    state parse_vlan_tag {
        pkt.extract(hdr.vlan_tag);
        transition select(hdr.vlan_tag.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
            default: accept;
        }
    }
    
#ifdef PARSER_OPT
    @critical
#endif
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
    

}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{



    // action show() {
    //     hdr.recirculate.myquene = eg_intr_md.deq_qdepth;
    //     meta.qlen = eg_intr_md.deq_qdepth;
    // }
    // table quene {
    //     actions  = { 
    //         show; 
    //     }
    //     default_action = show();
    // }
    // table www {
    //     actions = {
    //         NoAction;
    //     }
    //     default_action = NoAction;
    // }
    // compare_plane() do_loop;
    apply {
        // quene.apply(); 
        // meta._pad2 = 3;
        // if(pkt_is_mirrored){
        //     www.apply();
        // }
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
