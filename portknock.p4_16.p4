#include <core.p4>
#include <v1model.p4>

#define ticket_valid_time 5000000 // timeout in microseconds for ticket


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/


struct intrinsic_metadata_t {
    bit<32> ingress_global_timestamp;
    bit<16> mcast_grp;
    bit<16> egress_rid;
}

struct metadata_t {
    bit<48> ticket;
    bit<48> ticket_hash;
    bit<48> ticket_granting_time_index;
    bit<48> ticket_granting_time;
    bit<48> state_value;
    bit<48> state_hash;
    bit<32> nhop_ipv4;
    bit<48> eth_sa;
    bit<48> eth_da;
    bit<32> ipv4_sa;
    bit<32> ipv4_da;
    bit<16> tcp_sp;
    bit<16> tcp_dp;
    bit<16> tcp_length;
    bit<16> udp_sp;
    bit<16> udp_dp;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<6>  res;
    bit<6>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

struct metadata {

    metadata_t meta;
}

struct headers {

    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/


parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        meta.meta.eth_da = hdr.ethernet.dstAddr;
        meta.meta.eth_sa = hdr.ethernet.srcAddr;
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.meta.ipv4_sa = hdr.ipv4.srcAddr;
        meta.meta.ipv4_da = hdr.ipv4.dstAddr;
        meta.meta.tcp_length = hdr.ipv4.totalLen - 16w20;
        transition select(hdr.ipv4.protocol) {
            8w0x6: parse_tcp;
            8w0x11: parse_udp;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        meta.meta.tcp_sp = hdr.tcp.srcPort;
        meta.meta.tcp_dp = hdr.tcp.dstPort;
        transition accept;
    }
    state parse_udp {
        packet.extract(hdr.udp);
        meta.meta.udp_sp = hdr.udp.srcPort;
        meta.meta.udp_dp = hdr.udp.dstPort;
        transition accept;
    }
    state start {
        transition parse_ethernet;
    }
}
/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/


control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
        verify_checksum_with_payload(hdr.tcp.isValid(), { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 8w0, hdr.ipv4.protocol, meta.meta.tcp_length, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.tcp.seqNo, hdr.tcp.ackNo, hdr.tcp.dataOffset, hdr.tcp.res, hdr.tcp.flags, hdr.tcp.window, hdr.tcp.urgentPtr }, hdr.tcp.checksum, HashAlgorithm.csum16);
    }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

register<bit<48>>(32w100) state_value_reg;
register<bit<48>>(32w100) ticket_reg;
register<bit<48>>(32w100) ticket_time_reg;

control host_need_processing(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action get_state() {
        state_value_reg.read(meta.meta.state_value, (bit<32>)meta.meta.state_hash);
        ticket_reg.read(meta.meta.ticket, (bit<32>)meta.meta.ticket_hash);
    }
    action reset_state() {
        state_value_reg.write((bit<32>)meta.meta.state_hash, (bit<48>)0);
        meta.meta.state_value = 48w0;
        meta.meta.ticket = 48w0;
    }
    action update_state(bit<8> state, bit<8> ticket) {
        state_value_reg.write((bit<32>)meta.meta.state_hash, (bit<48>)state);
        ticket_reg.write((bit<32>)meta.meta.ticket_hash, (bit<48>)ticket);
        ticket_time_reg.write((bit<32>)meta.meta.ticket_granting_time_index, (bit<48>)standard_metadata.ingress_global_timestamp);
    }
    table get_state_table {
        actions = {
            get_state;
        }
    }
    table reset_state_table {
        actions = {
            reset_state;
        }
    }
    table update_state_table {
        actions = {
            update_state;
        }
        key = {
            hdr.tcp.dstPort      : exact;
            meta.meta.state_value: exact;
        }
    }
    apply {
        get_state_table.apply();
        if (update_state_table.apply().hit) {
            ;
        } else {
            reset_state_table.apply();
        }
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action set_dmac(bit<48> dmac) {
        hdr.ethernet.dstAddr = dmac;
    }
    action _drop() {
        mark_to_drop(standard_metadata);
    }
    action get_ticket_reg() {
        ticket_reg.read(meta.meta.ticket, (bit<32>)meta.meta.ticket_hash);
        ticket_time_reg.read(meta.meta.ticket_granting_time, (bit<32>)meta.meta.ticket_granting_time_index);
        ticket_time_reg.write((bit<32>)(meta.meta.ticket_granting_time_index + 48w1), (bit<48>)standard_metadata.ingress_global_timestamp);
        ticket_time_reg.write((bit<32>)(meta.meta.ticket_granting_time_index + 48w2), (bit<48>)meta.meta.ticket_granting_time);
        ticket_time_reg.write((bit<32>)(meta.meta.ticket_granting_time_index + 48w3), (bit<48>)(meta.meta.ticket_granting_time + (bit<48>)ticket_valid_time));
    }
    action grant_ticket_for_not_suspicious() {
        meta.meta.ticket = 48w1;
    }
    action get_hash_val() {
        hash(meta.meta.state_hash, HashAlgorithm.crc32, (bit<32>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.ipv4.protocol }, (bit<64>)100);
        hash(meta.meta.ticket_hash, HashAlgorithm.crc32, (bit<32>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, (bit<64>)100);
        hash(meta.meta.ticket_granting_time_index, HashAlgorithm.crc32, (bit<32>)0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, (bit<64>)100);
    }
    action set_nhop(bit<32> nhop_ipv4, bit<9> port) {
        meta.meta.nhop_ipv4 = nhop_ipv4;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 8w1;
    }
    action reset_ticket() {
        ticket_reg.write((bit<32>)meta.meta.ticket_hash, (bit<48>)0);
        state_value_reg.write((bit<32>)meta.meta.state_hash, (bit<48>)0);
        meta.meta.state_value = 48w0;
        meta.meta.ticket = 48w0;
    }
    action _nop() {
        ;
    }
    table forward {
        actions = {
            set_dmac;
            _drop;
        }
        key = {
            meta.meta.nhop_ipv4: exact;
        }
        size = 512;
    }
    table get_ticket_reg_table {
        actions = {
            get_ticket_reg;
        }
    }
    table grant_ticket_for_not_suspicious_table {
        actions = {
            grant_ticket_for_not_suspicious;
        }
    }
    table hash_val_table {
        actions = {
            get_hash_val;
        }
    }
    table ipv4_lpm {
        actions = {
            set_nhop;
            _drop;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 1024;
    }
    table reset_ticket_table {
        actions = {
            reset_ticket;
        }
    }
    table ticket_deny_table {
        actions = {
            _nop;
        }
        key = {
            meta.meta.ticket: exact;
            hdr.ipv4.srcAddr: lpm;
            hdr.ipv4.dstAddr: exact;
        }
    }
    host_need_processing() host_need_processing_0;
    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0) {
            hash_val_table.apply();
            ipv4_lpm.apply();
            forward.apply();
            get_ticket_reg_table.apply();
            if (meta.meta.ticket != 48w0 && meta.meta.ticket_granting_time + (bit<48>)ticket_valid_time < (bit<48>)standard_metadata.ingress_global_timestamp) {
                reset_ticket_table.apply();
            }
            if (ticket_deny_table.apply().hit) {
                host_need_processing_0.apply(hdr, meta, standard_metadata);
            } else {
                grant_ticket_for_not_suspicious_table.apply();
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action _drop() {
        mark_to_drop(standard_metadata);
    }
    action rewrite_mac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }
    table drop_table {
        actions = {
            _drop;
        }
    }
    table send_frame {
        actions = {
            rewrite_mac;
            _drop;
        }
        key = {
            standard_metadata.egress_port: exact;
        }
        size = 256;
    }
    apply {
        if (meta.meta.ticket != 48w1) {
            drop_table.apply();
        }
        send_frame.apply();
    }
}



/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
        update_checksum_with_payload(hdr.tcp.isValid(), { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 8w0, hdr.ipv4.protocol, meta.meta.tcp_length, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.tcp.seqNo, hdr.tcp.ackNo, hdr.tcp.dataOffset, hdr.tcp.res, hdr.tcp.flags, hdr.tcp.window, hdr.tcp.urgentPtr }, hdr.tcp.checksum, HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
    }
}


/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
