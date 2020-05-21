// ethernet header
header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}
//ipv4 header
header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

//tcp header
header_type tcp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 6;
        flags : 6;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}

//udp header
header_type udp_t {
    fields {
        srcPort : 16;
        dstPort : 16;
        length_ : 16;
        checksum : 16;
    }
}

header ethernet_t ethernet;
header ipv4_t ipv4;
header tcp_t tcp;
header udp_t udp;

//metadata
header_type intrinsic_metadata_t {
    fields {
        ingress_global_timestamp : 32;
        mcast_grp : 16;
        egress_rid : 16;
    }
}

header_type metadata_t {
    fields {
        ticket : 48; // set to 1 after the correct port sequence was knocked
        ticket_hash : 48; // offset to the position of ticket in  the register array
        ticket_granting_time_index : 48; // offset to the position of time of ticket granting
        ticket_granting_time : 48; // time when the ticket was grant
        state_value : 48; // save the current state value
        state_hash : 48; // offset to the position of state in  the register array
        nhop_ipv4 : 32; //routing
        //ethernet information
        eth_sa : 48;    //eth src addr
        eth_da : 48;    //eth des addr
        //ip information
        ipv4_sa : 32;   //ipv4 src addr
        ipv4_da : 32;   //ipv4 des addr
        //tcp information
        tcp_sp : 16;    //tcp src port
        tcp_dp : 16;    //tcp des port
        tcp_length : 16;    //tcp packet length
        //udp information
        udp_sp : 16; //udp src port
        udp_dp : 16; //udp dst port
    }
}

metadata intrinsic_metadata_t intrinsic_metadata;
metadata metadata_t meta;

register state_value_reg {
    width : 48;
    instance_count : 100;
}

register ticket_reg {
    width : 48;
    instance_count : 100;
}

register ticket_time_reg {
    width : 48;
    instance_count : 100;
}

#define ticket_valid_time 50000000 // timeout for ticket mikrosec


parser start {
    return parse_ethernet;
}

#define ETHERTYPE_IPV4 0x0800
#define PROTOCOL_TCP 0x06
#define PROTOCOL_UDP 0x11

parser parse_ethernet {
    extract(ethernet);
    set_metadata(meta.eth_da,ethernet.dstAddr);
    set_metadata(meta.eth_sa,ethernet.srcAddr);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default : ingress;
    }
}

parser parse_ipv4 {
    extract(ipv4);
    set_metadata(meta.ipv4_sa, ipv4.srcAddr);
	set_metadata(meta.ipv4_da, ipv4.dstAddr);
    set_metadata(meta.tcp_length, ipv4.totalLen - 20);
    return select(latest.protocol) {
        PROTOCOL_TCP : parse_tcp;
        PROTOCOL_UDP : parse_udp;
        default: ingress;
    }
}

//checksum: ipv4
field_list ipv4_checksum_list {
    ipv4.version;
    ipv4.ihl;
    ipv4.diffserv;
    ipv4.totalLen;
    ipv4.identification;
    ipv4.flags;
    ipv4.fragOffset;
    ipv4.ttl;
    ipv4.protocol;
    ipv4.srcAddr;
    ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum {
    verify ipv4_checksum;
    update ipv4_checksum;
}

parser parse_tcp {
    extract(tcp);
    set_metadata(meta.tcp_sp, tcp.srcPort);
    set_metadata(meta.tcp_dp, tcp.dstPort);
    return ingress;

}

// checksum: tcp
field_list tcp_checksum_list {
        ipv4.srcAddr;
        ipv4.dstAddr;
        8'0;
        ipv4.protocol;
        meta.tcp_length;
        tcp.srcPort;
        tcp.dstPort;
        tcp.seqNo;
        tcp.ackNo;
        tcp.dataOffset;
        tcp.res;
        tcp.flags;
        tcp.window;
        tcp.urgentPtr;
        payload;
}

field_list_calculation tcp_checksum {
    input {
        tcp_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field tcp.checksum {
    verify tcp_checksum if(valid(tcp));
    update tcp_checksum if(valid(tcp));
}

parser parse_udp {
    extract(udp);
    set_metadata(meta.udp_sp, udp.srcPort);
    set_metadata(meta.udp_dp, udp.dstPort);
    return ingress;
}

field_list hash_fields {
    ipv4.srcAddr;
    ipv4.dstAddr;
    ipv4.protocol;
}

field_list_calculation update_state_hash {
    input {
        hash_fields;
    }
    algorithm : crc32;
    output_width : 32;
}

field_list ticket_hash_fields {
    ipv4.srcAddr;
    ipv4.dstAddr;
}

field_list_calculation ticket_index_hash {
    input {
        ticket_hash_fields;
    }
    algorithm : crc32;
    output_width : 32;
}

field_list ticket_time_hash_fields {
    ipv4.srcAddr;
    ipv4.dstAddr;
}

field_list_calculation ticket_time_index_hash {
    input {
        ticket_time_hash_fields;
    }
    algorithm : crc32;
    output_width : 32;
}


action _nop() {
    no_op();
}

action _drop() {
    drop();
}

table drop_table {
    actions {
        _drop;
    }
}

action set_nhop(nhop_ipv4, port) {
    modify_field(meta.nhop_ipv4, nhop_ipv4);
    modify_field(standard_metadata.egress_spec, port);
    modify_field(ipv4.ttl, ipv4.ttl - 1);
}

table ipv4_lpm {
    reads {
        ipv4.dstAddr : lpm;
    }
    actions {
        set_nhop;
        _drop;
    }
    size: 1024;
}

action set_dmac(dmac) {
    modify_field(ethernet.dstAddr, dmac);
}

table forward {
    reads {
        meta.nhop_ipv4 : exact;
    }
    actions {
        set_dmac;
        _drop;
    }
    size: 512;
}

action rewrite_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
}

table send_frame {
    reads {
        standard_metadata.egress_port: exact;
    }
    actions {
        rewrite_mac;
        _drop;
    }
    size: 256;
}

action get_hash_val () {
    modify_field_with_hash_based_offset(meta.state_hash, 0, update_state_hash, 100);
    modify_field_with_hash_based_offset(meta.ticket_hash, 0, ticket_index_hash, 100);
    modify_field_with_hash_based_offset(meta.ticket_granting_time_index, 0, ticket_time_index_hash, 100);
}

table hash_val_table {
    actions {
        get_hash_val;
    }
}

action grant_ticket_for_not_suspicious () {
    modify_field(meta.ticket, 1);
}

table grant_ticket_for_not_suspicious_table {
    actions {
        grant_ticket_for_not_suspicious;
    }
}

table ticket_deny_table {
    reads {
        meta.ticket : exact;
        ipv4.srcAddr : lpm;
        ipv4.dstAddr : exact;
    }
    actions {
        _nop;
    }
}

action reset_state () {
    register_write(state_value_reg, meta.state_hash, 0);
    modify_field(meta.state_value, 0);
    modify_field(meta.ticket, 0);
}

table reset_state_table {
    actions {
        reset_state;
    }
}

action reset_ticket () {
    register_write(ticket_reg, meta.ticket_hash, 0);
    register_write(state_value_reg, meta.state_hash, 0);
    modify_field(meta.state_value, 0);
    modify_field(meta.ticket, 0);
}

table reset_ticket_table {
    actions {
        reset_ticket;
    }
}

action update_state (state, ticket) {
    register_write(state_value_reg, meta.state_hash, state);
    register_write(ticket_reg, meta.ticket_hash, ticket);
    register_write(ticket_time_reg, meta.ticket_granting_time_index, intrinsic_metadata.ingress_global_timestamp);
}

table update_state_table {
    reads {
        tcp.dstPort : exact;
        meta.state_value : exact;
    }
    actions {
        update_state;
    }
}

action get_state () {
    register_read(meta.state_value, state_value_reg, meta.state_hash);
    register_read(meta.ticket, ticket_reg, meta.ticket_hash);
    //modify_field(ipv4.ttl, meta.state_value);
}

table get_state_table {
    actions {
        get_state;
    }
}

action get_ticket_reg () {
    register_read(meta.ticket, ticket_reg, meta.ticket_hash);
    register_read(meta.ticket_granting_time, ticket_time_reg,meta.ticket_granting_time_index);
    register_write(ticket_time_reg, meta.ticket_granting_time_index + 1, intrinsic_metadata.ingress_global_timestamp);
    register_write(ticket_time_reg, meta.ticket_granting_time_index + 2, meta.ticket_granting_time);
    register_write(ticket_time_reg, meta.ticket_granting_time_index + 3, meta.ticket_granting_time + 50000000);

}

table get_ticket_reg_table {
    actions {
        get_ticket_reg;
    }
}





control host_need_processing {
    apply(get_state_table);
    apply(update_state_table) {
        miss {
            apply(reset_state_table);
        }
    }
}

control ingress {
    if(valid(ipv4) and ipv4.ttl > 0) {
        apply(hash_val_table);
        apply(ipv4_lpm);
        apply(forward);
    //if(valid(tcp) or valid(udp)){
            apply(get_ticket_reg_table);
            if ((meta.ticket != 0) and (meta.ticket_granting_time + ticket_valid_time < intrinsic_metadata.ingress_global_timestamp)){
                apply(reset_ticket_table);
            }
            apply(ticket_deny_table) {
                hit {
                    host_need_processing();
                }

                miss {
                    apply(grant_ticket_for_not_suspicious_table);
                }
            }
        //}
    }
}

control egress {
        if(meta.ticket != 1){
            apply(drop_table);
        }
        apply(send_frame);
}
