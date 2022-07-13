#ifndef _SIRIUS_METADATA_P4_
#define _SIRIUS_METADATA_P4_

#include "dash_headers.p4"

struct encap_data_t {
    bit<24> vni;
    bit<24> dest_vnet_vni;
    IPv4Address underlay_sip;
    IPv4Address underlay_dip;
    EthernetAddress underlay_smac;
    EthernetAddress underlay_dmac;
    EthernetAddress overlay_dmac;
}

enum bit<16> direction_t {
    INVALID = 0,
    OUTBOUND = 1,
    INBOUND = 2
}

struct conntrack_data_t {
    bool allow_in;
    bool allow_out;
}

struct eni_data_t {
    bit<32> cps;
    bit<32> pps;
    bit<32> flows;
    bit<1>  admin_state;
}

enum bit<8> route_action_type_t {
    DROP   = 0,
    VNET   = 1,
    DIRECT = 2
}

struct metadata_t {
    bool dropped;
    direction_t direction;
    encap_data_t encap_data;
    EthernetAddress eni_addr;
    bit<16> eni_id;
    eni_data_t eni_data;
    bit<16> inbound_vm_id;
    bit<8> appliance_id;
    bit<1> is_dst_ip_v6;
    bit<1> is_lkup_dst_ip_v6;
    IPv4ORv6Address dst_ip_addr;
    IPv4ORv6Address lkup_dst_ip_addr;
    conntrack_data_t conntrack_data;
    route_action_type_t route_action_type;
}

#endif /* _SIRIUS_METADATA_P4_ */
