#include <core.p4>
#include <v1model.p4>
#include "dash_headers.p4"
#include "dash_metadata.p4"
#include "dash_parser.p4"
#include "dash_vxlan.p4"
#include "dash_outbound.p4"
#include "dash_conntrack.p4"
#include "dash_acl.p4"

control dash_verify_checksum(inout headers_t hdr,
                             inout metadata_t meta)
{
    apply { }
}

control dash_compute_checksum(inout headers_t hdr,
                          inout metadata_t meta)
{
    apply { }
}

control dash_ingress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata)
{
    action drop_action() {
        mark_to_drop(standard_metadata);
    }

    action deny() {
        meta.dropped = true;
    }

    action accept() {
    }

    @name("vip|dash")
    table vip {
        key = {
            hdr.ipv4.dst_addr : exact @name("hdr.ipv4.dst_addr:VIP");
        }

        actions = {
            accept;
            deny;
        }

        const default_action = deny;
    }

    action set_outbound_direction() {
        meta.direction = direction_t.OUTBOUND;
    }

    @name("direction_lookup|dash")
    table direction_lookup {
        key = {
            hdr.vxlan.vni : exact @name("hdr.vxlan.vni:VNI");
        }

        actions = {
            set_outbound_direction;
            deny;
        }
    }

    action set_appliance(EthernetAddress neighbor_mac,
                         EthernetAddress mac,
                         IPv4Address ip) {
        meta.encap_data.underlay_dmac = neighbor_mac;
        meta.encap_data.underlay_smac = mac;
        meta.encap_data.underlay_sip = ip;
    }

    table appliance {
        key = {
            meta.appliance_id : ternary @name("meta.appliance_id:appliance_id");
        }

        actions = {
            set_appliance;
        }
    }

    action set_eni_attrs(bit<32> cps,
                         bit<32> pps,
                         bit<32> flows,
                         bit<1> admin_state,
                         bit<16> eni_id,
                         bit<24> vni,
                         bit<16> stage1_outbound_acl_group_id,
                         bit<16> stage1_inbound_acl_group_id,
                         bit<16> stage2_outbound_acl_group_id,
                         bit<16> stage2_inbound_acl_group_id,
                         bit<16> stage3_outbound_acl_group_id,
                         bit<16> stage3_inbound_acl_group_id,
                         bit<16> route_table_id,
                         bit<16> vnet_id,
                         bit<16> tunnel_id) {
        meta.eni_data.cps   = cps;
        meta.eni_data.pps   = pps;
        meta.eni_data.flows = flows;
        meta.eni_data.admin_state = admin_state;
        meta.eni_id = eni_id;
        meta.encap_data.vni = vni;
        if (meta.direction == direction_t.OUTBOUND) {
            meta.stage1_acl_group_id = stage1_outbound_acl_group_id;
            meta.stage2_acl_group_id = stage2_outbound_acl_group_id;
            meta.stage3_acl_group_id = stage3_outbound_acl_group_id;
        } else {
            meta.stage1_acl_group_id = stage1_inbound_acl_group_id;
            meta.stage2_acl_group_id = stage2_inbound_acl_group_id;
            meta.stage3_acl_group_id = stage3_inbound_acl_group_id;
        }
        meta.route_table_id = route_table_id;
        meta.vnet = vnet_id;
        meta.tunnel_id = tunnel_id;
    }

    @name("eni|dash")
    table eni {
        key = {
            meta.eni_addr : exact @name("meta.eni_addr:address");
        }

        actions = {
            set_eni_attrs;
        }
    }

    direct_counter(CounterType.packets_and_bytes) eni_counter;

    table eni_meter {
        key = {
            meta.eni_id : exact @name("meta.eni_id:eni_id");
            meta.direction : exact @name("meta.direction:direction");
            meta.dropped : exact @name("meta.dropped:dropped");
        }

        actions = { NoAction; }

        counters = eni_counter;
    }

    action permit() {}

    action pa_validate() {}

    @name("pa_validation|dash_vnet")
    table pa_validation {
        key = {
            meta.eni_id: exact @name("meta.eni_id:eni_id");
            meta.pa_src : exact @name("meta.pa_src:sip");
            meta.lookup_vni : exact @name("meta.lookup_vni:VNI");
        }

        actions = {
            permit;
            @defaultonly deny;
        }

        const default_action = deny;
    }

    @name("vnet|dash_vnet")
    table vnet {
        key = {
            meta.lookup_vni : exact @name("meta.lookup_vni:vni");
        }
        actions = {
            permit;
            pa_validate;
            @defaultonly deny;
        }

        const default_action = deny;
    }

    apply {
        vip.apply();
        if (meta.dropped) {
            return;
        }

        meta.direction = direction_t.INBOUND;
        direction_lookup.apply();

        appliance.apply();

        /* Outer header processing */
        meta.lookup_vni = hdr.vxlan.vni;
        meta.pa_src = hdr.ipv4.src_addr;
        vxlan_decap(hdr);

        /* At this point the processing is done on customer headers */

        meta.dst_ip_addr = 0;
        meta.is_dst_ip_v6 = 0;
        if (hdr.ipv6.isValid()) {
            meta.dst_ip_addr = hdr.ipv6.dst_addr;
            meta.is_dst_ip_v6 = 1;
        } else if (hdr.ipv4.isValid()) {
            meta.dst_ip_addr = (bit<128>)hdr.ipv4.dst_addr;
        }

        /* Put VM's MAC in the direction agnostic metadata field */
        meta.eni_addr = meta.direction == direction_t.OUTBOUND  ?
                                          hdr.ethernet.src_addr :
                                          hdr.ethernet.dst_addr;
        eni.apply();
        if (meta.eni_data.admin_state == 0) {
            deny();
            return;
        }

        if (meta.direction == direction_t.OUTBOUND) {
            meta.lookup_vni = meta.encap_data.vni;
        }
        switch (vnet.apply().action_run) {
             pa_validate: {
                 pa_validation.apply();
             }
        }

        if (meta.direction == direction_t.OUTBOUND) {
#ifdef STATEFUL_P4
            ConntrackOut.apply(0);
#endif /* STATEFUL_P4 */

#ifdef PNA_CONNTRACK
            ConntrackOut.apply(hdr, meta);
#endif // PNA_CONNTRACK
        } else {
#ifdef STATEFUL_P4
            ConntrackIn.apply(0);
#endif /* STATEFUL_P4 */
#ifdef PNA_CONNTRACK
            ConntrackIn.apply(hdr, meta);
#endif // PNA_CONNTRACK
        }

        /* ACL */
        if (!meta.conntrack_data.allow_out) {
            acl.apply(hdr, meta, standard_metadata);
        }

        if (meta.direction == direction_t.OUTBOUND) {
#ifdef STATEFUL_P4
            ConntrackIn.apply(1);
#endif /* STATEFUL_P4 */

#ifdef PNA_CONNTRACK
        ConntrackIn.apply(hdr, meta);
#endif // PNA_CONNTRACK
        } else if (meta.direction == direction_t.INBOUND) {
#ifdef STATEFUL_P4
            ConntrackOut.apply(1);
#endif /* STATEFUL_P4 */
#ifdef PNA_CONNTRACK
            ConntrackOut.apply(hdr, meta);
#endif //PNA_CONNTRACK

        }

        if (meta.direction == direction_t.OUTBOUND) {
            outbound.apply(hdr, meta, standard_metadata);
        } else {
            meta.encap_data.overlay_dmac = hdr.ethernet.dst_addr;
        }

        eni_meter.apply();

        /* Send packet to port 1 by default if we reached the end of pipeline */
        if (meta.dropped) {
            drop_action();
        } else {
            standard_metadata.egress_spec = 1;
        }
    }
}

control dash_egress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata)
{
    action set_tunnel_attributes(EthernetAddress underlay_dmac,
                                 IPv4Address underlay_dip,
                                 bit<24> vni) {
        meta.encap_data.underlay_dmac = underlay_dmac;
        meta.encap_data.underlay_dip = underlay_dip;
        meta.encap_data.vni = vni;
    }

    @name("dash_tunnel|dash_vnet")
    table tunnel {
        key = {
            meta.tunnel_id: exact @name("meta.tunnel_id:tunnel_id");
        }

        actions = {
            set_tunnel_attributes;
        }
    }

    apply {
        tunnel.apply();

        vxlan_encap(hdr,
                    meta.encap_data.underlay_dmac,
                    meta.encap_data.underlay_smac,
                    meta.encap_data.underlay_dip,
                    meta.encap_data.underlay_sip,
                    meta.encap_data.overlay_dmac,
                    meta.encap_data.vni);
    }
}

V1Switch(dash_parser(),
         dash_verify_checksum(),
         dash_ingress(),
         dash_egress(),
         dash_compute_checksum(),
         dash_deparser()) main;
