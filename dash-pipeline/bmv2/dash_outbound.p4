#ifndef _SIRIUS_OUTBOUND_P4_
#define _SIRIUS_OUTBOUND_P4_

#include "dash_headers.p4"
#include "dash_acl.p4"
#include "dash_conntrack.p4"

control outbound(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata)
{
    action set_vni(bit<24> vni) {
        meta.encap_data.vni = vni;
    }

    @name("eni_to_vni|dash_vnet")
    table eni_to_vni {
        key = {
            meta.eni_id : exact @name("meta.eni_id:eni_id");
        }

        actions = {
            set_vni;
        }
    }

    action set_route_attrs(route_action_type_t route_action_type,
                           bit<24> dest_vnet_vni,
                           bit<1> use_overlay_nh_ip,
                           bit<1> is_overlay_nh_ip_v6,
                           IPv4ORv6Address overlay_nh_ip) {
        meta.route_action_type = route_action_type;
        if (route_action_type == route_action_type_t.VNET) {
            meta.encap_data.dest_vnet_vni = dest_vnet_vni;
            if (use_overlay_nh_ip == 1) {
                meta.lkup_dst_ip_addr = overlay_nh_ip;
                meta.is_lkup_dst_ip_v6 = is_overlay_nh_ip_v6;
            }
        }
        /* ROUTE_ACTION_TYPE_DIRECT -  send to underlay router directly */
    }

    direct_counter(CounterType.packets_and_bytes) routing_counter;

    @name("routing|dash_vnet")
    table routing {
        key = {
            meta.eni_id : exact @name("meta.eni_id:eni_id");
            meta.is_dst_ip_v6 : exact @name("meta.is_dst_ip_v6:v4_or_v6");
            meta.dst_ip_addr : lpm @name("meta.dst_ip_addr:destination");
        }

        actions = {
            set_route_attrs; /* for expressroute - ecmp of overlay */
        }

        counters = routing_counter;
    }

    action set_tunnel_mapping(IPv4Address underlay_dip,
                              EthernetAddress overlay_dmac,
                              bit<1> use_dst_vni) {
        /*
           if (use_dst_vni)
               vni = meta.encap_data.vni;
          else
              vni = meta.encap_data.dest_vnet_vni;
        */
        meta.encap_data.vni = meta.encap_data.vni * (bit<24>)(~use_dst_vni) + meta.encap_data.dest_vnet_vni * (bit<24>)use_dst_vni;
        meta.encap_data.overlay_dmac = overlay_dmac;
        meta.encap_data.underlay_dip = underlay_dip;
    }

    direct_counter(CounterType.packets_and_bytes) ca_to_pa_counter;

    @name("ca_to_pa|dash_vnet")
    table ca_to_pa {
        key = {
            /* Flow for express route */
            meta.encap_data.dest_vnet_vni : exact @name("meta.encap_data.dest_vnet_vni:dest_vni");
            meta.is_lkup_dst_ip_v6 : exact @name("meta.is_lkup_dst_ip_v6:v4_or_v6");
            meta.lkup_dst_ip_addr : exact @name("meta.lkup_dst_ip_addr:dip");
        }

        actions = {
            set_tunnel_mapping;
        }

        counters = ca_to_pa_counter;
    }

    apply {
        eni_to_vni.apply();

#ifdef STATEFUL_P4
           ConntrackOut.apply(0);
#endif /* STATEFUL_P4 */

#ifdef PNA_CONNTRACK
        ConntrackOut.apply(hdr, meta);
#endif // PNA_CONNTRACK

        /* ACL */
        if (!meta.conntrack_data.allow_out) {
            acl.apply(hdr, meta, standard_metadata);
        }

#ifdef STATEFUL_P4
            ConntrackIn.apply(1);
#endif /* STATEFUL_P4 */

#ifdef PNA_CONNTRACK
        ConntrackIn.apply(hdr, meta);
#endif // PNA_CONNTRACK

        meta.lkup_dst_ip_addr = meta.dst_ip_addr;
        meta.is_lkup_dst_ip_v6 = meta.is_dst_ip_v6;
        meta.route_action_type = route_action_type_t.DROP;

        routing.apply();

        if (meta.route_action_type == route_action_type_t.VNET) {
            ca_to_pa.apply();

            vxlan_encap(hdr,
                        meta.encap_data.underlay_dmac,
                        meta.encap_data.underlay_smac,
                        meta.encap_data.underlay_dip,
                        meta.encap_data.underlay_sip,
                        meta.encap_data.overlay_dmac,
                        meta.encap_data.vni);
        }
        if (meta.route_action_type == route_action_type_t.DROP) {
            meta.dropped = true;
        }
    }
}

#endif /* _SIRIUS_OUTBOUND_P4_ */
