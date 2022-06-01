#ifndef _SIRIUS_OUTBOUND_P4_
#define _SIRIUS_OUTBOUND_P4_

#include "sirius_headers.p4"

control outbound(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata)
{
    action route_vnet(bit<24> dest_vnet_vni) {
        meta.encap_data.dest_vnet_vni = dest_vnet_vni;
    }

    direct_counter(CounterType.packets_and_bytes) routing_counter;

    table routing {
        key = {
            meta.eni : exact @name("meta.eni:eni");
            meta.is_dst_ip_v6 : exact @name("meta.is_dst_ip_v6:v4_or_v6");
            meta.dst_ip_addr : lpm @name("meta.dst_ip_addr:destination");
        }

        actions = {
            route_vnet; /* for expressroute - ecmp of overlay */
        }

        counters = routing_counter;
    }

    action set_tunnel_mapping(bit<16> tunnel_id,
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
        meta.tunnel_id = tunnel_id;
    }

    direct_counter(CounterType.packets_and_bytes) ca_to_pa_counter;

    table ca_to_pa {
        key = {
            /* Flow for express route */
            meta.encap_data.dest_vnet_vni : exact @name("meta.encap_data.dest_vnet_vni:dest_vni");
            meta.is_dst_ip_v6 : exact @name("meta.is_dst_ip_v6:v4_or_v6");
            meta.dst_ip_addr : exact @name("meta.dst_ip_addr:dip");
        }

        actions = {
            set_tunnel_mapping;
        }

        counters = ca_to_pa_counter;
    }

    apply {
        switch (routing.apply().action_run) {
            route_vnet: {
                ca_to_pa.apply();
             }
         }
    }
}

#endif /* _SIRIUS_OUTBOUND_P4_ */
