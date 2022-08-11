#ifndef _SIRIUS_INBOUND_P4_
#define _SIRIUS_INBOUND_P4_

#include "dash_headers.p4"
#include "dash_service_tunnel.p4"
#include "dash_vxlan.p4"

control inbound(inout headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_metadata)
{
    apply {
        vxlan_encap(hdr,
                    meta.encap_data.underlay_dmac,
                    meta.encap_data.underlay_smac,
                    meta.encap_data.underlay_dip,
                    meta.encap_data.underlay_sip,
                    hdr.ethernet.dst_addr,
                    meta.encap_data.vni);
    }
}

#endif /* _SIRIUS_INBOUND_P4_ */
