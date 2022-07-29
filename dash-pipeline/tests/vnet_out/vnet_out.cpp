#include <iostream>
#include <vector>
#include <string.h>

#include <sai.h>


extern sai_status_t sai_create_direction_lookup_entry(
        _In_ const sai_direction_lookup_entry_t *direction_lookup_entry,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

extern sai_status_t sai_create_eni_ether_address_map_entry(
        _In_ const sai_eni_ether_address_map_entry_t *outbound_eni_lookup_from_vm_entry,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

extern sai_status_t sai_create_outbound_eni_to_vni_entry(
        _In_ const sai_outbound_eni_to_vni_entry_t *outbound_eni_to_vni_entry,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

extern sai_status_t sai_create_eni(
        _Out_ sai_object_id_t *eni_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

extern sai_dash_api_t sai_dash_api_impl;

int main(int argc, char **argv)
{
    sai_object_id_t switch_id = SAI_NULL_OBJECT_ID;
    sai_attribute_t attr;
    std::vector<sai_attribute_t> attrs;

    sai_direction_lookup_entry_t dle = {};
    dle.switch_id = switch_id;
    dle.vni = 60;

    attr.id = SAI_DIRECTION_LOOKUP_ENTRY_ATTR_ACTION;
    attr.value.u32 = SAI_DIRECTION_LOOKUP_ENTRY_ACTION_SET_OUTBOUND_DIRECTION;
    attrs.push_back(attr);

    /* sai_status_t status = sai_dash_api_impl.create_direction_lookup_entry(&dle, attrs.size(), attrs.data()); */
    sai_status_t status = sai_create_direction_lookup_entry(&dle, attrs.size(), attrs.data());
    if (status != SAI_STATUS_SUCCESS)
    {
        std::cout << "Failed to create Direction Lookup Entry" << std::endl;
        return 1;
    }

    attrs.clear();

    attr.id = SAI_ENI_ATTR_CPS;
    attr.value.u32 = 10000;
    attrs.push_back(attr);

    attr.id = SAI_ENI_ATTR_PPS;
    attr.value.u32 = 100000;
    attrs.push_back(attr);

    attr.id = SAI_ENI_ATTR_FLOWS;
    attr.value.u32 = 100000;
    attrs.push_back(attr);

    attr.id = SAI_ENI_ATTR_ADMIN_STATE;
    attr.value.booldata = true;
    attrs.push_back(attr);

    attr.id = SAI_ENI_ATTR_VM_UNDERLAY_DIP;
    sai_ip_addr_t u_dip_addr = {.ip4 = 0x010310ac};
    sai_ip_address_t u_dip = {.addr_family = SAI_IP_ADDR_FAMILY_IPV4,
                              .addr = u_dip_addr};
    attr.value.ipaddr = u_dip;
    attrs.push_back(attr);

    attr.id = SAI_ENI_ATTR_VM_VNI;
    attr.value.u32 = 9;
    attrs.push_back(attr);

    sai_object_id_t eni_id;
    /* status = sai_dash_api_impl.create_eni(&eni_id, switch_id, attrs.size(), attrs.data()); */
    status = sai_create_eni(&eni_id, switch_id, attrs.size(), attrs.data());

    attrs.clear();

    sai_eni_ether_address_map_entry_t eam;
    eam.switch_id = switch_id;
    eam.address[0] = 0xaa;
    eam.address[1] = 0xcc;
    eam.address[2] = 0xcc;
    eam.address[3] = 0xcc;
    eam.address[4] = 0xcc;
    eam.address[5] = 0xcc;

    attr.id = SAI_ENI_ETHER_ADDRESS_MAP_ENTRY_ATTR_ENI_ID;
    attr.value.u16 = eni_id;
    attrs.push_back(attr);

    status = sai_create_eni_ether_address_map_entry(&eam, attrs.size(), attrs.data());
    if (status != SAI_STATUS_SUCCESS)
    {
        std::cout << "Failed to create ENI Lookup From VM" << std::endl;
        return 1;
    }

    attrs.clear();

    sai_outbound_eni_to_vni_entry_t e2v = {};
    e2v.switch_id = switch_id;
    e2v.eni_id = eni_id;

    attr.id = SAI_OUTBOUND_ENI_TO_VNI_ENTRY_ATTR_VNI;
    attr.value.u32 = 9;
    attrs.push_back(attr);

    /* status = sai_dash_api_impl.create_outbound_eni_to_vni_entry(&e2v, attrs.size(), attrs.data()); */
    status = sai_create_outbound_eni_to_vni_entry(&e2v, attrs.size(), attrs.data());
    if (status != SAI_STATUS_SUCCESS)
    {
        std::cout << "Failed to create ENI To VNI" << std::endl;
        return 1;
    }

    attrs.clear();


    std::cout << "Done." << std::endl;

    return 0;
}
