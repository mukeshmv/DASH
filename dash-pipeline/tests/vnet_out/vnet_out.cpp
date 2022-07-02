#include <iostream>
#include <vector>
#include <string.h>

#include <sai.h>


extern sai_status_t sai_create_direction_lookup_entry(
        _In_ const sai_direction_lookup_entry_t *direction_lookup_entry,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list);

extern sai_status_t sai_create_eni_entry(
        _In_ const sai_eni_entry_t *eni_entry,
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

    sai_eni_entry_t eam;
    eam.switch_id = switch_id;
    eam.address[0] = 0xaa;
    eam.address[1] = 0xcc;
    eam.address[2] = 0xcc;
    eam.address[3] = 0xcc;
    eam.address[4] = 0xcc;
    eam.address[5] = 0xcc;

    attr.id = SAI_ENI_ENTRY_ATTR_ENI_ID;
    attr.value.u16 = 7;
    attrs.push_back(attr);

    attr.id = SAI_ENI_ENTRY_ATTR_VNI;
    attr.value.u16 = 9;
    attrs.push_back(attr);

    attr.id = SAI_ENI_ENTRY_ATTR_TUNNEL_ID;
    attr.value.u16 = 2;
    attrs.push_back(attr);

    attr.id = SAI_ENI_ENTRY_ATTR_ROUTE_TABLE_ID;
    attr.value.u16 = 2;
    attrs.push_back(attr);

    attr.id = SAI_ENI_ENTRY_ATTR_STAGE1_OUTBOUND_ACL_GROUP_ID,
    attr.value.u16 = 2;
    attrs.push_back(attr);

    attr.id = SAI_ENI_ENTRY_ATTR_STAGE1_INBOUND_ACL_GROUP_ID,
    attr.value.u16 = 2;
    attrs.push_back(attr);

    attr.id = SAI_ENI_ENTRY_ATTR_STAGE2_OUTBOUND_ACL_GROUP_ID,
    attr.value.u16 = 2;
    attrs.push_back(attr);

    attr.id = SAI_ENI_ENTRY_ATTR_STAGE2_INBOUND_ACL_GROUP_ID,
    attr.value.u16 = 2;
    attrs.push_back(attr);

    attr.id = SAI_ENI_ENTRY_ATTR_STAGE3_OUTBOUND_ACL_GROUP_ID,
    attr.value.u16 = 2;
    attrs.push_back(attr);

    attr.id = SAI_ENI_ENTRY_ATTR_STAGE3_INBOUND_ACL_GROUP_ID,
    attr.value.u16 = 2;
    attrs.push_back(attr);

    attr.id = SAI_ENI_ENTRY_ATTR_CPS,
    attr.value.u16 = 1000;
    attrs.push_back(attr);

    attr.id = SAI_ENI_ENTRY_ATTR_PPS,
    attr.value.u16 = 10000;
    attrs.push_back(attr);

    attr.id = SAI_ENI_ENTRY_ATTR_FLOWS,
    attr.value.u16 = 100;
    attrs.push_back(attr);

    attr.id = SAI_ENI_ENTRY_ATTR_VNET_ID,
    attr.value.u16 = 2;
    attrs.push_back(attr);

    attr.id = SAI_ENI_ENTRY_ATTR_ADMIN_STATE,
    attr.value.booldata = true;
    attrs.push_back(attr);

    status = sai_create_eni_entry(&eam, attrs.size(), attrs.data());
    if (status != SAI_STATUS_SUCCESS)
    {
        std::cout << "Failed to create ENI entry" << std::endl;
        return 1;
    }

    attrs.clear();

    std::cout << "Done." << std::endl;

    return 0;
}
