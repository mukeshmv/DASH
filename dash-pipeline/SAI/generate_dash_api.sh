#!/bin/bash
if [[ $1 ]]; then
    DBG_LVL="--debug=$1"
fi
./sai_api_gen.py \
    /bmv2/dash_pipeline.bmv2/dash_pipeline_p4rt.json \
    --ignore-tables=appliance,eni_meter,slb_decap \
    --overwrite=false ${DBG_LVL} \
    dash
