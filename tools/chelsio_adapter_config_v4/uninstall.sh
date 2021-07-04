#!/bin/bash
bin_files="Datawise_t540_cr_init_gen3_500_825_t540_xfi_vpd.bin Datawise_t540_xfi_gen3_500_825_124vf.bin diamanti_t6240_so_init_800_1050_gen3_x8_248vf.bin diamanti_t6240_so_init_800_1050_gen3_x8_variable_2x40gxlaui_vpd.bin t520_bt_init_gen3_250_820_fixed_2133_vpd.bin t520_cr_init_gen3_250_825_fixed_2133_vpd.bin t520_ll_init_gen3_650_1075_variable_2133_vpd.bin t520_ocp_init_gen3_250_825_vpd.bin t520_so_init_gen3_250_825_fixed_vpd.bin t540_bt_init_gen3_500_820_variable_2133_vpd.bin t540_cr_init_gen3_500_825_variable_2133_vpd_2mc.bin t580_cr_init_gen3_500Mhz_variable_2133_vpd.bin t580_cr_qsa_variable_2133_vpd.bin t580_cr_spider_variable_2133_vpd.bin t580_lp_cr_init_gen3_500Mhz_variable_2133_vpd.bin t580_lp_cr_qsa_variable_2133_vpd.bin t580_lp_cr_spider_variable_2133_vpd.bin t580_lp_so_init_gen3_500Mhz_variable_vpd.bin t580_lp_so_qsa_variable_vpd.bin t580_ocp_so_4x10g_vpd.bin t580_ocp_so_init_gen3_500Mhz_2x40g_vpd.bin t580_so_spider_variable_2133_vpd.bin t61100_ocp_so_cr_init_800_950_gen3_x16_variable_15625_1x100g_vpd_mfg.bin t62100_cr_init_800_1050_gen3_x16_variable_2133_15625_2x100g_vpd_mfg.bin t62100_lp_cr_init_800_1050_gen3_x16_variable_2133_15625_2x100g_vpd_mfg.bin t62100_so_cr_init_800_1050_gen3_x16_variable_15625_2x100g_vpd_mfg.bin t62100_spider_cr_variable_2133_15625_2x100g_vpd.bin t62100_spider_lp_cr_variable_2133_15625_2x100g_vpd.bin t62100_spider_so_cr_variable_15625_2x100g_vpd.bin t6225_cr_init_500_950_gen3_x8_variable_2133_15625_2x25g_vpd_mfg.bin t6225_ll_cr_init_800_1050_gen3_x8_variable_2133_15625_2x25g_vpd_mfg.bin t6225_ocp_so_cr_init_500_950_gen3_x8_variable_15625_2x25g_vpd_mfg.bin t6225_so_cr_init_500_950_gen3_x8_variable_15625_2x25g_vpd_mfg.bin t6425_cr_init_250_950_gen3_x4_variable_2133_15625_2x25g_vpd_mfg.bin t6225_ocp_so_cr_init_500_950_gen3_x8_248vf_mfg.bin t6225_so_cr_init_500_950_gen3_x8_248vf_mfg.bin"

BINDIR="/lib/firmware/cxgb4/config/"
exefiles="chelsio_adapter_config.py t5seeprom t6seeprom"
EXEDIR="/sbin"

#echo "Removed following VPD binaries from ${BINDIR}"
# Copies .bin files to BINDIR
for bins in ${bin_files} ; do
     if [ -f ${BINDIR}/${bins} ] ; then
         /bin/rm -vf ${BINDIR}/${bins} 
     fi
done
#echo ""

#echo "Removed following scripts from ${EXEDIR} "
#Copies exefiles to /sbin
for exes in ${exefiles} ; do
    if [ -f ${EXEDIR}/${exes} ] ; then
        /bin/rm -vf ${EXEDIR}/${exes} 
    fi
done


