#!/usr/bin/python2

import subprocess
import re
import sys
from optparse import OptionParser
from platform import system
from os import path

system = system()

if system == "FreeBSD":
	BIN_DIR   = "/usr/local/bin"
	#VI_PATH -> vpd init files path
	VI_PATH   = "/usr/src/sys/dev/cxgbe/firmware/adapter_configuration"
	VPD_PATH  = VI_PATH
elif system == "SunOS":
	BIN_DIR   = "/sbin"
	VI_PATH   = "/lib"
	VPD_PATH  = VI_PATH 
else:
	BIN_DIR   = "/sbin"
	VI_PATH   = "/lib/firmware/cxgb4/config"
	VPD_PATH  = VI_PATH

NAME      = 'name'
FILE      = 'file'
SPEED     = 'speed'
VPD_INIT  = 'vpd_init'
VPD       = 'vpd'
INIT      = 'init'
T5SEEPROM = "%s/t5seeprom" % BIN_DIR 
T6SEEPROM = "%s/t6seeprom" % BIN_DIR 
DEFAULT   = "dflt"
SPIDER    = "spd"
QSA       = "qsa"
VF248     = "vf248"
VF124     = "vf124"

SPEED_2X100G = "2x100G"
SPEED_1X100G = "1x100G"
SPEED_2X25G  = "2x25G"
SPEED_4X25G  = "4x25G"
SPEED_2X40G  = "2x40G"
SPEED_4X10G  = "4x10G"
SPEED_2X10G  = "2x10G"
SPEED_2X1G   = "2x1G"
SPEED_22G    = "2x10G, 2x1G"

OPT_DEFAULT_SETTINGS = 1
OPT_VPD_SETTINGS     = 2
OPT_INIT_SETTINGS    = 3
MODE_DEFAULT         = 1
MODE_SPD             = 2
MODE_QSA             = 3
SET_DEFAULT          = 1
SET_VF248            = 2
SET_VF124            = 3

g_bus_id    = ""
g_card_ver  = -1

g_spd_speeds = ""
g_dflt_speeds = ""
g_seeprom = ""

vpd_modes = {MODE_DEFAULT: DEFAULT, MODE_SPD:SPIDER, MODE_QSA:QSA}
init_modes = {SET_DEFAULT: DEFAULT, SET_VF248: VF248, SET_VF124:VF124}

#T6 ADAPTERS VPD INIT BINARIES
T62100_SO_CR_VI_BIN            = "t62100_so_cr_init_800_1050_gen3_x16_variable_15625_2x100g_vpd_mfg.bin"
T62100_CR_VI_BIN               = "t62100_cr_init_800_1050_gen3_x16_variable_2133_15625_2x100g_vpd_mfg.bin"
T62100_LP_CR_VI_BIN            = "t62100_lp_cr_init_800_1050_gen3_x16_variable_2133_15625_2x100g_vpd_mfg.bin"

#T6 ADAPTERS VPD BINARIES
T62100_SO_CR_DFLT_VPD_BIN           = "t62100_so_cr_variable_15625_2x100g_vpd_mfg.bin"
T62100_SO_CR_SPD_VPD_BIN            = "t62100_spider_so_cr_variable_15625_2x100g_vpd.bin"

T62100_CR_DFLT_VPD_BIN              = "t62100_cr_variable_2133_15625_2x100g_vpd_mfg.bin"
T62100_CR_SPD_VPD_BIN               = "t62100_spider_cr_variable_2133_15625_2x100g_vpd.bin"

T62100_LP_CR_DFLT_VPD_BIN           = "t62100_lp_cr_variable_2133_15625_2x100g_vpd_mfg.bin"
T62100_LP_CR_SPD_VPD_BIN            = "t62100_spider_lp_cr_variable_2133_15625_2x100g_vpd.bin"

#T6 ADAPTERS INIT BINARIES
T62100_SO_CR_DFLT_INIT_BIN          = "t62100_so_cr_init_800_1050_gen3_x16_mfg.bin"
T62100_SO_CR_248VF_INIT_BIN         = "t2100_so_cr_248vf_init.bin"

T62100_CR_DFLT_INIT_BIN             = "t62100_cr_init_800_1050_gen3_x16_mfg.bin"
T62100_CR_248VF_INIT_BIN            = "t62100_cr_init_800_1050_gen3_x16_248vf_mfg.bin"

T62100_LP_CR_DFLT_INIT_BIN          = "t62100_lp_cr_init_800_1050_gen3_x16_mfg.bin"
T62100_LP_CR_248VF_INIT_BIN         = "t2100_lp_cr_248vf_init.bin"

T6225_CR_DFLT_INIT_BIN              = "t6225_cr_init_500_950_gen3_x8_mfg.bin"
T6225_CR_248VF_INIT_BIN             = "t6225_cr_init_500_950_gen3_x8_248vf_mfg.bin"

T6240_SO_DFLT_INIT_BIN              = "diamanti_t6240_so_init_800_1050_gen3_x8.bin"
T6240_SO_248VF_INIT_BIN             = "diamanti_t6240_so_init_800_1050_gen3_x8_248vf.bin"

T6225_OCP_SO_DFLT_INIT_BIN          = "t6225_ocp_so_cr_init_500_950_gen3_x8_mfg.bin"
T6225_OCP_SO_248VF_INIT_BIN         = "t6225_ocp_so_cr_init_500_950_gen3_x8_248vf_mfg.bin"

T6225_SO_CR_DFLT_INIT_BIN           = "t6225_so_cr_init_500_950_gen3_x8_mfg.bin"
T6225_SO_CR_248VF_INIT_BIN          = "t6225_so_cr_init_500_950_gen3_x8_248vf_mfg.bin"

#OTHER T6 ADAPTERS VPD INIT BINARIES
T6225_LL_CR_VI_BIN          = "t6225_ll_cr_init_800_1050_gen3_x8_variable_2133_15625_2x25g_vpd_mfg.bin"
T6225_SO_CR_VI_BIN          = "t6225_so_cr_init_500_950_gen3_x8_variable_15625_2x25g_vpd_mfg.bin"
T6225_CR_VI_BIN             = "t6225_cr_init_500_950_gen3_x8_variable_2133_15625_2x25g_vpd_mfg.bin"
T6225_HM_CR_VI_BIN          = "t6225_hm_cr_init_500_950_gen3_x8_variable_2133_15625_2x25g_vpd_mfg.bin"
T6225_OCP_SO_VI_BIN         = "t6225_ocp_so_cr_init_500_950_gen3_x8_variable_15625_2x25g_vpd_mfg.bin"
T6425_CR_VI_BIN             = "t6425_cr_init_250_950_gen3_x4_variable_2133_15625_2x25g_vpd_mfg.bin"
T61100_OCP_SO_VI_BIN        = "t61100_ocp_so_cr_init_800_950_gen3_x16_variable_15625_1x100g_vpd_mfg.bin"
T62100_HM_CR_VI_BIN         = "t62100_hm_cr_init_650_950_gen3_x8_variable_2133_15625_2x100g_vpd_mfg.bin"
T6240_SO_VI_BIN             = "diamanti_t6240_so_init_800_1050_gen3_x8_variable_2x40gxlaui_vpd.bin"

#T5 ADAPTERS INIT BINARIES
T540_XFI_DFLT_INIT_BIN     = "Datawise_t540_cr_init_gen3_500_825.bin"
T540_XFI_124VF_INIT_BIN    = "Datawise_t540_xfi_gen3_500_825_124vf.bin"

#T580-LP-CR VPD INIT BINARIES   VI -> VPD INIT
T580_LP_CR_DFLT_VI_BIN     = "t580_lp_cr_init_gen3_500Mhz_variable_2133_vpd.bin"
T580_LP_CR_SPD_VI_BIN      = "t580_lp_cr_init_gen3_500Mhz_spider_variable_2133_vpd.bin"
T580_LP_CR_QSA_VI_BIN      = "t580_lp_cr_init_gen3_500Mhz_qsa_variable_2133_vpd.bin"

#T580-LP-CR VPD BINARIES
T580_LP_CR_DFLT_VPD_BIN    = "t580_lp_cr_variable_2133_vpd.bin"
T580_LP_CR_SPD_VPD_BIN     = "t580_lp_cr_spider_variable_2133_vpd.bin"
T580_LP_CR_QSA_VPD_BIN     = "t580_lp_cr_qsa_variable_2133_vpd.bin"

#T580-CR VPD INIT BINARIES
T580_CR_DFLT_VI_BIN        = "t580_cr_init_gen3_500Mhz_variable_2133_vpd.bin"
T580_CR_SPD_VI_BIN         = "t580_cr_init_gen3_500Mhz_spider_variable_2133_vpd.bin"
T580_CR_QSA_VI_BIN         = "t580_cr_init_gen3_500Mhz_qsa_variable_2133_vpd.bin"

#T580-CR VPD BINARIES
T580_CR_DFLT_VPD_BIN       = "t580_cr_variable_2133_vpd.bin"
T580_CR_SPD_VPD_BIN        = "t580_cr_spider_variable_2133_vpd.bin"
T580_CR_QSA_VPD_BIN        = "t580_cr_qsa_variable_2133_vpd.bin"

#T580-SO-CR VPD INIT BINARIES
T580_SO_CR_DFLT_VI_BIN  = "t580_lp_so_init_gen3_500Mhz_variable_vpd.bin"
T580_SO_CR_SPD_VI_BIN   = "t580_lp_so_init_gen3_500Mhz_spider_variable_2133_vpd.bin"
T580_SO_CR_QSA_VI_BIN   = "t580_lp_so_init_gen3_500Mhz_qsa_variable_vpd.bin"

#T580-SO-CR VPD BINARIES
T580_SO_CR_DFLT_VPD_BIN = "t580_lp_so_variable_vpd.bin"
T580_SO_CR_SPD_VPD_BIN  = "t580_so_spider_variable_2133_vpd.bin"
T580_SO_CR_QSA_VPD_BIN  = "t580_lp_so_qsa_variable_vpd.bin"

#T580-OCP-SO VPD INIT BINARIES
T580_OCP_SO_DFLT_VI_BIN  = "t580_ocp_so_init_gen3_500Mhz_2x40g_vpd.bin"
T580_OCP_SO_SPD_VI_BIN   = "t580_ocp_so_init_gen3_500Mhz_4x10g_vpd.bin"

#T580-OCP-SO VPD BINARIES
T580_OCP_SO_DFLT_VPD_BIN = "t580_ocp_so_2x40g_vpd.bin"
T580_OCP_SO_SPD_VPD_BIN  = "t580_ocp_so_4x10g_vpd.bin"

#OTHER T5 ADAPTERS VPD INIT BINARIES
T520_LL_CR_VI_BIN          = "t520_ll_init_gen3_650_1075_variable_2133_vpd.bin"
T520_CR_VI_BIN             = "t520_cr_init_gen3_250_825_fixed_2133_vpd.bin"
T520_SO_CR_VI_BIN          = "t520_so_init_gen3_250_825_fixed_vpd.bin"
T520_OCP_SO_VI_BIN         = "t520_ocp_init_gen3_250_825_vpd.bin"
T520_BT_VI_BIN             = "t520_bt_init_gen3_250_820_fixed_2133_vpd.bin"
T522_CR_VI_BIN             = "t522_cr_init_gen3_500mhz_fixed_2133_vpd.bin"
T540_CR_VI_BIN             = "t540_cr_init_gen3_500_825_variable_2133_vpd_2mc.bin"
T502_BT_VI_BIN		   = "t502_bt_init_gen3_150mhz_fixed_1600_vpd.bin"
T540_BT_VI_BIN		   = "t540_bt_init_gen3_500_820_variable_2133_vpd.bin"
T540_XFI_VI_BIN            = "Datawise_t540_cr_init_gen3_500_825_t540_xfi_vpd.bin"

#vpd + init files for chelsio cards VI -> vpd init
T520_LL_CR_VIS     = {DEFAULT:'%s/%s' % (VI_PATH, T520_LL_CR_VI_BIN)}
T520_CR_VIS        = {DEFAULT:'%s/%s' % (VI_PATH, T520_CR_VI_BIN)}
T520_SO_CR_VIS     = {DEFAULT:'%s/%s' % (VI_PATH, T520_SO_CR_VI_BIN)}
T520_OCP_SO_VIS    = {DEFAULT:'%s/%s' % (VI_PATH, T520_OCP_SO_VI_BIN)}
T520_BT_VIS        = {DEFAULT:'%s/%s' % (VI_PATH, T520_BT_VI_BIN)}
T522_CR_VIS        = {DEFAULT:'%s/%s' % (VI_PATH, T522_CR_VI_BIN)}
T540_CR_VIS        = {DEFAULT:'%s/%s' % (VI_PATH, T540_CR_VI_BIN)}
T502_BT_VIS        = {DEFAULT:'%s/%s' % (VI_PATH, T502_BT_VI_BIN)}
T540_BT_VIS        = {DEFAULT:'%s/%s' % (VI_PATH, T540_BT_VI_BIN)}
T540_XFI_VIS       = {DEFAULT:'%s/%s' % (VI_PATH, T540_XFI_VI_BIN)}

T580_LP_CR_VI     = {DEFAULT:'%s/%s' % (VI_PATH, T580_LP_CR_DFLT_VI_BIN),
		     #SPIDER :'%s/%s' % (VI_PATH, T580_LP_CR_SPD_VI_BIN),
		     #QSA    :'%s/%s' % (VI_PATH, T580_LP_CR_QSA_VI_BIN) 
		    }

T580_CR_VI        = {DEFAULT:'%s/%s' % (VI_PATH, T580_CR_DFLT_VI_BIN),
		     #SPIDER :'%s/%s' % (VI_PATH, T580_CR_SPD_VI_BIN),
		     #QSA    :'%s/%s' % (VI_PATH, T580_CR_QSA_VI_BIN)
		    }

T580_SO_CR_VI  = {DEFAULT:'%s/%s' % (VI_PATH, T580_SO_CR_DFLT_VI_BIN),
		  #SPIDER :'%s/%s' % (VI_PATH, T580_SO_CR_SPD_VI_BIN),
		  #QSA    :'%s/%s' % (VI_PATH, T580_SO_CR_QSA_VI_BIN)
		 }

T580_OCP_SO_VI  = {DEFAULT:'%s/%s' % (VI_PATH, T580_OCP_SO_DFLT_VI_BIN),
		   #SPIDER :'%s/%s' % (VI_PATH, T580_OCP_SO_SPD_VI_BIN)
		  }

#vpd file for t580 cards
T580_LP_CR_VPD    = {DEFAULT:'%s/%s' % (VPD_PATH, T580_LP_CR_DFLT_VPD_BIN),
		     SPIDER :'%s/%s' % (VPD_PATH, T580_LP_CR_SPD_VPD_BIN),
		     QSA    :'%s/%s' % (VPD_PATH, T580_LP_CR_QSA_VPD_BIN)
		    }

T580_CR_VPD       = {DEFAULT:'%s/%s' % (VPD_PATH, T580_CR_DFLT_VPD_BIN),
		     SPIDER :'%s/%s' % (VPD_PATH, T580_CR_SPD_VPD_BIN),
		     QSA    :'%s/%s' % (VPD_PATH, T580_CR_QSA_VPD_BIN)
		    }

T580_SO_CR_VPD = {DEFAULT:'%s/%s' % (VPD_PATH, T580_SO_CR_DFLT_VPD_BIN),
		  SPIDER :'%s/%s' % (VPD_PATH, T580_SO_CR_SPD_VPD_BIN),
		  QSA    :'%s/%s' % (VPD_PATH, T580_SO_CR_QSA_VPD_BIN)
		 }

T580_OCP_SO_VPD  = {DEFAULT:'%s/%s' % (VPD_PATH, T580_OCP_SO_DFLT_VPD_BIN),
		    SPIDER :'%s/%s' % (VPD_PATH, T580_OCP_SO_SPD_VPD_BIN)
		   }

# T6 Adapter
#vpd + init files
T62100_SO_CR_VIS    = {DEFAULT:'%s/%s' % (VI_PATH, T62100_SO_CR_VI_BIN),
		      }

T62100_CR_VIS       = {DEFAULT:'%s/%s' % (VI_PATH, T62100_CR_VI_BIN),
		      }

T62100_LP_CR_VIS    = {DEFAULT:'%s/%s' % (VI_PATH, T62100_LP_CR_VI_BIN),
		      }

T6225_LL_CR_VIS     = {DEFAULT:'%s/%s' % (VI_PATH, T6225_LL_CR_VI_BIN),
		      }

T6225_SO_CR_VIS     = {DEFAULT:'%s/%s' % (VI_PATH, T6225_SO_CR_VI_BIN),
		      }

T6225_CR_VIS        = {DEFAULT:'%s/%s' % (VI_PATH, T6225_CR_VI_BIN),
		      }

T6225_HM_CR_VIS     = {DEFAULT:'%s/%s' % (VI_PATH, T6225_HM_CR_VI_BIN),
		      }

T6240_SO_VIS        = {DEFAULT:'%s/%s' % (VI_PATH, T6240_SO_VI_BIN),
		      }

T6225_OCP_SO_VIS    = {DEFAULT:'%s/%s' % (VI_PATH, T6225_OCP_SO_VI_BIN),
		      }

T6425_CR_VIS        = {DEFAULT:'%s/%s' % (VI_PATH, T6425_CR_VI_BIN),
		      }

T61100_OCP_SO_VIS   = {DEFAULT:'%s/%s' % (VI_PATH, T61100_OCP_SO_VI_BIN),
		      }

T62100_HM_CR_VIS    = {DEFAULT:'%s/%s' % (VI_PATH, T62100_HM_CR_VI_BIN),
		      }

# T6 VPD settings files
T62100_SO_CR_VPDS   = {DEFAULT:'%s/%s' % (VPD_PATH, T62100_SO_CR_DFLT_VPD_BIN),
		       SPIDER :'%s/%s' % (VPD_PATH, T62100_SO_CR_SPD_VPD_BIN),
		      }

T62100_CR_VPDS      = {DEFAULT:'%s/%s' % (VPD_PATH, T62100_CR_DFLT_VPD_BIN),
		       SPIDER :'%s/%s' % (VPD_PATH, T62100_CR_SPD_VPD_BIN),
		      }

T62100_LP_CR_VPDS   = {DEFAULT:'%s/%s' % (VPD_PATH, T62100_LP_CR_DFLT_VPD_BIN),
		       SPIDER :'%s/%s' % (VPD_PATH, T62100_LP_CR_SPD_VPD_BIN),
		      }

#T6 init settings files
T62100_SO_CR_INITS  = {DEFAULT:'%s/%s' % (VPD_PATH, T62100_SO_CR_DFLT_INIT_BIN),
		       #VF248 :'%s/%s' % (VPD_PATH, T62100_SO_CR_248VF_INIT_BIN),
		      }

T62100_CR_INITS     = {DEFAULT:'%s/%s' % (VPD_PATH, T62100_CR_DFLT_INIT_BIN),
		       #VF248 :'%s/%s' % (VPD_PATH, T62100_CR_248VF_INIT_BIN),
		      }

T62100_LP_CR_INITS  = {DEFAULT:'%s/%s' % (VPD_PATH, T62100_LP_CR_DFLT_INIT_BIN),
		       #VF248 :'%s/%s' % (VPD_PATH, T62100_LP_CR_248VF_INIT_BIN),
		      }

T6225_CR_INITS     = {DEFAULT:'%s/%s' % (VPD_PATH, T6225_CR_DFLT_INIT_BIN),
		       #VF248 :'%s/%s' % (VPD_PATH, T6225_CR_248VF_INIT_BIN),
		      }

T6240_SO_INITS     = {DEFAULT:'%s/%s' % (VPD_PATH, T6240_SO_DFLT_INIT_BIN),
		       VF248 :'%s/%s' % (VPD_PATH, T6240_SO_248VF_INIT_BIN),
		      }

T6225_OCP_SO_INITS = {DEFAULT:'%s/%s' % (VPD_PATH, T6225_OCP_SO_DFLT_INIT_BIN),
		       VF248 :'%s/%s' % (VPD_PATH, T6225_OCP_SO_248VF_INIT_BIN),
		      }

T6225_SO_CR_INITS = {DEFAULT:'%s/%s' % (VPD_PATH, T6225_SO_CR_DFLT_INIT_BIN),
		       VF248 :'%s/%s' % (VPD_PATH, T6225_SO_CR_248VF_INIT_BIN),
		      }

#T5 init settings files
T540_XFI_INITS     = {DEFAULT:'%s/%s' % (VPD_PATH, T540_XFI_DFLT_INIT_BIN),
		       VF124 :'%s/%s' % (VPD_PATH, T540_XFI_124VF_INIT_BIN),
		      }

T580_LP_CR_FILES    = {VPD_INIT:T580_LP_CR_VI,     VPD:T580_LP_CR_VPD}
T580_CR_FILES       = {VPD_INIT:T580_CR_VI,        VPD:T580_CR_VPD}
T580_SO_CR_FILES    = {VPD_INIT:T580_SO_CR_VI,     VPD:T580_SO_CR_VPD}
T580_OCP_SO_FILES   = {VPD_INIT:T580_OCP_SO_VI,    VPD:T580_OCP_SO_VPD}
T62100_SO_CR_FILES  = {VPD_INIT:T62100_SO_CR_VIS,  VPD:T62100_SO_CR_VPDS} #,  INIT:T62100_SO_CR_INITS}
T62100_LP_CR_FILES  = {VPD_INIT:T62100_LP_CR_VIS,  VPD:T62100_LP_CR_VPDS} #,  INIT:T62100_LP_CR_INITS}
T62100_CR_FILES     = {VPD_INIT:T62100_CR_VIS,     VPD:T62100_CR_VPDS} #,     INIT:T62100_CR_INITS}
T6225_LL_CR_FILES   = {VPD_INIT:T6225_LL_CR_VIS}
T6225_SO_CR_FILES   = {VPD_INIT:T6225_SO_CR_VIS,  INIT:T6225_SO_CR_INITS}
T6225_CR_FILES      = {VPD_INIT:T6225_CR_VIS} #,      INIT:T6225_CR_INITS}
T6225_HM_CR_FILES   = {VPD_INIT:T6225_HM_CR_VIS}
T6240_SO_FILES      = {VPD_INIT:T6240_SO_VIS,     INIT:T6240_SO_INITS}
T6425_CR_FILES      = {VPD_INIT:T6425_CR_VIS}
T6225_OCP_SO_FILES  = {VPD_INIT:T6225_OCP_SO_VIS, INIT:T6225_OCP_SO_INITS}
T61100_OCP_SO_FILES = {VPD_INIT:T61100_OCP_SO_VIS}
T62100_HM_CR_FILES  = {VPD_INIT:T62100_HM_CR_VIS}
T520_LL_CR_FILES    = {VPD_INIT:T520_LL_CR_VIS}
T520_CR_FILES       = {VPD_INIT:T520_CR_VIS}
T520_SO_CR_FILES    = {VPD_INIT:T520_SO_CR_VIS}
T520_OCP_SO_FILES   = {VPD_INIT:T520_OCP_SO_VIS}
T520_BT_FILES       = {VPD_INIT:T520_BT_VIS}
T522_CR_FILES       = {VPD_INIT:T522_CR_VIS}
T540_CR_FILES       = {VPD_INIT:T540_CR_VIS}
T502_BT_FILES       = {VPD_INIT:T502_BT_VIS}
T540_BT_FILES       = {VPD_INIT:T540_BT_VIS}
T540_XFI_FILES      = {VPD_INIT:T540_XFI_VIS,     INIT:T540_XFI_INITS}

tn = {0x5410:{NAME:'T580_LP_CR',    FILE:T580_LP_CR_FILES,  SPEED:SPEED_2X40G},
      0x540d:{NAME:'T580_CR',       FILE:T580_CR_FILES,     SPEED:SPEED_2X40G},
      0x5414:{NAME:'T580_SO_CR',    FILE:T580_SO_CR_FILES,  SPEED:SPEED_2X40G},
      0x5416:{NAME:'T580_OCP_SO',   FILE:T580_OCP_SO_FILES, SPEED:SPEED_2X40G},
      0x5411:{NAME:'T520_LL_CR',    FILE:T520_LL_CR_FILES,  SPEED:SPEED_2X10G},
      0x5401:{NAME:'T520_CR',       FILE:T520_CR_FILES,     SPEED:SPEED_2X10G},
      0x5407:{NAME:'T520_SO_CR',    FILE:T520_SO_CR_FILES,  SPEED:SPEED_2X10G},
      0x5417:{NAME:'T520_OCP_SO',   FILE:T520_OCP_SO_FILES, SPEED:SPEED_2X10G},
      0x5409:{NAME:'T520_BT   ',    FILE:T520_BT_FILES,     SPEED:SPEED_2X10G},
      0x5402:{NAME:'T522_CR',       FILE:T522_CR_FILES,     SPEED:SPEED_22G},
      0x5403:{NAME:'T540_CR',       FILE:T540_CR_FILES,     SPEED:SPEED_4X10G},
      0x5415:{NAME:'T502_BT',       FILE:T502_BT_FILES,     SPEED:SPEED_2X1G},
      0x5418:{NAME:'T540_BT',       FILE:T540_BT_FILES,     SPEED:SPEED_4X10G},
      0x5492:{NAME:'T540_XFI',      FILE:T540_XFI_FILES,    SPEED:SPEED_4X10G},

      0x6407:{NAME:'T62100_LP_CR',   FILE:T62100_LP_CR_FILES,  SPEED:SPEED_2X100G},
      0x6408:{NAME:'T62100_SO_CR',   FILE:T62100_SO_CR_FILES,  SPEED:SPEED_2X100G},
      0x640D:{NAME:'T62100_CR',      FILE:T62100_CR_FILES,     SPEED:SPEED_2X100G},
      0x6411:{NAME:'T6225_LL_CR',    FILE:T6225_LL_CR_FILES,   SPEED:SPEED_2X25G},
      0x6402:{NAME:'T6225_SO_CR',    FILE:T6225_SO_CR_FILES,   SPEED:SPEED_2X25G},
      0x6401:{NAME:'T6225_CR',       FILE:T6225_CR_FILES,      SPEED:SPEED_2X25G},
      0x6482:{NAME:'T6225_HM_CR',    FILE:T6225_HM_CR_FILES,   SPEED:SPEED_2X25G},
      0x6403:{NAME:'T6425_CR',       FILE:T6425_CR_FILES,      SPEED:SPEED_4X25G},
      0x6405:{NAME:'T6225_OCP_SO',   FILE:T6225_OCP_SO_FILES,  SPEED:SPEED_2X25G},
      0x6414:{NAME:'T61100_OCP_SO',  FILE:T61100_OCP_SO_FILES, SPEED:SPEED_1X100G},
      0x6483:{NAME:'T62100_HM_CR',   FILE:T62100_HM_CR_FILES,  SPEED:SPEED_2X100G},
      0x6485:{NAME:'T6240_SO',       FILE:T6240_SO_FILES,      SPEED:SPEED_2X40G},
     }

def run_cmd(cmd, shell=False, stdout=False):
	"""
	Run the given command on the machine and return the
	return code, output, err.
	"""
	cmd = cmd.split()

	stddata = ""
	stderr = ""
	try:
		if not stdout:
			p = subprocess.Popen(cmd, shell=shell, stdout=subprocess.PIPE,
					     stderr=subprocess.PIPE)
			stddata, stderr = p.communicate()
			# Get rid of leading and trailing white spaces
    			stddata = stddata.strip()
		else:
			p = subprocess.Popen(cmd, shell=shell, stderr=subprocess.PIPE)
			stderr = p.communicate()

		stderr = filter(None, stderr)
	except Exception as e:
		return (-1, "", str(e))

	return (p.returncode, stddata, stderr)

def detect_chelsio_card():
	"""
	detect chelsio card
	returns list of device id of chelsio cards
	and list of bus id of chelsio cards 
	"""

	dev_list =[]
	bus_list =[]
	if system == "FreeBSD":
		cmd = "pciconf -l"
		(ret, out, err) = run_cmd(cmd)
		if ret or err:
			print "Error: pciconf command not found. Please install libpci package and retry the command: %s" % err
			sys.exit(-1)

		out = out.split("\n")
		output = []
		for line in out:
			if re.search("pci.+:.+:.+:4.+0x00001425", line):
				output.append(line)

		for line in output:
			line = line.split()
			m = re.search(".+pci.:(.+:.+:4).*", line[0])
			if not m:
				return (None, None)	
			bus_list.append(m.group(1)[0:-2]+'.0')
			m = re.search("chip=(0x.+)1425",line[3])
			if not m:
				return (None, None)
			dev_list.append(int(m.group(1), 16))
	elif system == "SunOS":
		BIN_DIR = "/sbin"
		cmd = "scanpci -v"
		(ret, out, err) = run_cmd(cmd)
		out = out.split("\n\n")

		for dev in out:
			m = re.search("pci bus 0x(.+)\s+cardnum 0x(.+)\s+function 0x04:.*vendor 0x1425\s+device\s+0x(.+)", dev)
			if m:
				bus = "%x:%x.%x" % (int(m.group(1), 16), int(m.group(2), 16), 4)
				bus_list.append(bus)
				dev_list.append(int(m.group(3), 16))

		if len(bus_list) == 0:
			print "Error: can not find chelsio card"
			sys.exit(-1)
	else:
		BIN_DIR = "/sbin"
		cmd = "lspci -n -d 1425:* -s *:*.4"
		(ret, out, err) = run_cmd(cmd)
		out = out.split("\n")
			
		for dev in out:
			dev = dev.split()
			dev_list.append(int("0x%s" % dev[2].split(":")[1], 16))
			#converting format 07:00.0 to 7.0.0
				
			busId = dev[0].split(".")
			func = busId[-1]    #busId = [0000:01:00, 0]
			busId = busId[0].split(":")
			#Either busId = [0000, 01, 0] = [domain, bus number, slot]
			#or busId = [01, 0] = [bus number, slot]
			slot = busId[-1]
			busNo = busId[-2]
			busId = "%x:%x.%x" % (int(busNo, 16), int(slot, 16), 0)
			bus_list.append(busId)

	return (dev_list, bus_list)
    
def input_vpd_mode(default_enable, spider_enable, qsa_enable):
	"""
	"""
	global g_dflt_speeds
	global g_spd_speeds
	input_ind = {MODE_DEFAULT:-1, MODE_SPD:-1, MODE_QSA:-1}
	
	#if not spider_enable and not qsa_enable:
	#	vpd_mode = MODE_DEFAULT
	#	return vpd_mode
	i = 0
	print "|------------------------------------|"
	print "| Possible Chelsio adapter modes:    |"
	if default_enable:
		i += 1
		print "| %d: Default mode (%-6s)           |" % (i, g_dflt_speeds) 
		input_ind[MODE_DEFAULT] = i
	if spider_enable:
		i += 1
		print "| %d: Spider(%-6s)                  |" % (i, g_spd_speeds) 
		input_ind[MODE_SPD] = i
	if qsa_enable:
		i += 1
		print "| %d: QSA                             |" % i
		input_ind[MODE_QSA] = i
	print "|------------------------------------|"
	#if not spider_enable:
	#	print "\033[31mFor this card spider mode is not "\
	#	      "supported\n\033[0m"
	#if not qsa_enable:
	#	print "\033[31mFor this card qsa mode is not "\
	#	      "supported\n\033[0m"
	if i == 0:
		print "\n\t No mode available\n"
		sys.exit(-1)

	try:
		if i > 1:
			vpd_mode = input("Select mode: ")
		else:
			vpd_mode = 1
		vpd_mode = input_ind.keys()[input_ind.values().index(vpd_mode)]
	except:
		print "\n\tWrong Input\n"
		sys.exit(-1)

	return vpd_mode

def input_init_mode(default_enable, vf248_enable, vf124_enable):
	"""
	"""
	input_ind = {SET_DEFAULT:-1, SET_VF248:-1, SET_VF124:-1}

	#if not vf248_enable and not vf124_enable:
	#	vpd_mode = MODE_DEFAULT
	#	return vpd_mode

	i = 0
	print "|------------------------------------|"
	print "| Possible Chelsio adapter settings: |"
	if default_enable:
		i += 1
		print "| %d: Default settings                |" % i
		input_ind[SET_DEFAULT] = i
	if vf248_enable:
		i += 1
		print "| %d: 248 VFs mode                    |" % i
		input_ind[SET_VF248] = i
	if vf124_enable:
		i += 1
		print "| %d: 124 VFs mode                    |" % i
		input_ind[SET_VF124] = i
	print "|------------------------------------|"
	#if not vf248_enable:
	#	print "\033[31mFor this card 248 VF mode is not "\
	#	      "supported\n\033[0m"
	#if not vf124_enable:
	#	print "\033[31mFor this card 124 VF mode is not "\
	#	      "supported\n\033[0m"
	if i == 0:
		print "\n\tNo Settings available\n"
		sys.exit(-1)

	try:
		if i > 1:
			init_mode = input("Select mode: ")
		else:
			init_mode = 1
		init_mode = input_ind.keys()[input_ind.values().index(init_mode)]
	except:
		print "\n\tWrong Input\n"
		sys.exit(-1)

	return init_mode


def get_file_arg(dev_id, option, vpd_mode, init_mode):
	"""
	"""
	global g_dflt_speeds
	global g_spd_speeds

	if option == OPT_DEFAULT_SETTINGS:
		tn_file = tn[dev_id][FILE][VPD_INIT][DEFAULT]
		file_arg = "-f:%s" % tn_file
	elif option == OPT_VPD_SETTINGS:
		spider_enable = tn[dev_id][FILE][VPD].has_key(SPIDER)
		qsa_enable = tn[dev_id][FILE][VPD].has_key(QSA)
		if not vpd_mode:
			default_enable = 0
			vpd_mode = input_vpd_mode(default_enable, spider_enable,
						  qsa_enable)

		if vpd_mode == MODE_DEFAULT:
			print "Default mode (%-6s) selected" % g_dflt_speeds
		elif spider_enable and vpd_mode == MODE_SPD:
			print "Spider mode (%-6s) selected" % g_spd_speeds 
		elif qsa_enable and vpd_mode == MODE_QSA:
			print "QSA mode selected"
		else:
			if vpd_mode == MODE_SPD or vpd_mode == MODE_QSA:
				print "\n\t Selected mode not supported\n"
			else:
				print "\n\tWrong mode\n"
			sys.exit(-1)

		vpd_mode_str = vpd_modes[vpd_mode] #index to key convert
		tn_file = tn[dev_id][FILE][VPD][vpd_mode_str]
		file_arg = "-fvpd:%s" % tn_file

	elif option == OPT_INIT_SETTINGS:
		vf248_enable = tn[dev_id][FILE][INIT].has_key(VF248)
		vf124_enable = tn[dev_id][FILE][INIT].has_key(VF124)
		if not init_mode: 
			default_enable = 0
			init_mode = input_init_mode(default_enable, vf248_enable,
						    vf124_enable)

		if init_mode == SET_DEFAULT:
			print "Default Setting selected"
		elif vf248_enable and init_mode == SET_VF248:
			print "248 VF setting selected"
		elif vf124_enable and init_mode == SET_VF124:
			print "124 VF setting selected"
		else:
			if init_mode == SET_VF248 or init_mode == SET_VF124:
				print "\n\t Selected setting not supported\n"
			else:
				print "\n\t Wrong mode\n"
			sys.exit(-1)

		init_mode_str = init_modes[init_mode] #index to key convert
		tn_file = tn[dev_id][FILE][INIT][init_mode_str]
		file_arg = "-finit:%s" % tn_file

	if not path.isfile(tn_file) :
		print "\n\tFile not available: \"%s\"\n" % tn_file 
		sys.exit(-1)

	return file_arg


def main():
	"""
	"""

	global g_bus_id
	global g_card_ver
	global g_dflt_speeds
	global g_spd_speeds

	is_t580 = 0
	is_t62100 = 0
	parser = OptionParser(version="%prog 2.0.0.0")
	parser.add_option("-b", "--bus", dest="bus", help="bus id")

	helpmsg = "%-52s\n%-52s\n%-52s\n%-52s" % ("change configuration",
		  "'D' or '1' for changing to Default settings",
		  "'M' or '2' for changing T580 mode",
		  "'S' or '3' for Changing Adapter Config settings")
	parser.add_option("-c", "--change_config", dest="config",
			  help = helpmsg)

	helpmsg = "%-52s\n%-52s\n%-52s\n%-52s" % ("Options for changing T580/T62100 mode",
		  "'D' or '1' for Default mode (2x40G)",
		  "'S' or '2' for Spider mode (4x10G)",
		  "'Q' or '3' for QSA mode")
	parser.add_option("-m", "--vpd_mode", dest="vpd_mode", 
			  help=helpmsg)

	helpmsg = "%-52s\n%-52s\n%-52s\n%-52s" % ("Options for changing Adapter settings",
		  "'D' or '1' for Default settings",
		  "'T' or '2' for 248 VF",
		  "'O' or '3' for 124 VF")
	parser.add_option("-i", "--init_mode", dest="init_mode", 
			  help=helpmsg)


	(ch_card_list, ch_bus_list) = detect_chelsio_card()
	if not ch_card_list:
		print "\n\tChelsio card not detected\n"
		sys.exit(-1)

	

	(options, args) = parser.parse_args()

	#making sure format 7.0.0 
	g_bus_id = options.bus
	card_no = -1
	if g_bus_id:
		try:
			g_bus_id = g_bus_id[:-1]+'0'
			g_bus_id = g_bus_id.split(":")
			g_bus_id[1] = g_bus_id[1].split(".")
			g_bus_id = "%x:%x.%01x" %\
				 (int(g_bus_id[0], 16), int(g_bus_id[1][0],16), int(g_bus_id[1][1], 16))
			card_no = ch_bus_list.index(g_bus_id)
		except Exception as e:
			print "\n\tError: bus '%s' not available\n" % options.bus
			sys.exit(-1)

	option = options.config
	if option:
		option = option.lower()
		if option == 'd' or option == '1':
			option = OPT_DEFAULT_SETTINGS
		elif option == 'm' or option == '2':
			option = OPT_VPD_SETTINGS
		elif option == 's' or option == '3':
			option = OPT_INIT_SETTINGS
		else:
			option = 0

	vpd_mode = options.vpd_mode
	if vpd_mode:
		vpd_mode = vpd_mode.lower()
		if vpd_mode =='d' or vpd_mode == '1':
			vpd_mode = MODE_DEFAULT
		elif vpd_mode == 's' or vpd_mode == '2':
			vpd_mode = MODE_SPD
		elif vpd_mode == 'q' or vpd_mode == '3':
			vpd_mode = MODE_QSA
		else:
			vpd_mode = 0


	init_mode = options.init_mode
	if init_mode:
		init_mode = init_mode.lower()
		if init_mode =='d' or init_mode == '1':
			init_mode = SET_DEFAULT
		elif init_mode == 's' or init_mode == '2':
			init_mode = SET_VF248
		elif init_mode == 'q' or init_mode == '3':
			init_mode = SET_VF124
		else:
			init_mode = 0

	card_no_to_ind = []
	if ch_card_list:
		print "\nChelsio adapter detected\n"
		if not g_bus_id:
			ind = -1;
			no_of_cards = 0
			print "|------------------------------------|"
			print "| Choose Chelsio card:               |"
			for dev in ch_card_list:
				ind += 1
				if dev not in tn:
					continue
				dev_name = "%-16s%s" % (tn[dev][NAME], ch_bus_list[ind])
				card_no_to_ind.append(ind);
				no_of_cards += 1
				print "| %d. %-32s|" % (no_of_cards, dev_name)
			print "|------------------------------------|"

			if no_of_cards == 0 and len(ch_card_list):
				print "\n\tDetected Cards are not supported\n" 
				sys.exit(-1)

			try:
				card_no = input("Select card: ")
			except:
				card_no = -1

			card_no -= 1

			if card_no < 0 or card_no >= no_of_cards:
				print "\n\tWrong Input\n"
				sys.exit(-1)

		if len(card_no_to_ind) != 0:
			card_no = card_no_to_ind[card_no];
		dev_id = ch_card_list[card_no]
		g_bus_id = ch_bus_list[card_no]
		dev_name = tn[dev_id][NAME]
		g_card_ver = int(dev_name[1:2])
		print "\nCard %s(%s) selected" % (dev_name, g_bus_id)

	g_dflt_speeds = tn[dev_id][SPEED]
	if g_card_ver == 5:
		if not path.isfile(T5SEEPROM) :
			print "\n\t\"%s\" not available\n" % T5SEEPROM
			sys.exit(-1)
		g_seeprom = T5SEEPROM;
		g_spd_speeds = SPEED_4X10G
	elif g_card_ver == 6:
		if not path.isfile(T6SEEPROM) :
			print "\n\t\"%s\" not available\n" % T6SEEPROM
			sys.exit(-1)
		g_spd_speeds = SPEED_2X25G
		g_seeprom = T6SEEPROM;
	else:
		print "\n\tCard version not found"
		sys.exit(-1)

	if re.search("T580", tn[dev_id][NAME]):
		is_t580 = 1
	if re.search("T62100", tn[dev_id][NAME]):
		is_t62100  = 1

	if is_t580:
		opt = "T580 mode"
	elif is_t62100:
		opt = "T62100 mode"
	else:
		opt = "VPD"

	if not option:
		input_ind = {OPT_DEFAULT_SETTINGS: -1, OPT_VPD_SETTINGS:-1, OPT_INIT_SETTINGS:-1}
		i = 0
		print ""
		print "|------------------------------------|"
		print "| Choose option                      |"

		if tn[dev_id][FILE].has_key(VPD_INIT): 
			i += 1
			print "| %d. Change to Default settings      |" % i
			input_ind[OPT_DEFAULT_SETTINGS] = i
		
		if tn[dev_id][FILE].has_key(VPD): 
			i += 1
			print "| %d. Change %-25s|" % (i, opt)
			input_ind[OPT_VPD_SETTINGS] = i
		if tn[dev_id][FILE].has_key(INIT): 
			i += 1
			print "| %d. Change Adapter Config settings  |" % i
			input_ind[OPT_INIT_SETTINGS] = i
		print "|------------------------------------|"
		try:
			option = input("Select option: ")
			option = input_ind.keys()[input_ind.values().index(option)]
		except:
			option = -1

	if option == OPT_DEFAULT_SETTINGS:
		print "\nFlashing Default settings"
	elif option == OPT_VPD_SETTINGS:
		print "\nChanging %s" % opt
	elif option == OPT_INIT_SETTINGS:
		print "\nChanging Adapter Config settings"
	else:
		print "\n\tWrong input\n"
		sys.exit(-1)

	file_arg = get_file_arg(dev_id, option, vpd_mode, init_mode) 
	
	try:
		prompt = raw_input("\nDo you want to update the chosen "\
				   "configuration for %s (y/n): " %\
				   dev_name)
	except:
		prompt = 'n'

	if prompt != 'y' and prompt !='Y':
		print "\n\tExiting\n"
		sys.exit(-1)

	cmd = "%s -b %s write %s" % (g_seeprom, g_bus_id, file_arg)
	print "\nRunning command:"
	print "%s\n" % cmd
	#Here stdout=True means output will be printed on console,
	#"out" var will be empty in below command
	(ret, out, err) = run_cmd(cmd, stdout=True)
	if ret < 0 or err:
		print "Error in running command: %s\n" % str(err)
		sys.exit(-1)

	print "\nverifying ..."
	cmd = "%s -b %s verify %s" % (g_seeprom, g_bus_id, file_arg)
	print "%s\n" % cmd
	(ret, out, err) = run_cmd(cmd)
	if ret or err or re.search("FAILED", out):
		print "\n\tError: Verification failed: %s\n" % err
		sys.exit(-1)

	print out

	#printing in green color
	print"\033[32m\n\tFlashing is completed\n\033[0m"


if __name__ == "__main__":
	main()
