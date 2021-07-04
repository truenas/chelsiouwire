/*
 * Copyright (c) 2020-2021 Chelsio Communications. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2 or the OpenIB.org BSD license
 * below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *      - Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "common.h"
#include "cxgb4_ofld.h"
#include "chtcp_ioctl.h"
#include "chtcp_kmain.h"

void
chtcp_free_ktxq_info(struct chtcp_kadapter *dev,
		     struct chtcp_free_txq_info *fti)
{
	struct chtcp_ktxq_info *txqi, *txq_tmp;

	list_for_each_entry_safe(txqi, txq_tmp, &dev->ktxq_list, ktxq_link) {
		if ((txqi->port_id != fti->port_id) ||
		    (txqi->eq_id != fti->eq_id))
			continue;

		list_del(&txqi->ktxq_link);
		kfree(txqi);
		break;
	}
}

void
chtcp_free_krxq_info(struct chtcp_kadapter *dev,
		     struct chtcp_free_rxq_info *fri)
{
	struct chtcp_krxq_info *rxqi, *rxq_tmp;

	list_for_each_entry_safe(rxqi, rxq_tmp, &dev->krxq_list, krxq_link) {
		if ((rxqi->port_id != fri->port_id) ||
		    (rxqi->iq_id != fri->iq_id) ||
		    (rxqi->fl_id != fri->fl_id))
			continue;

		list_del(&rxqi->krxq_link);
		kfree(rxqi);
		break;
	}
}


int chtcp_kofld_eq_free(struct chtcp_kadapter *dev,
			struct chtcp_free_txq_info *fti)
{
	struct net_device *ndev = dev->lldi.ports[fti->port_id];
	struct fw_eq_ofld_cmd c;
	int ret;

	memset(&c, 0, sizeof(c));
	c.op_to_vfn = cpu_to_be32(V_FW_CMD_OP(FW_EQ_OFLD_CMD) |
				  F_FW_CMD_REQUEST | F_FW_CMD_EXEC |
				  V_FW_EQ_OFLD_CMD_PFN(dev->lldi.pf) |
				  V_FW_EQ_OFLD_CMD_VFN(0));
	c.alloc_to_len16 = cpu_to_be32(F_FW_EQ_OFLD_CMD_FREE | FW_LEN16(c));
	c.eqid_pkd = cpu_to_be32(V_FW_EQ_OFLD_CMD_EQID(fti->eq_id));
	rtnl_lock();
	ret = cxgb4_wr_mbox(ndev, &c, sizeof(c), &c);
	rtnl_unlock();
	if (ret)
		pr_err("%s: cxgb4_wr_mbox failed: %d", __FUNCTION__, ret);

	return ret;
}

int chtcp_kofld_iq_free(struct chtcp_kadapter *dev,
			 struct chtcp_free_rxq_info *fri)
{
	struct net_device *ndev = dev->lldi.ports[fri->port_id];
	struct fw_iq_cmd c;
	int ret;

	memset(&c, 0, sizeof(c));
	c.op_to_vfn = cpu_to_be32(V_FW_CMD_OP(FW_IQ_CMD) | F_FW_CMD_REQUEST |
				  F_FW_CMD_EXEC | V_FW_IQ_CMD_PFN(dev->lldi.pf) |
				  V_FW_IQ_CMD_VFN(0));
	c.alloc_to_len16 = cpu_to_be32(F_FW_IQ_CMD_FREE | FW_LEN16(c));
	c.type_to_iqandstindex =
		cpu_to_be32(V_FW_IQ_CMD_TYPE(FW_IQ_TYPE_FL_INT_CAP));
	c.iqid = cpu_to_be16(fri->iq_id);
	c.fl0id = cpu_to_be16(fri->fl_id);
	c.fl1id = cpu_to_be16(0xffff);
	rtnl_lock();
	ret = cxgb4_wr_mbox(ndev, &c, sizeof(c), &c);
	rtnl_unlock();
	if (ret)
		pr_err("%s: cxgb4_wr_mbox failed: %d", __FUNCTION__, ret);

	return ret;
}

int chtcp_ksge_alloc_ofld_txq(struct chtcp_kadapter *dev,
			       struct chtcp_txq_info *txq_info)
{
	u32 nentries = txq_info->u.in.nentries;
	struct chtcp_free_txq_info fti;
	struct chtcp_ktxq_info *txqi;
	struct fw_eq_ofld_cmd c;
	unsigned int chip_ver;
	struct adapter *adap;
	struct net_device *ndev;
	struct sge *s;
	u32 cntx_id;
	u8 port_id;
	int ret;

	port_id = txq_info->u.in.port_id;
	ndev = dev->lldi.ports[port_id];
	adap = dev->adap;
	s = &adap->sge;
	cntx_id = s->fw_evtq.cntxt_id;

	chip_ver = CHELSIO_CHIP_VERSION(dev->lldi.adapter_type);

	memset(&c, 0, sizeof(c));
	c.op_to_vfn = cpu_to_be32(V_FW_CMD_OP(FW_EQ_OFLD_CMD) | F_FW_CMD_REQUEST |
			    F_FW_CMD_WRITE | F_FW_CMD_EXEC |
			    V_FW_EQ_OFLD_CMD_PFN(dev->lldi.pf) |
			    V_FW_EQ_OFLD_CMD_VFN(0));
	c.alloc_to_len16 = cpu_to_be32(F_FW_EQ_OFLD_CMD_ALLOC |
				 F_FW_EQ_OFLD_CMD_EQSTART | (sizeof(c) / 16));
	c.fetchszm_to_iqid =
		cpu_to_be32(V_FW_EQ_OFLD_CMD_HOSTFCMODE(X_HOSTFCMODE_STATUS_PAGE) |
		      V_FW_EQ_OFLD_CMD_PCIECHN(cxgb4_port_chan(ndev)) |
		      F_FW_EQ_OFLD_CMD_FETCHRO | V_FW_EQ_OFLD_CMD_IQID(cntx_id));
	c.dcaen_to_eqsize =
		cpu_to_be32(V_FW_EQ_OFLD_CMD_FBMIN(chip_ver <= CHELSIO_T5
					     ? X_FETCHBURSTMIN_64B
					     : X_FETCHBURSTMIN_64B_T6) |
		      V_FW_EQ_OFLD_CMD_FBMAX(X_FETCHBURSTMAX_512B) |
		      V_FW_EQ_OFLD_CMD_CIDXFTHRESH(X_CIDXFLUSHTHRESH_32) |
		      V_FW_EQ_OFLD_CMD_EQSIZE(nentries));
	c.eqaddr = cpu_to_be64(txq_info->u.in.phys_addr);

	rtnl_lock();
	ret = cxgb4_wr_mbox(ndev, &c, sizeof(c), &c);
	rtnl_unlock();
	if (ret) {
		pr_err("%s: cxgb4_wr_mbox failed: %d", __FUNCTION__, ret);
		return ret;
	}

	txq_info->u.out.cntxt_id = G_FW_EQ_OFLD_CMD_EQID(be32_to_cpu(c.eqid_pkd));

	ret = cxgb4_bar2_sge_qregs(ndev, txq_info->u.out.cntxt_id,
				   T4_BAR2_QTYPE_EGRESS, 1,
				   &txq_info->u.out.bar2_offset,
				   &txq_info->u.out.bar2_qid);
	if (ret) {
		pr_err("%s: cxgb4_wr_mbox failed: %d", __FUNCTION__, ret);
		goto free_q;
	}

	txqi = kzalloc(sizeof(struct chtcp_ktxq_info), GFP_KERNEL);
        if (!txqi) {
		pr_err("%s: kzalloc failed for chtcp_ktxq_info: %d",
		       __FUNCTION__, ret);
                ret = -ENOMEM;
		goto free_q;
        }
	txqi->eq_id = txq_info->u.out.cntxt_id;
	txqi->port_id = port_id;
	list_add_tail(&txqi->ktxq_link, &dev->ktxq_list);

	return 0;

free_q:
	fti.port_id = port_id;
	fti.eq_id = txq_info->u.out.cntxt_id;
	chtcp_kofld_eq_free(dev, &fti);
	return ret;
}

/* setup congestion manager context */
int chtcp_setup_conm_ctx(struct chtcp_kadapter *dev,
			 struct chtcp_conm_ctx_info *conm_info)
{
	struct net_device *ndev;
	u32 param, val;
	int ret;

	ndev = dev->lldi.ports[conm_info->port_id];

	/* For T5 and later we attempt to set up the Congestion Manager values
	 * of the new RX Ethernet Queue.  This should really be handled by
	 * firmware because it's more complex than any host driver wants to
	 * get involved with and it's different per chip and this is almost
	 * certainly wrong.  Firmware would be wrong as well, but it would be
	 * a lot easier to fix in one place ...  For now we do something very
	 * simple (and hopefully less wrong).
	 */

	param = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DMAQ) |
		 V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DMAQ_CONM_CTXT) |
		 V_FW_PARAMS_PARAM_YZ(conm_info->iq_id));

	val = V_CONMCTXT_CNGTPMODE(X_CONMCTXT_CNGTPMODE_QUEUE);

	ret = cxgb4_set_params(ndev, 1, &param, &val);
	if (ret)
		pr_err("Failed to set Congestion Manager Context for Ingress"
		       "Queue %d: %d\n", conm_info->iq_id, -ret);

	return ret;
}

int chtcp_ksge_alloc_ofld_rxq(struct chtcp_kadapter *dev,
			       struct chtcp_rxq_info *rxq_info)
{
	struct chtcp_free_rxq_info fri;
	struct chtcp_krxq_info *rxqi;
	int ret;
	struct fw_iq_cmd c;
	unsigned int chip_ver;
	struct net_device *ndev;
	int pciechan;
	u32 fl_size;
	u8 port_id;

	fl_size = rxq_info->u.in.fl_size;
	port_id = rxq_info->u.in.port_id;
	ndev = dev->lldi.ports[port_id];

	chip_ver = CHELSIO_CHIP_VERSION(dev->lldi.adapter_type);

	pciechan = cxgb4_port_chan(ndev);

	memset(&c, 0, sizeof(c));
	c.op_to_vfn = cpu_to_be32(V_FW_CMD_OP(FW_IQ_CMD) | F_FW_CMD_REQUEST |
			    F_FW_CMD_WRITE | F_FW_CMD_EXEC |
			    V_FW_IQ_CMD_PFN(dev->lldi.pf) | V_FW_IQ_CMD_VFN(0));
	c.alloc_to_len16 = cpu_to_be32(F_FW_IQ_CMD_ALLOC | F_FW_IQ_CMD_IQSTART |
				 FW_LEN16(c));
	c.type_to_iqandstindex =
			cpu_to_be32(V_FW_IQ_CMD_TYPE(FW_IQ_TYPE_FL_INT_CAP) |
			      V_FW_IQ_CMD_IQASYNCH(0) |
			      V_FW_IQ_CMD_VIID(cxgb4_port_viid(ndev)) |
			      V_FW_IQ_CMD_IQANDST(0) |
			      V_FW_IQ_CMD_IQANUD(X_UPDATEDELIVERY_STATUS_PAGE) |
			      V_FW_IQ_CMD_IQANDSTINDEX(0));
	c.iqdroprss_to_iqesize = cpu_to_be16(V_FW_IQ_CMD_IQPCIECH(pciechan) |
				       F_FW_IQ_CMD_IQGTSMODE |
				       V_FW_IQ_CMD_IQINTCNTTHRESH(0) |
				       V_FW_IQ_CMD_IQESIZE(
					ilog2(rxq_info->u.in.iqe_len) - 4));

	c.iqsize = cpu_to_be16(rxq_info->u.in.q_size);
	c.iqaddr = cpu_to_be64(rxq_info->u.in.q_phys_addr);
	c.iqns_to_fl0congen = cpu_to_be32(F_FW_IQ_CMD_IQFLINTCONGEN |
				    V_FW_IQ_CMD_IQTYPE(FW_IQ_IQTYPE_OFLD));


	/* filling fl info */
	c.iqns_to_fl0congen |=
			cpu_to_be32(V_FW_IQ_CMD_FL0HOSTFCMODE(X_HOSTFCMODE_NONE) |
			      (rxq_info->u.in.pack_en ?
			      F_FW_IQ_CMD_FL0PACKEN : 0) |
			      V_FW_IQ_CMD_FL0FETCHRO(0) |
			      V_FW_IQ_CMD_FL0DATARO(0) |
			      F_FW_IQ_CMD_FL0PADEN);
	c.iqns_to_fl0congen |=
			cpu_to_be32(F_FW_IQ_CMD_FL0CONGCIF | F_FW_IQ_CMD_FL0CONGEN);

	/* In T6, for egress queue type FL there is internal overhead
	 * of 16B for header going into FLM module.  Hence the maximum
	 * allowed burst size is 448 bytes.  For T4/T5, the hardware
	 * doesn't coalesce fetch requests if more than 64 bytes of
	 * Free List pointers are provided, so we use a 128-byte Fetch
	 * Burst Minimum there (T6 implements coalescing so we can use
	 * the smaller 64-byte value there).
	 */
	c.fl0dcaen_to_fl0cidxfthresh =
		cpu_to_be16(V_FW_IQ_CMD_FL0FBMIN(chip_ver <= CHELSIO_T5
					   ? X_FETCHBURSTMIN_128B
					   : X_FETCHBURSTMIN_64B_T6) |
		      V_FW_IQ_CMD_FL0FBMAX(chip_ver <= CHELSIO_T5
					   ? X_FETCHBURSTMAX_512B
					   : X_FETCHBURSTMAX_256B) |
		      V_FW_IQ_CMD_FL0CIDXFTHRESH(X_CIDXFLUSHTHRESH_1));
	c.fl0size = cpu_to_be16(rxq_info->u.in.fl_size);
	c.fl0addr = cpu_to_be64(rxq_info->u.in.fl_addr);

	rtnl_lock();
	ret = cxgb4_wr_mbox(ndev, &c, sizeof(c), &c);
	rtnl_unlock();
	if (ret) {
		pr_err("%s: cxgb4_wr_mbox failed: %d", __FUNCTION__, ret);
		return ret;
	}

	rxq_info->u.out.q_cntxt_id = be16_to_cpu(c.iqid);
	rxq_info->u.out.q_abs_id = be16_to_cpu(c.physiqid);
	ret = cxgb4_bar2_sge_qregs(ndev, rxq_info->u.out.q_cntxt_id,
				   T4_BAR2_QTYPE_INGRESS, 1,
				   &rxq_info->u.out.q_bar2_offset,
				   &rxq_info->u.out.q_bar2_qid);
	if (ret) {
		pr_err("%s: cxgb4_bar2_sge_qregs failed: %d", __FUNCTION__,
		       ret);
		goto free_q;
	}

	rxq_info->u.out.fl_cntxt_id = be16_to_cpu(c.fl0id);

	/* Note, we must initialize the BAR2 Free List User Doorbell
	 * information before refilling the Free List!
	 */
	ret = cxgb4_bar2_sge_qregs(ndev, rxq_info->u.out.fl_cntxt_id,
				   T4_BAR2_QTYPE_EGRESS, 1,
				   &rxq_info->u.out.fl_bar2_offset,
				   &rxq_info->u.out.fl_bar2_qid);
	if (ret) {
		pr_err("%s: cxgb4_bar2_sge_qregs failed: %d", __FUNCTION__,
		       ret);
		goto free_q;
	}

	rxqi = kzalloc(sizeof(struct chtcp_krxq_info), GFP_KERNEL);
        if (!rxqi) {
		pr_err("%s: kzalloc failed for chtcp_krxq_info: %d",
		       __FUNCTION__, ret);
                ret = -ENOMEM;
		goto free_q;
        }
	rxqi->iq_id = rxq_info->u.out.q_cntxt_id;
	if (fl_size)
		rxqi->fl_id = rxq_info->u.out.fl_cntxt_id;
	else
		rxqi->fl_id = 0xffff;
	rxqi->port_id = port_id;
	list_add_tail(&rxqi->krxq_link, &dev->krxq_list);

	return 0;

free_q:
	fri.port_id = port_id;
	fri.iq_id = rxq_info->u.out.q_cntxt_id;
	fri.fl_id = rxq_info->u.out.fl_cntxt_id;
	chtcp_kofld_iq_free(dev, &fri);
	return ret;
}
