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
#include<linux/version.h>
#include<linux/module.h>
#include<linux/moduleparam.h>
#include<linux/kernel.h>
#include<linux/pci.h>
#include<linux/net.h>
#include<linux/inet.h>
#include<linux/errno.h>
#include "common.h"
#include "t4_regs.h"
#include "cxgb4_ofld.h"
#include "chtcp_kmain.h"
#include "chtcp_kcm.h"
#include "chtcp_ioctl.h"
#include "t4_msg.h"
#include "clip_tbl.h"

#define CHTCP_DRV_MODULE_NAME         "chtcp"

static LIST_HEAD(chtcp_list);
static DEFINE_MUTEX(chtcp_list_lock);
static	atomic_t index = ATOMIC_INIT(0);

static dev_t chtcp_dev;
static struct class *chtcp_class;
static void chtcp_free_all_queues(struct chtcp_kadapter *dev);
static void chtcp_del_sock_list(struct chtcp_kadapter *dev);

static char *chtcp_pci_address = NULL;
module_param(chtcp_pci_address, charp, S_IRUGO);
MODULE_PARM_DESC(chtcp_pci_address, " PCI device address of the adapters to be"
		 " enabled (e.g 0000:01:00.4,0000:02:00.4 ). "
		 "All T5/T6 adapters are enabled by default");

int chtcp_open(struct inode *inode, struct file *filp)
{
	struct chtcp_kadapter *dev;
	struct cdev *cdev = filp->f_inode->i_cdev;

	dev = container_of(cdev, struct chtcp_kadapter, chtcp_cdev);

	mutex_lock(&dev->adap_lock);
	if (dev->file_in_use) {
		/* don't allow device file open more than 1 time */
		pr_err("%s: %s device file already opened\n",
			pci_name(dev->lldi.pdev), __func__);

		mutex_unlock(&dev->adap_lock);
		return -EPERM;
	}
	dev->file_in_use = true;
	mutex_unlock(&dev->adap_lock);

	return 0;
}

int chtcp_close(struct inode *inode, struct file *filp)
{
	struct chtcp_kadapter *dev;
	struct cdev *cdev = filp->f_inode->i_cdev;

	dev = container_of(cdev, struct chtcp_kadapter, chtcp_cdev);

	/* check if app terminated abnormally */
	if (!list_empty(&dev->lcsk_list) &&
	    (!list_empty(&dev->ktxq_list) || !list_empty(&dev->krxq_list)))
		chtcp_infinite_wait();

	chtcp_del_sock_list(dev);

	mutex_lock(&dev->adap_lock);
	chtcp_free_all_queues(dev);
	dev->file_in_use = false;
	mutex_unlock(&dev->adap_lock);

	return 0;
}

static void
chtcp_get_tid_info(struct chtcp_kadapter *dev, struct chtcp_tid_info *t)
{
	struct tid_info *tid = dev->lldi.tids;

	memset(t, 0, sizeof(*t));
	t->ntids = tid->ntids;
	t->nstids = tid->nstids;
	t->natids = tid->natids;
	t->tid_base = tid->tid_base;
	t->stid_base = tid->stid_base;
}

static int chtcp_mmap(struct file *flip, struct vm_area_struct *vma)
{
	struct cdev *cdev = flip->f_inode->i_cdev;
	size_t size;
	struct chtcp_kadapter *dev;
	struct pci_dev *pdev;
	int ret = 0;

	if (((phys_addr_t)vma->vm_pgoff) != 0)
		return -EINVAL;

	size = vma->vm_end - vma->vm_start;

	dev = container_of(cdev, struct chtcp_kadapter, chtcp_cdev);
	pdev = dev->lldi.pdev;
	if (size != pci_resource_len(pdev, CHTCP_PCI_BAR_NUM))
		return -EINVAL;

	vma->vm_pgoff += (pci_resource_start(pdev, CHTCP_PCI_BAR_NUM) >> PAGE_SHIFT);
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	ret = io_remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff, size,
				vma->vm_page_prot);

	return ret;
}

static int chtcp_handle_get_device_info(struct chtcp_kadapter *dev,
					void __user *useraddr)
{
	struct chtcp_adapter_info adap_info;
	struct adapter *adap;
	struct sge *s;
	u32 i;

	adap = dev->adap;
	s = &adap->sge;
	adap_info.nports = dev->lldi.nports;
	adap_info.pf = dev->lldi.pf;
	adap_info.fl_starve_thres = s->fl_starve_thres;
	adap_info.stat_len = dev->lldi.sge_egrstatuspagesize;
	adap_info.fl_align = dev->lldi.sge_ingpadboundary;
	adap_info.sge_fl_db = adap->params.arch.sge_fl_db;
	adap_info.bar2_length = pci_resource_len(dev->lldi.pdev,
						 CHTCP_PCI_BAR_NUM);
	if (!PAGE_ALIGNED(adap_info.bar2_length))
		return -EINVAL;
	adap_info.pktshift = dev->lldi.sge_pktshift;
	adap_info.adapter_type = dev->lldi.adapter_type;
	adap_info.wr_cred = dev->lldi.wr_cred;

	adap_info.fl_buf_size = 0;
	for (i = 0; i < 16; i++) {
		u32 reg_addr = A_SGE_FL_BUFFER_SIZE0 + (i * sizeof(u32));
		u32 fl_buf_size = t4_read_reg(adap, reg_addr);

#define CHTCP_FL_BUF_SIZE	9216
		if (fl_buf_size == CHTCP_FL_BUF_SIZE) {
			adap_info.fl_buf_idx = i;
			adap_info.fl_buf_size = fl_buf_size;
			break;
		}
	}

	if (!adap_info.fl_buf_size) {
		pr_err("%s: %s: fl buffer idx not found\n",
		       pci_name(dev->lldi.pdev), __func__);
		return -EINVAL;
	}

	memcpy(adap_info.mtus, dev->lldi.mtus, sizeof(adap_info.mtus));

	strlcpy(adap_info.pci_devname, pci_name(dev->lldi.pdev),
		sizeof(adap_info.pci_devname));

	if (copy_to_user(useraddr, &adap_info,
			sizeof(struct chtcp_adapter_info)))
		return -EFAULT;
	return 0;
}

static long chtcp_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct chtcp_kadapter *dev;
	struct cdev *cdev = filp->f_inode->i_cdev;
	struct chtcp_txq_info txq_info;
	struct chtcp_rxq_info rxq_info;
	struct chtcp_free_txq_info fti;
	struct chtcp_free_rxq_info fri;
	struct chtcp_conm_ctx_info conm_ctx;
	struct chtcp_tid_info t;
	void *useraddr;
	u32 stid;
	int rc = 0;

	if (_IOC_TYPE(cmd) != CHTCP_IOCTL_MAGIC)
		return -ENOTTY;

	if (_IOC_NR(cmd) > CHTCP_IOCTL_MAXNR)
		return -ENOTTY;

	useraddr = (void __user *)arg;
	dev = container_of(cdev, struct chtcp_kadapter, chtcp_cdev);

	mutex_lock(&dev->adap_lock);
	switch (cmd) {
	case CHTCP_IOCTL_GET_DEV_INFO_CMD:
		rc = chtcp_handle_get_device_info(dev, useraddr);
		break;
	case CHTCP_IOCTL_ALLOC_TXQ_CMD:
		rc = copy_from_user(&txq_info, useraddr, sizeof(txq_info));
		if (rc) {
			rc = -EFAULT;
			goto out;
		}
		rc = chtcp_ksge_alloc_ofld_txq(dev, &txq_info);
		if (rc)
			goto out;

		if (copy_to_user(useraddr, &txq_info, sizeof(txq_info))) {
			rc = -EFAULT;
			goto out;
		}

		break;
	case CHTCP_IOCTL_ALLOC_RXQ_CMD:
		rc = copy_from_user(&rxq_info, useraddr, sizeof(rxq_info));
		if (rc) {
			rc = -EFAULT;
			goto out;
		}
		rc = chtcp_ksge_alloc_ofld_rxq(dev, &rxq_info);
		if (rc)
			goto out;

		if (copy_to_user(useraddr, &rxq_info, sizeof(rxq_info))) {
			rc = -EFAULT;
			goto out;
		}
		break;
	case CHTCP_IOCTL_CPL_PASS_OPEN_CMD:
		rc = chtcp_handle_pass_open_req(dev, useraddr);
		break;
	case CHTCP_IOCTL_CPL_CLOSE_LISTSRV_REQ_CMD:
		rc = chtcp_handle_close_listsrv_req(dev, useraddr);
		break;
	case CHTCP_IOCTL_CPL_PASS_ACCEPT_REQ_CMD:
		rc = chtcp_handle_pass_accept_req(dev, useraddr);
		break;
	case CHTCP_IOCTL_CPL_CLOSE_LISTSRV_RPL_CMD:
		rc = copy_from_user(&stid, useraddr, sizeof(u32));
		if(rc) {
			rc = -EFAULT;
			goto out;
		}
		rc = chtcp_handle_close_listsrv_rpl(dev, stid);
		break;
	case CHTCP_IOCTL_GET_TID_INFO_CMD:
		chtcp_get_tid_info(dev, &t);
		rc = copy_to_user(useraddr, &t, sizeof(t));
		if (rc) {
			rc = -EFAULT;
			goto out;
		}
		break;
	case CHTCP_IOCTL_FREE_SOCK_CMD:
		rc = chtcp_handle_free_sock(dev, useraddr);
		break;
	case CHTCP_IOCTL_FREE_TXQ_CMD:
		rc = copy_from_user(&fti, useraddr, sizeof(fti));
		if(rc) {
			rc = -EFAULT;
			goto out;
		}
		rc = chtcp_kofld_eq_free(dev, &fti);
		if (!rc)
			chtcp_free_ktxq_info(dev, &fti);
		break;
	case CHTCP_IOCTL_FREE_RXQ_CMD:
		rc = copy_from_user(&fri, useraddr, sizeof(fri));
		if(rc) {
			rc = -EFAULT;
			goto out;
		}
		rc = chtcp_kofld_iq_free(dev, &fri);
		if (!rc)
			chtcp_free_krxq_info(dev, &fri);
		break;
	case CHTCP_IOCTL_CHECK_ARP_FAILURE_CMD:
		rc = chtcp_handle_arp_failure(dev, useraddr);
		break;
	case CHTCP_IOCTL_RELEASE_TID_CMD:
		rc = chtcp_handle_release_tid(dev, useraddr);
		break;
	case CHTCP_IOCTL_SETUP_CONM_CTX_CMD:
		rc = copy_from_user(&conm_ctx, useraddr, sizeof(conm_ctx));
		if(rc) {
			rc = -EFAULT;
			goto out;
		}
		rc = chtcp_setup_conm_ctx(dev, &conm_ctx);
		break;
	default:
		pr_err("%s: %s Invalid ioctl %u", pci_name(dev->lldi.pdev),
			__func__, _IOC_NR(cmd));
	}

out:
	mutex_unlock(&dev->adap_lock);
	return rc;
}

const struct file_operations chtcp_fops = {
	.owner	=	THIS_MODULE,
	.open	=	chtcp_open,
	.mmap   =	chtcp_mmap,
	.unlocked_ioctl	= chtcp_ioctl,
	.release	= chtcp_close,
};

static void *setup_chtcp_device(const struct cxgb4_lld_info *lldi)
{
	int ret = 0;
	struct chtcp_kadapter *dev;
	struct port_info *pi;
	char cdevname[20];
	const char *pci_addr = pci_name(lldi->pdev);

	dev = kzalloc(sizeof(struct chtcp_kadapter), GFP_KERNEL);
	if (!dev) {
		pr_err("%s: %s: out of memory\n", pci_addr, __func__);
		ret = -ENOMEM;
		goto out;
	}

	dev->devno = MKDEV(MAJOR(chtcp_dev), (MINOR(chtcp_dev) +
			   atomic_read(&index)));
	cdev_init(&dev->chtcp_cdev, &chtcp_fops);
	if ((ret = cdev_add(&dev->chtcp_cdev, dev->devno, 1)) < 0) {
		pr_err("%s: %s: failed to add char device\n", pci_addr,
			__func__);
		goto free_cdev;
	}

	scnprintf(cdevname, sizeof(cdevname), "chtcp-%d", atomic_read(&index));
	dev->pdev = device_create(chtcp_class, NULL, dev->devno, NULL,
				  cdevname);
	if (IS_ERR(dev->pdev)) {
		ret = PTR_ERR(dev->pdev);
		goto out_unregister_devnode;
	}

	memcpy(&dev->lldi, lldi ,sizeof(struct cxgb4_lld_info));
	dev->nports = lldi->nports;
	pi = netdev_priv(lldi->ports[0]);
	dev->adap = pi->adapter;
	INIT_LIST_HEAD(&dev->lcsk_list);
	INIT_LIST_HEAD(&dev->ktxq_list);
	INIT_LIST_HEAD(&dev->krxq_list);
	mutex_init(&dev->lcsk_lock);
	mutex_init(&dev->adap_lock);
	mutex_lock(&chtcp_list_lock);
	list_add_tail(&dev->list_node, &chtcp_list);
	mutex_unlock(&chtcp_list_lock);
	atomic_inc(&index);

	return dev;
out_unregister_devnode:
	cdev_del(&dev->chtcp_cdev);
free_cdev:
	kfree(dev);
out:
	return NULL;
}

static void *chtcp_uld_add(const struct cxgb4_lld_info *lldi)
{
	void *handle;
	const char *pci_addr = pci_name(lldi->pdev);

	if (chtcp_pci_address && !strstr(chtcp_pci_address, pci_addr)) {
		pr_info("chtcp: adapter %s is not enabled\n", pci_addr);
		return NULL;
	}

	handle = setup_chtcp_device(lldi);
	if (!handle) {
		pr_err("%s: %s chtcp device bringup failed\n",pci_addr,
			__func__);
		goto out;
	}
out:
	return handle;
}

static int chtcp_uld_state_change(void *handle, enum cxgb4_state new_state)
{
	return 0;
}

const static struct cxgb4_uld_info chtcp_uld_info = {
	.name =	CHTCP_DRV_MODULE_NAME,
	.add =	chtcp_uld_add,
	.state_change =	chtcp_uld_state_change,
};

#define CHTCP_DRV_MODULE_DESC		"Chelsio T5-T6 CHTCP Driver"

static __init int chtcp_init_module(void)
{
	int rc = 0;

	pr_info("%s. \n", CHTCP_DRV_MODULE_DESC " " CHTCP_DRV_MODULE_NAME" v" CHTCP_MODULE_VERSION);

	rc = alloc_chrdev_region(&chtcp_dev, 0, CHTCP_MAX_ADAPTER_NUM,
				 CHTCP_DRV_MODULE_NAME);
	if (rc < 0) {
		pr_err("%s: could not allocate major number\n", __func__);
		goto out;
	}

	chtcp_class = class_create(THIS_MODULE, CHTCP_DRV_MODULE_NAME);
	if (IS_ERR(chtcp_class)) {
		pr_err("%s: failed to create class\n",__func__);
		rc = PTR_ERR(chtcp_class);
		goto destory_chrdev;
	}

	rc = cxgb4_register_uld_type(CXGB4_ULD_CHTCP, &chtcp_uld_info);
	if (rc < 0) {
		pr_err("%s: failed to register uld\n",__func__);
		goto unregister_uld;
	}

	return rc;

unregister_uld:
	class_destroy(chtcp_class);
destory_chrdev:
	unregister_chrdev_region(chtcp_dev, CHTCP_MAX_ADAPTER_NUM);
out:
	return rc;
}

static void chtcp_del_sock_list(struct chtcp_kadapter *dev)
{
	struct chtcp_klisten_sock *lcsk, *lcsk_tmp;

	mutex_lock(&dev->lcsk_lock);
	list_for_each_entry_safe(lcsk, lcsk_tmp, &dev->lcsk_list, lcsk_link) {
		struct chtcp_ksock *acsk, *acsk_tmp;

		mutex_lock(&lcsk->acsk_lock);
		list_for_each_entry_safe(acsk, acsk_tmp, &lcsk->acsk_list, acsk_link) {
			/* free accept sock */
			chtcp_free_kcsk(dev, acsk->tid);
		}
		mutex_unlock(&lcsk->acsk_lock);

		/*ret = chtcp_remove_server(dev, lcsk,
					  dev->lldi.rxq_ids[lcsk->port_id]);
		if (ret)
			pr_err("chtcp_remove_server failed: %d\n", ret);*/

	}
	mutex_unlock(&dev->lcsk_lock);
}

static void chtcp_free_all_queues(struct chtcp_kadapter *dev)
{
	struct chtcp_ktxq_info *txqi, *txq_tmp;
	struct chtcp_krxq_info *rxqi, *rxq_tmp;
	int rc;

	list_for_each_entry_safe(txqi, txq_tmp, &dev->ktxq_list, ktxq_link) {
		struct chtcp_free_txq_info fti;

		list_del(&txqi->ktxq_link);
		fti.port_id = txqi->port_id;
		fti.eq_id = txqi->eq_id;
		rc = chtcp_kofld_eq_free(dev, &fti);
		if (rc)
			pr_err("%s: %s: chtcp_kofld_eq_free failed: port id %u eq "
			       "id %u: rc %d\n", pci_name(dev->lldi.pdev), __func__,
				fti.port_id, fti.eq_id, rc);

		kfree(txqi);
	}

	list_for_each_entry_safe(rxqi, rxq_tmp, &dev->krxq_list, krxq_link) {
		struct chtcp_free_rxq_info fri;

		list_del(&rxqi->krxq_link);
		fri.port_id = rxqi->port_id;
		fri.iq_id = rxqi->iq_id;
		fri.fl_id = rxqi->fl_id;
		rc = chtcp_kofld_iq_free(dev, &fri);
		if (rc)
			pr_err("%s: %s: chtcp_kofld_iq_free failed: port id %u eq "
			       "id %u: fl id %u: rc %d\n", pci_name(dev->lldi.pdev), __func__,
				fri.port_id, fri.iq_id, fri.fl_id, rc);
		kfree(rxqi);
	}
}

static __exit void chtcp_exit_module(void)
{
	struct chtcp_kadapter *dev, *tmp;

	mutex_lock(&chtcp_list_lock);
	list_for_each_entry_safe(dev, tmp, &chtcp_list, list_node) {
		device_destroy(chtcp_class, dev->devno);
		cdev_del(&dev->chtcp_cdev);
		list_del(&dev->list_node);
		kfree(dev);
	}
	mutex_unlock(&chtcp_list_lock);

	cxgb4_unregister_uld_type(CXGB4_ULD_CHTCP);
	class_destroy(chtcp_class);
	unregister_chrdev_region(chtcp_dev, CHTCP_MAX_ADAPTER_NUM);
}

module_init(chtcp_init_module);
module_exit(chtcp_exit_module);

MODULE_AUTHOR("Chelsio Communications, Inc.");
MODULE_DESCRIPTION(CHTCP_DRV_MODULE_DESC);
MODULE_VERSION(CHTCP_MODULE_VERSION);
MODULE_LICENSE("Dual BSD/GPL");
