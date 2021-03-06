#include <linux/build-salt.h>
#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(.gnu.linkonce.this_module) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

MODULE_INFO(intree, "Y");

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section(__versions) = {
	{ 0x8ea849e, "module_layout" },
	{ 0xe9186521, "register_netdevice" },
	{ 0x8739f334, "dev_mc_sync_multiple" },
	{ 0x93c20051, "kobject_put" },
	{ 0xe95e308e, "netdev_info" },
	{ 0xab652df1, "kmalloc_caches" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0x867ef945, "dev_mc_unsync" },
	{ 0x349cba85, "strchr" },
	{ 0xca905177, "proc_create_seq_private" },
	{ 0xe3deb977, "param_ops_int" },
	{ 0x754d539c, "strlen" },
	{ 0xf078fd67, "dev_disable_lro" },
	{ 0x19f462ab, "kfree_call_rcu" },
	{ 0xa207869b, "vlan_dev_vlan_id" },
	{ 0x7dba91eb, "__skb_flow_dissect" },
	{ 0x79aa04a2, "get_random_bytes" },
	{ 0x1fbcca2a, "seq_puts" },
	{ 0x676f41c, "netdev_rx_handler_register" },
	{ 0xc7a4fbed, "rtnl_lock" },
	{ 0x4cba4ca4, "vlan_uses_dev" },
	{ 0xfa690589, "netdev_cmd_to_name" },
	{ 0x25f0412e, "netif_carrier_on" },
	{ 0xef50cae4, "dst_release" },
	{ 0xb3635b01, "_raw_spin_lock_bh" },
	{ 0xa2272dc8, "skb_clone" },
	{ 0xffeedf6a, "delayed_work_timer_fn" },
	{ 0xbc3bdc7f, "flow_get_u32_src" },
	{ 0xcc5ee855, "seq_printf" },
	{ 0xd2da1048, "register_netdevice_notifier" },
	{ 0xd50e8a85, "netif_carrier_off" },
	{ 0x56470118, "__warn_printk" },
	{ 0x2df5580c, "netdev_master_upper_dev_get" },
	{ 0xd4dcfc9f, "remove_proc_entry" },
	{ 0x837b7b09, "__dynamic_pr_debug" },
	{ 0xf36a3159, "dev_set_allmulti" },
	{ 0x6ac8e490, "vlan_vid_del" },
	{ 0x974b80f1, "netpoll_poll_dev" },
	{ 0x427b95e2, "call_netdevice_notifiers" },
	{ 0xb659397a, "__dev_kfree_skb_any" },
	{ 0xc6f46339, "init_timer_key" },
	{ 0x9fa7184a, "cancel_delayed_work_sync" },
	{ 0xbcb0eb0b, "vlan_vid_add" },
	{ 0xe7941a72, "__netpoll_setup" },
	{ 0x70eff63e, "vlan_vids_del_by_dev" },
	{ 0x3c3ff9fd, "sprintf" },
	{ 0xc10f0ffb, "pv_ops" },
	{ 0xaeca8b04, "netdev_walk_all_upper_dev_rcu" },
	{ 0x15ba50a6, "jiffies" },
	{ 0x5f43e360, "__dynamic_netdev_dbg" },
	{ 0x9d0d6206, "unregister_netdevice_notifier" },
	{ 0xfddcf1d, "skb_trim" },
	{ 0xe2d5255a, "strcmp" },
	{ 0xb5c70ad6, "vlan_vids_add_by_dev" },
	{ 0x7aba6573, "netdev_master_upper_dev_link" },
	{ 0x2c581fd4, "dev_mc_add" },
	{ 0x4f14051e, "__netdev_alloc_skb" },
	{ 0xb7885dcc, "netdev_lower_get_next_private_rcu" },
	{ 0xd318e213, "netdev_lower_state_changed" },
	{ 0xdf84e749, "__pskb_pull_tail" },
	{ 0x84837dfe, "netdev_change_features" },
	{ 0xcd5c6c21, "netpoll_send_skb_on_dev" },
	{ 0x6b10bee1, "_copy_to_user" },
	{ 0x367a4d53, "PDE_DATA" },
	{ 0x4136a96f, "netdev_has_upper_dev" },
	{ 0xf1db1704, "nla_memcpy" },
	{ 0xa16fc7b3, "param_ops_charp" },
	{ 0x5f155dd7, "dev_set_mac_address" },
	{ 0xeba59bcd, "unregister_pernet_subsys" },
	{ 0xe877be74, "proc_mkdir" },
	{ 0x9fdecc31, "unregister_netdevice_many" },
	{ 0x11089ac7, "_ctype" },
	{ 0xc025016c, "flow_keys_dissector" },
	{ 0x38643aa3, "current_task" },
	{ 0x4c29440, "__ethtool_get_link_ksettings" },
	{ 0xac9b67d7, "arp_create" },
	{ 0xc5850110, "printk" },
	{ 0x27562caa, "ethtool_op_get_link" },
	{ 0xbcab6ee6, "sscanf" },
	{ 0xe1537255, "__list_del_entry_valid" },
	{ 0xa965ca81, "reciprocal_value" },
	{ 0xe0e3cea6, "ns_capable" },
	{ 0x9cf230cf, "kobject_init_and_add" },
	{ 0x62849ac7, "dev_valid_name" },
	{ 0x54a25aaf, "netdev_class_remove_file_ns" },
	{ 0x6606939d, "free_netdev" },
	{ 0xe7b00dfb, "__x86_indirect_thunk_r13" },
	{ 0x9166fada, "strncpy" },
	{ 0x7b855f37, "dev_mc_del" },
	{ 0xe429d9a0, "nla_put" },
	{ 0xf3847883, "netdev_upper_dev_unlink" },
	{ 0x5a921311, "strncmp" },
	{ 0x5792f848, "strlcpy" },
	{ 0xab1248be, "skb_push" },
	{ 0x652032cb, "mac_pton" },
	{ 0x8c03d20c, "destroy_workqueue" },
	{ 0x37f36ab6, "dev_close" },
	{ 0xf4f14de6, "rtnl_trylock" },
	{ 0x122994b7, "netdev_bonding_info_change" },
	{ 0xeb31264c, "dev_mc_flush" },
	{ 0xfda9581f, "prandom_u32" },
	{ 0x6091797f, "synchronize_rcu" },
	{ 0x396ffb6d, "inet_confirm_addr" },
	{ 0x90cfa369, "init_net" },
	{ 0x262b5ec7, "rtnl_link_unregister" },
	{ 0x9a49c55, "__dev_get_by_index" },
	{ 0x68f31cbd, "__list_add_valid" },
	{ 0xfa731956, "netdev_lower_dev_get_private" },
	{ 0x9eacf8a5, "kstrndup" },
	{ 0x371b5e60, "dev_open" },
	{ 0xae414502, "dev_uc_flush" },
	{ 0xc6cbbc89, "capable" },
	{ 0xb601be4c, "__x86_indirect_thunk_rdx" },
	{ 0x1d05158e, "netdev_upper_get_next_dev_rcu" },
	{ 0x2e89682e, "sysfs_remove_file_ns" },
	{ 0x49c41a57, "_raw_spin_unlock_bh" },
	{ 0xb2fcb56d, "queue_delayed_work_on" },
	{ 0xdecd0b29, "__stack_chk_fail" },
	{ 0x869db7f, "vlan_dev_vlan_proto" },
	{ 0x49d026fd, "netdev_rx_handler_unregister" },
	{ 0x1d24c881, "___ratelimit" },
	{ 0xb8b9f817, "kmalloc_order_trace" },
	{ 0x5a460992, "kfree_skb" },
	{ 0xac5fcec0, "in4_pton" },
	{ 0x9eb26fb5, "passthru_features_check" },
	{ 0xdff5a870, "alloc_netdev_mqs" },
	{ 0x2ea2c95c, "__x86_indirect_thunk_rax" },
	{ 0xc38d2e99, "arp_xmit" },
	{ 0x46571785, "netdev_lower_get_next_private" },
	{ 0xa751f358, "register_pernet_subsys" },
	{ 0x94f5f1a, "pskb_expand_head" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x1426720b, "netdev_err" },
	{ 0x7bcee6c0, "ether_setup" },
	{ 0x23d1c7a1, "dev_uc_unsync" },
	{ 0xd7a02f91, "__dev_get_by_name" },
	{ 0x9fad3bb0, "kmem_cache_alloc_trace" },
	{ 0xdbf17652, "_raw_spin_lock" },
	{ 0x8e024d8f, "unregister_netdevice_queue" },
	{ 0x16104dc3, "ip_route_output_flow" },
	{ 0xf6ebc03b, "net_ratelimit" },
	{ 0x688a7c42, "netdev_warn" },
	{ 0x4fb92907, "__skb_flow_get_ports" },
	{ 0x406eadda, "dev_set_promiscuity" },
	{ 0x8516c14a, "flow_get_u32_dst" },
	{ 0x37a0cba, "kfree" },
	{ 0xc664f69d, "dev_uc_sync_multiple" },
	{ 0x69acdf38, "memcpy" },
	{ 0xdc9cb4e2, "param_array_ops" },
	{ 0xca1b8576, "dev_trans_start" },
	{ 0xc91d6876, "__dev_set_mtu" },
	{ 0x799debac, "rtnl_link_register" },
	{ 0xdfbaba18, "dev_uc_sync" },
	{ 0x8d7079b3, "netdev_lower_get_first_private_rcu" },
	{ 0xa0dad88e, "netdev_adjacent_get_private" },
	{ 0x901d0e5, "nla_put_64bit" },
	{ 0x74f424ff, "__netpoll_free" },
	{ 0x656e4a6e, "snprintf" },
	{ 0xb0e602eb, "memmove" },
	{ 0x7eb890a3, "consume_skb" },
	{ 0x85670f1d, "rtnl_is_locked" },
	{ 0x7f02188f, "__msecs_to_jiffies" },
	{ 0xf416b840, "sysfs_create_file_ns" },
	{ 0xe56ac49e, "dev_queue_xmit" },
	{ 0x9a9985f1, "netdev_is_rx_handler_busy" },
	{ 0x6dfebd71, "skb_put" },
	{ 0x13c49cc2, "_copy_from_user" },
	{ 0xd04f09af, "param_ops_uint" },
	{ 0x78131b29, "skb_copy_bits" },
	{ 0x5e80f63f, "dev_mc_sync" },
	{ 0xdf9208c0, "alloc_workqueue" },
	{ 0x7ea0e08b, "dev_pre_changeaddr_notify" },
	{ 0x6e720ff2, "rtnl_unlock" },
	{ 0x69668826, "netdev_increment_features" },
	{ 0x210763d6, "dev_get_stats" },
	{ 0x7af5935f, "netdev_class_create_file_ns" },
	{ 0xc0013de6, "dev_set_mtu" },
	{ 0xe914e41e, "strcpy" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "D3884F53B7ABFFC65462996");
