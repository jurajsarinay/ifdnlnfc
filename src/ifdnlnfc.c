/*
 *
 *  libnlnfc - PC/SC IFD Handler for Linux NFC subsystem
 *
 *  Copyright (C) 2024 Juraj Šarinay <juraj@sarinay.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 *
 *  uses code from neard & nfctool by Intel
 *  https://github.com/linux-nfc/neard
 *
 *  ATR derivation code adapted from ifdnfc by Frank Morgner
 *  https://github.com/nfc-tools/ifdnfc
 *
 */

#include "config.h"

#include "ifdnlnfc.h"
#include <debuglog.h>
#include <errno.h>
#include <ifdhandler.h>
#include <linux/nfc.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>
#include <netlink/handlers.h>
#include <netlink/netlink.h>
#include <sys/uio.h>
#include <unistd.h>

static struct nl_sock *cmd_sock, *event_sock;
static int nfc_family_id;
static struct ifdnlnfc_state ifdnlnfc_state = {};

static int nl_error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
			void *arg)
{
	int *ret = arg;
	*ret = err->error;
	return NL_STOP;
}

static int nl_finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;

	*ret = 1;

	return NL_SKIP;
}

static int nl_ack_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;

	*ret = 1;

	return NL_SKIP;
}

static int nl_send_msg(struct nl_sock *sock, struct nl_msg *msg,
		int (*rx_handler)(struct nl_msg *, void *),
		void *data)
{
	struct nl_cb *cb;
	int err, done;

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb)
		return -ENOMEM;

	err = nl_send_auto_complete(sock, msg);
	if (err < 0) {
		nl_cb_put(cb);
		return err;
	}

	err = done = 0;

	nl_cb_err(cb, NL_CB_CUSTOM, nl_error_handler, &err);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, nl_finish_handler, &done);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, nl_ack_handler, &done);

	if (rx_handler)
		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, rx_handler, data);

	while (err == 0 && done == 0)
		nl_recvmsgs(sock, cb);

	nl_cb_put(cb);

	return err;
}


static int nl_set_powered(struct nfc_adapter * adapter, int powered)
{
	struct nl_msg *msg;
	void *hdr;
	int err;
	uint8_t cmd;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	if (powered)
		cmd = NFC_CMD_DEV_UP;
	else
		cmd = NFC_CMD_DEV_DOWN;

	hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, nfc_family_id, 0,
			NLM_F_REQUEST, cmd, NFC_GENL_VERSION);
	if (!hdr) {
		err = -EINVAL;
		goto nla_put_failure;
	}

	err = -EMSGSIZE;

	NLA_PUT_U32(msg, NFC_ATTR_DEVICE_INDEX, adapter->idx);

	err = nl_send_msg(cmd_sock, msg, NULL, NULL);

	if (err)
		Log3(PCSC_LOG_ERROR, "Error powering %s NFC adapter. Idx: %d", powered ? "up" : "down", adapter->idx);
	else
		Log3(PCSC_LOG_INFO, "Powering %s NFC adapter. Idx: %d", powered ? "up" : "down", adapter->idx);

nla_put_failure:
	nlmsg_free(msg);
	return err;
}

static int nl_reactivate_target(uint32_t adapter_idx, uint32_t target_idx, uint32_t protocol)
{
	struct nl_msg *msg;
	void *hdr;
	int err;
	uint8_t cmd;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	cmd = NFC_CMD_ACTIVATE_TARGET;

	hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, nfc_family_id, 0,
			NLM_F_REQUEST, cmd, NFC_GENL_VERSION);
	if (!hdr) {
		err = -EINVAL;
		goto nla_put_failure;
	}

	err = -EMSGSIZE;

	NLA_PUT_U32(msg, NFC_ATTR_DEVICE_INDEX, adapter_idx);
	NLA_PUT_U32(msg, NFC_ATTR_TARGET_INDEX, target_idx);
	NLA_PUT_U32(msg, NFC_ATTR_PROTOCOLS, protocol);

	err = nl_send_msg(cmd_sock, msg, NULL, NULL);

nla_put_failure:
	nlmsg_free(msg);
	return err;
}

static int set_atr_from_hb(struct nfc_target *target, unsigned char * hb, int hb_len)
{
	int len = 4 + hb_len;

	if (len + 1 > MAX_ATR_SIZE) {
		/* should never happen */
		Log1(PCSC_LOG_ERROR, "Too many historical bytes.");
		return -1;
	}

	target->atr[0] = 0x3b;
	target->atr[1] = 0x80 + hb_len;
	target->atr[2] = 0x80;
	target->atr[3] = 0x01;

	if (hb_len > 0)
		memcpy(&target->atr[4], hb, hb_len);

	unsigned char tck = target->atr[1];
	for (int i = 2; i < len; i++)
		tck ^= target->atr[i];

	target->atr[len] = tck;
	target->atr_len = len + 1;

	return 0;
}

static int get_targets_handler(struct nl_msg *msg, void *arg)
{
        struct nlmsghdr *nlh = nlmsg_hdr(msg);
        struct nlattr *attrs[NFC_ATTR_MAX + 1];

	struct list_targets_cb_state *state = arg;

	unsigned char hb[8];

        genlmsg_parse(nlh, 0, attrs, NFC_ATTR_MAX, NULL);

        if (!attrs[NFC_ATTR_TARGET_INDEX] || !attrs[NFC_ATTR_PROTOCOLS]) {
		return NL_SKIP;
	}

	if (state->found == 1) {
		Log1(PCSC_LOG_INFO, "Multiple NFC targets found. All but the first one will be ignored.");
	}

	if (state->found++) {
		return NL_SKIP; // at the moment limit to a single target
	}

	state->target->idx = nla_get_u32(attrs[NFC_ATTR_TARGET_INDEX]);
        state->target->supported_protocols = nla_get_u32(attrs[NFC_ATTR_PROTOCOLS]);

	Log3(PCSC_LOG_INFO, "NFC target found. Index: %d, supported protocols: %0x.", state->target->idx, state->target->supported_protocols);

	if (state->target->supported_protocols & NFC_PROTO_ISO14443_B_MASK) {

		if (attrs[NFC_ATTR_TARGET_SENSB_RES])
			LogXxd(PCSC_LOG_DEBUG, "ATQB: ", nla_data(attrs[NFC_ATTR_TARGET_SENSB_RES]), nla_len(attrs[NFC_ATTR_TARGET_SENSB_RES]));

		if (attrs[NFC_ATTR_TARGET_SENSB_RES] && nla_len(attrs[NFC_ATTR_TARGET_SENSB_RES]) == 11) {
			memcpy(hb, nla_data(attrs[NFC_ATTR_TARGET_SENSB_RES]) + 4, 7);
			hb[7] = 0;
			set_atr_from_hb(state->target, hb, 8);
		}
		else
			set_atr_from_hb(state->target, NULL, 0);
	}

	return NL_OK;
}

static int get_target_ats_handler(struct nl_msg *msg, void *arg)
{
        struct nlmsghdr *nlh = nlmsg_hdr(msg);
        struct nlattr *attrs[NFC_ATTR_MAX + 1];
	int hb_len = 0;
	unsigned char * hb = NULL;

	int ats_len = 0;
	unsigned char * ats = NULL;

	struct list_targets_cb_state *state = arg;

        genlmsg_parse(nlh, 0, attrs, NFC_ATTR_MAX, NULL);

	if (state->found || !attrs[NFC_ATTR_TARGET_INDEX] || state->target->idx != nla_get_u32(attrs[NFC_ATTR_TARGET_INDEX]))
		return NL_SKIP;

	state->found = 1;

	if (attrs[NFC_ATTR_TARGET_ATS]) {
		ats_len = nla_len(attrs[NFC_ATTR_TARGET_ATS]);
		ats = nla_data(attrs[NFC_ATTR_TARGET_ATS]);
		LogXxd(PCSC_LOG_DEBUG, "Got ATS: ", ats, ats_len);
	}
	else {
		Log1(PCSC_LOG_DEBUG, "ATS not present");
	}

	if (ats_len > 1) {
		hb_len = ats_len - 1;
		if (ats[0] & 0x40) hb_len--;
		if (ats[0] & 0x20) hb_len--;
		if (ats[0] & 0x10) hb_len--;
		if (hb_len > 0) hb = ats_len - hb_len + ats;
		if (hb_len < 0) {
			Log1(PCSC_LOG_ERROR, "ATS invalid");
			hb_len = 0;
		}
	}

	set_atr_from_hb(state->target, hb, hb_len);

        return NL_OK;
}

static int list_targets(struct nfc_adapter * adapter, struct nfc_target *result)
{
        struct nl_msg *msg;
        void *hdr;
	int err = -1;

	struct list_targets_cb_state state = {0, result};

	msg = nlmsg_alloc();
        if (!msg)
                return -ENOMEM;

        hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, nfc_family_id, 0,
			NLM_F_DUMP, NFC_CMD_GET_TARGET, NFC_GENL_VERSION);
        if (!hdr) {
                err = -EINVAL;
                goto nla_put_failure;
        }

	NLA_PUT_U32(msg, NFC_ATTR_DEVICE_INDEX, adapter->idx);

	if (!nl_send_msg(cmd_sock, msg, get_targets_handler, &state) && state.found) {
		nlmsg_free(msg);
		return 0;
	}

nla_put_failure:
	nlmsg_free(msg);
	return err;
}

static int get_target_ats(struct nfc_adapter * adapter, struct nfc_target * target)
{
        struct nl_msg *msg;
        void *hdr;
	int err = -ENOENT;

	struct list_targets_cb_state state = {0, target};

	msg = nlmsg_alloc();
        if (!msg)
                return -ENOMEM;

        hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, nfc_family_id, 0,
			NLM_F_DUMP, NFC_CMD_GET_TARGET, NFC_GENL_VERSION);
        if (!hdr) {
                err = -EINVAL;
                goto nla_put_failure;
        }

	NLA_PUT_U32(msg, NFC_ATTR_DEVICE_INDEX, adapter->idx);

	err = nl_send_msg(cmd_sock, msg, get_target_ats_handler, &state);

	if (!err && state.found) {
		nlmsg_free(msg);
		return 0;
	}

nla_put_failure:
	nlmsg_free(msg);
	return err;
}

static int event_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *attr[NFC_ATTR_MAX + 1];
        struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	uint32_t cmd = gnlh->cmd;
	int * card_present = arg;
	uint32_t device_index;

	if (cmd != NFC_EVENT_TARGETS_FOUND || !ifdnlnfc_state.channel_open)
		return NL_SKIP;

	nla_parse(attr, NFC_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

	if (!attr[NFC_ATTR_DEVICE_INDEX])
		return NL_SKIP;

	device_index = nla_get_u32(attr[NFC_ATTR_DEVICE_INDEX]);

	if (device_index == ifdnlnfc_state.adapter.idx) {
		*card_present = 1;
		ifdnlnfc_state.adapter.poll_active = 0;
		Log2(PCSC_LOG_DEBUG, "NFC_TARGETS_FOUND. Adapter index:%d.", device_index);
		return NL_OK;
	}
	return NL_SKIP;
}

static int family_handler(struct nl_msg *msg, void *arg)
{
        int *group_id = arg;
        struct nlattr *tb[CTRL_ATTR_MAX + 1];
        struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
        struct nlattr *mcgrp;
        int rem_mcgrp;

        nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		genlmsg_attrlen(gnlh, 0), NULL);

        if (!tb[CTRL_ATTR_MCAST_GROUPS])
                return NL_SKIP;

        nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], rem_mcgrp) {
                struct nlattr *tb_mcgrp[CTRL_ATTR_MCAST_GRP_MAX + 1];

                nla_parse(tb_mcgrp, CTRL_ATTR_MCAST_GRP_MAX,
			nla_data(mcgrp), nla_len(mcgrp), NULL);

                if (!tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME] ||
			!tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID])
                        continue;
                if (strncmp(nla_data(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME]),
				NFC_GENL_MCAST_EVENT_NAME,
				nla_len(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME])))
                        continue;
                *group_id = nla_get_u32(tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID]);
		return NL_OK;
        }

        return NL_SKIP;
}

static int get_multicast_id(struct nl_sock *sock, int *group_id)
{
        struct nl_msg *msg;
        int err = -EINVAL;
	int ctrlid;

        msg = nlmsg_alloc();
        if (!msg)
                return -ENOMEM;

        ctrlid = genl_ctrl_resolve(sock, "nlctrl");

        genlmsg_put(msg, 0, 0, ctrlid, 0,
		0, CTRL_CMD_GETFAMILY, 0);

        NLA_PUT_STRING(msg, CTRL_ATTR_FAMILY_NAME, NFC_GENL_NAME);

	err = nl_send_msg(sock, msg, family_handler, group_id);

nla_put_failure:
	nlmsg_free(msg);
	return err;
}

static int get_device_handler(struct nl_msg *n, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(n);
	struct nlattr *attrs[NFC_ATTR_MAX + 1];
        uint32_t protocols = 0;
        uint8_t powered, rf_mode;

	struct get_adapter_cb_state *state = arg;

        genlmsg_parse(nlh, 0, attrs, NFC_ATTR_MAX, NULL);

        if (attrs[NFC_ATTR_DEVICE_POWERED]) {
		powered = nla_get_u8(attrs[NFC_ATTR_DEVICE_POWERED]);
	}

	if (attrs[NFC_ATTR_RF_MODE]) {
		rf_mode =  nla_get_u8(attrs[NFC_ATTR_RF_MODE]);
        }

        if (attrs[NFC_ATTR_PROTOCOLS])
	{
                protocols = nla_get_u32(attrs[NFC_ATTR_PROTOCOLS]);
		if (protocols & (NFC_PROTO_ISO14443_MASK | NFC_PROTO_ISO14443_B_MASK)) {
			state->found = 1;
			state->adapter->idx = state->idx;
			state->adapter->initial_mode = rf_mode;
			state->adapter->initial_power = powered;

			Log4(PCSC_LOG_INFO, "NFC adapter found. Index: %d, powered: %d, supported protocols: %0x.", state->adapter->idx, powered, protocols);

		}
	}

        return NL_SKIP;
}

static int list_devices_handler(struct nl_msg *n, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(n);
	struct nlattr *attrs[NFC_ATTR_MAX + 1];
        uint32_t protocols = 0;
        uint8_t powered, rf_mode;

	struct list_adapters_cb_state * state = arg;

	if (state->found)
		return NL_SKIP;

        genlmsg_parse(nlh, 0, attrs, NFC_ATTR_MAX, NULL);

	if (!attrs[NFC_ATTR_DEVICE_NAME] || nla_strcmp(attrs[NFC_ATTR_DEVICE_NAME], state->name)) return NL_SKIP;

        if (!attrs[NFC_ATTR_DEVICE_INDEX]) {
                return NL_STOP;
        }

        if (attrs[NFC_ATTR_DEVICE_POWERED]) {
		powered =  nla_get_u8(attrs[NFC_ATTR_DEVICE_POWERED]);
	}

	if (attrs[NFC_ATTR_RF_MODE]) {
		rf_mode =  nla_get_u8(attrs[NFC_ATTR_RF_MODE]);
        }

        if (attrs[NFC_ATTR_PROTOCOLS])
	{
                protocols = nla_get_u32(attrs[NFC_ATTR_PROTOCOLS]);
		if (protocols & (NFC_PROTO_ISO14443_MASK | NFC_PROTO_ISO14443_B_MASK)) {
			state->found = 1;
			state->adapter->idx = nla_get_u32(attrs[NFC_ATTR_DEVICE_INDEX]);
			state->adapter->initial_mode = rf_mode;
			state->adapter->initial_power = powered;

			Log5(PCSC_LOG_INFO, "NFC adapter found. Name: %s, Index: %d, powered: %d, supported protocols: %0x.", state->name, state->adapter->idx, powered, protocols);

		}
	}

        return NL_SKIP;
}

static int poll_for_targets(struct nfc_adapter * adapter)
{
	struct nl_msg *msg;
        void *hdr;
        int err = -EINVAL;

	if (ifdnlnfc_state.adapter.poll_active) {
		Log2(PCSC_LOG_ERROR, "Poll active, not starting. Adapter index: %d.", adapter->idx);
		return 0;
	}

	msg = nlmsg_alloc();
        if (!msg)
                return -ENOMEM;

        hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, nfc_family_id, 0,
			NLM_F_REQUEST, NFC_CMD_START_POLL, NFC_GENL_VERSION);
        if (!hdr) {
                err = -EINVAL;
                goto nla_put_failure;
        }

	NLA_PUT_U32(msg, NFC_ATTR_DEVICE_INDEX, adapter->idx);
	NLA_PUT_U32(msg, NFC_ATTR_IM_PROTOCOLS, NFC_PROTO_ISO14443_MASK |  NFC_PROTO_ISO14443_B_MASK);

	err = nl_send_msg(cmd_sock, msg, NULL, NULL);

	if (err)
		Log3(PCSC_LOG_ERROR, "Error %x starting NFC target poll. Adapter index: %d.", err, adapter->idx);
	else {
		Log2(PCSC_LOG_DEBUG, "NFC target poll started. Adapter index:%d.", adapter->idx);
		ifdnlnfc_state.adapter.poll_active = 1;
	}

nla_put_failure:
	return err;
}

static int stop_poll_for_targets(struct nfc_adapter * adapter)
{
	struct nl_msg *msg;
        void *hdr;
        int err = -EINVAL;

	if (!adapter->poll_active) {
		Log2(PCSC_LOG_ERROR, "Poll not active, nothing to stop. Adapter index: %d.", adapter->idx);
		return 0;
	}

	msg = nlmsg_alloc();
        if (!msg)
                return -ENOMEM;

        hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, nfc_family_id, 0,
			NLM_F_REQUEST, NFC_CMD_STOP_POLL, NFC_GENL_VERSION);
        if (!hdr) {
                err = -EINVAL;
                goto nla_put_failure;
        }

	NLA_PUT_U32(msg, NFC_ATTR_DEVICE_INDEX, adapter->idx);

	err = nl_send_msg(cmd_sock, msg, NULL, NULL);

	if (err)
		Log3(PCSC_LOG_ERROR, "Error %x stopping NFC target poll. Adapter index: %d.", err, adapter->idx);
	else {
		adapter->poll_active=0;
		Log2(PCSC_LOG_DEBUG, "NFC target poll stopped. Adapter index: %d.", adapter->idx);
	}
nla_put_failure:
	return err;
}

static int get_adapter_by_idx(uint32_t idx, struct nfc_adapter *adapter)
{
	struct nl_msg *msg;
        void *hdr;
        int err = -EINVAL;

	struct get_adapter_cb_state state = {idx, 0, adapter};

	msg = nlmsg_alloc();
        if (!msg)
                return -ENOMEM;

        hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, nfc_family_id, 0,
			NLM_F_REQUEST, NFC_CMD_GET_DEVICE, NFC_GENL_VERSION);
        if (!hdr) {
                err = -EINVAL;
                goto nla_put_failure;
        }

	NLA_PUT_U32(msg, NFC_ATTR_DEVICE_INDEX, idx);

	err = nl_send_msg(cmd_sock, msg, get_device_handler, &state);

	if (state.found) {
		err = 0;
	}
	else if (!err) {
		err = -ENODEV;
		Log2(PCSC_LOG_INFO, "NFC adapter not found. Index: %d", idx);
	}

nla_put_failure:
	nlmsg_free(msg);
	return err;
}

static int get_adapter_by_name(const char * adapter_name, struct nfc_adapter * adapter)
{
	struct nl_msg *msg;
        void *hdr;
        int err = 0;

	struct list_adapters_cb_state state = {adapter_name, 0, adapter};

	msg = nlmsg_alloc();
        if (!msg)
                return -ENOMEM;

        hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, nfc_family_id, 0,
			NLM_F_DUMP, NFC_CMD_GET_DEVICE, NFC_GENL_VERSION);
        if (!hdr) {
                err = -EINVAL;
                goto nla_put_failure;
        }

	err = nl_send_msg(cmd_sock, msg, list_devices_handler, &state);

	if (!err || !state.found) {
		err = -ENODEV;
		Log2(PCSC_LOG_INFO, "Adapter %s not found.", adapter_name);
	}

	nlmsg_free(msg);

nla_put_failure:
	return err;
}

static int netlink_cleanup()
{
	// no explicit nl_close() necessary
	nl_socket_free(cmd_sock);
	nl_socket_free(event_sock);
	return 0;
}

static int netlink_setup()
{
	int err, group_id;

        cmd_sock = nl_socket_alloc();

	if (!cmd_sock) {
		Log1(PCSC_LOG_ERROR, "Out of memory");
		return -ENOMEM;
	}

	event_sock = nl_socket_alloc();

	if (!event_sock) {
		nl_socket_free(cmd_sock);
		Log1(PCSC_LOG_ERROR, "Out of memory");
		return -ENOMEM;
	}

	err = genl_connect(cmd_sock);
	if (err) {
		netlink_cleanup();
		return err;
	}

	err = genl_connect(event_sock);
	if (err) {
		netlink_cleanup();
		return err;
	}

	err = nl_socket_set_nonblocking(event_sock);
	if (err) {
		netlink_cleanup();
		return err;
	}

	nfc_family_id = genl_ctrl_resolve(cmd_sock, "nfc");
        if (nfc_family_id < 0) {
		Log1(PCSC_LOG_DEBUG, "Unable to find NFC netlink family");
                err = -ENOENT;
        }

	err = get_multicast_id(cmd_sock, &group_id);

	if (err) {
		Log1(PCSC_LOG_DEBUG, "Unable to find multicast group ID");
		return err;
	}

	struct nl_cb *cb = nl_cb_alloc(NL_CB_VERBOSE);

	if (!cb) {
		Log1(PCSC_LOG_ERROR, "Out of memory");
		return -ENOMEM;
	}

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, event_handler, &ifdnlnfc_state.card_present);
	nl_socket_set_cb(event_sock, cb);
	nl_socket_disable_seq_check(event_sock);

	err = nl_socket_add_membership(event_sock, group_id);

	if (err)
		Log1(PCSC_LOG_DEBUG, "Error adding nl socket to notification group");

	return err;
}

static int connect_target(struct nfc_adapter *adapter, struct nfc_target *target)
{
	int err;
	uint32_t protocol = 0;

	if (target->supported_protocols & NFC_PROTO_ISO14443_MASK)
		protocol = NFC_PROTO_ISO14443;
	else if (target->supported_protocols & NFC_PROTO_ISO14443_B_MASK)
		protocol = NFC_PROTO_ISO14443_B;
	else {
		Log1(PCSC_LOG_DEBUG, "connect_target(): No suitable NFC protocol found.");
		return -1;
	}

	struct sockaddr_nfc sa = {PF_NFC, adapter->idx, target->idx, protocol};

	int fd = socket(AF_NFC, SOCK_SEQPACKET, NFC_SOCKPROTO_RAW);
	if (fd == -1)
		return -1;

	err = connect(fd, (struct sockaddr *) &sa, sizeof(sa));
	if (!err){
		ifdnlnfc_state.socket = fd;
		target->active_protocol = protocol;
		Log3(PCSC_LOG_DEBUG, "Connected to NFC target. Index: %d, Protocol: %0x.", target->idx, protocol);
		if (protocol == NFC_PROTO_ISO14443) get_target_ats(adapter, target);
	}
	else {
		close(fd);
	}

	return err;
}

RESPONSECODE
IFDHCreateChannelByName(DWORD Lun, LPSTR DeviceName)
{
	if (ifdnlnfc_state.channel_open || !DeviceName || netlink_setup())
		return IFD_COMMUNICATION_ERROR;

	if (get_adapter_by_name(DeviceName, &ifdnlnfc_state.adapter)) {
		netlink_cleanup();
		return IFD_NO_SUCH_DEVICE;
	}

	if ((ifdnlnfc_state.adapter.initial_power || !nl_set_powered(&ifdnlnfc_state.adapter, 1)) && poll_for_targets(&ifdnlnfc_state.adapter)) {
		netlink_cleanup();
		return IFD_COMMUNICATION_ERROR;
	}

	ifdnlnfc_state.channel_open = 1;

	return IFD_SUCCESS;
}

RESPONSECODE
IFDHCreateChannel(DWORD Lun, DWORD Channel)
{

	if (ifdnlnfc_state.channel_open || netlink_setup())
		return IFD_COMMUNICATION_ERROR;

	if (get_adapter_by_idx(Channel, &ifdnlnfc_state.adapter))
	{
		netlink_cleanup();
		return IFD_NO_SUCH_DEVICE;
	}

	if ((ifdnlnfc_state.adapter.initial_power || !nl_set_powered(&ifdnlnfc_state.adapter, 1)) && poll_for_targets(&ifdnlnfc_state.adapter)) {
		netlink_cleanup();
		return IFD_COMMUNICATION_ERROR;
	}

	ifdnlnfc_state.channel_open = 1;

	return IFD_SUCCESS;
}

RESPONSECODE
IFDHCloseChannel(DWORD Lun)
{
	if (!ifdnlnfc_state.channel_open)
		return IFD_COMMUNICATION_ERROR;

	if (ifdnlnfc_state.socket)
		close(ifdnlnfc_state.socket);

	stop_poll_for_targets(&ifdnlnfc_state.adapter);

	if (!ifdnlnfc_state.adapter.initial_power)
		nl_set_powered(&ifdnlnfc_state.adapter, 0);

	ifdnlnfc_state.socket = 0;
	ifdnlnfc_state.channel_open = 0;

	netlink_cleanup();

	return IFD_SUCCESS;
}

RESPONSECODE
IFDHGetCapabilities(DWORD Lun, DWORD Tag, PDWORD Length, PUCHAR Value)
{

	if (!Length || !Value)
		return IFD_COMMUNICATION_ERROR;
	if (*Length < 1)
		return IFD_ERROR_INSUFFICIENT_BUFFER;

	switch (Tag) {
	case TAG_IFD_ATR:
#ifdef SCARD_ATTR_ATR_STRING
	case SCARD_ATTR_ATR_STRING:
#endif
		if (!ifdnlnfc_state.socket)
			return IFD_COMMUNICATION_ERROR;
		if (*Length < ifdnlnfc_state.target.atr_len)
			return IFD_ERROR_INSUFFICIENT_BUFFER;
		*Length = ifdnlnfc_state.target.atr_len;
		memcpy(Value, &ifdnlnfc_state.target.atr, *Length);
		break;
	case TAG_IFD_SIMULTANEOUS_ACCESS:
		*Value = 0;
		*Length = 1;
		break;
	case TAG_IFD_THREAD_SAFE:
		*Value  = 0;
		*Length = 1;
		break;
	case TAG_IFD_SLOTS_NUMBER:
		*Value  = 1;
		*Length = 1;
		break;
	default:
		Log2(PCSC_LOG_DEBUG, "Tag %08lx not supported", Tag);
		return IFD_ERROR_TAG;
	}
	return IFD_SUCCESS;
}

RESPONSECODE
IFDHSetCapabilities(DWORD Lun, DWORD Tag, DWORD Length, PUCHAR Value)
{
	return IFD_ERROR_VALUE_READ_ONLY;
}

RESPONSECODE
IFDHSetProtocolParameters(DWORD Lun, DWORD Protocol, UCHAR Flags, UCHAR PTS1,
			UCHAR PTS2, UCHAR PTS3)
{
	if (Protocol != SCARD_PROTOCOL_T1)
		return IFD_PROTOCOL_NOT_SUPPORTED;

	return IFD_SUCCESS;
}

RESPONSECODE
IFDHPowerICC(DWORD Lun, DWORD Action, PUCHAR Atr, PDWORD AtrLength)
{
	int err = 0;

	switch (Action) {

	case IFD_RESET:
		Log1(PCSC_LOG_DEBUG, "IFD_RESET");
		if (ifdnlnfc_state.socket){
			if (!nl_reactivate_target(ifdnlnfc_state.adapter.idx, ifdnlnfc_state.target.idx, ifdnlnfc_state.target.active_protocol) && *AtrLength < ifdnlnfc_state.target.atr_len) {
				*AtrLength = ifdnlnfc_state.target.atr_len;
				memcpy(Atr, &ifdnlnfc_state.target.atr, *AtrLength);
				return IFD_SUCCESS;
			}
			else {
				*AtrLength = 0;
				return IFD_ERROR_POWER_ACTION;
			}
		}
		//break;
		Log1(PCSC_LOG_DEBUG, "falling through");


	case IFD_POWER_UP:
		Log1(PCSC_LOG_DEBUG, "IFD_POWER_UP");
		err = connect_target(&ifdnlnfc_state.adapter, &ifdnlnfc_state.target);
		if (err || *AtrLength < ifdnlnfc_state.target.atr_len) {
			ifdnlnfc_state.card_present = 0;
			return IFD_ERROR_POWER_ACTION;
		}
		else {
			*AtrLength = ifdnlnfc_state.target.atr_len;
			memcpy(Atr, &ifdnlnfc_state.target.atr, *AtrLength);
			return IFD_SUCCESS;
		}
		break;

	case IFD_POWER_DOWN:
		Log1(PCSC_LOG_DEBUG, "IFD_POWER_DOWN");
		if (ifdnlnfc_state.socket)
			close(ifdnlnfc_state.socket);
		*AtrLength = 0;
		ifdnlnfc_state.socket = 0;
		ifdnlnfc_state.card_present = 0;
		return IFD_SUCCESS;
	default:
	        ;
	}
	return IFD_NOT_SUPPORTED;
}

RESPONSECODE
IFDHTransmitToICC(DWORD Lun, SCARD_IO_HEADER SendPci, PUCHAR TxBuffer, DWORD
		TxLength, PUCHAR RxBuffer, PDWORD RxLength, PSCARD_IO_HEADER RecvPci)
{

	int bytes_read;
	int bytes_written;

	unsigned char null_header;
	struct iovec iov[] = {{&null_header, 1}, {RxBuffer, *RxLength}};

	if (!ifdnlnfc_state.socket)
		return IFD_COMMUNICATION_ERROR;

	if (SendPci.Protocol != 1)
		return IFD_NOT_SUPPORTED;

	LogXxd(PCSC_LOG_DEBUG, "Writing to card: ", TxBuffer, TxLength);

	bytes_written = write(ifdnlnfc_state.socket, TxBuffer, TxLength);
	if (bytes_written != TxLength) {
		Log3(PCSC_LOG_DEBUG, "Wrote %d bytes instead of %ld", bytes_written, TxLength);
		*RxLength = 0;
		ifdnlnfc_state.card_present = 0;
		close(ifdnlnfc_state.socket);
		ifdnlnfc_state.socket = 0;
		return IFD_COMMUNICATION_ERROR;
	}

	bytes_read = readv(ifdnlnfc_state.socket, iov, 2);

	if (bytes_read == -1) {
		Log2(PCSC_LOG_DEBUG, "readv() error, errno: %d", errno);
	}

	if (bytes_read < 1)
	{
		*RxLength = 0;
		ifdnlnfc_state.card_present = 0;
		close(ifdnlnfc_state.socket);
		ifdnlnfc_state.socket = 0;
		return IFD_COMMUNICATION_ERROR;
	}

	bytes_read--;

	LogXxd(PCSC_LOG_DEBUG, "Reading from card: ", RxBuffer, bytes_read);
	*RxLength = bytes_read;
	RecvPci->Protocol = 1;

	return IFD_SUCCESS;
}

RESPONSECODE
IFDHICCPresence(DWORD Lun)
{
	int err;
	if (!ifdnlnfc_state.channel_open)
		return IFD_COMMUNICATION_ERROR;

	if (ifdnlnfc_state.card_present)
		return IFD_SUCCESS;
	else if (!ifdnlnfc_state.adapter.poll_active) {
		poll_for_targets(&ifdnlnfc_state.adapter);
	}

	err = nl_recvmsgs_default(event_sock);

	if (!err && ifdnlnfc_state.card_present)
	{
		if (!list_targets(&ifdnlnfc_state.adapter, &ifdnlnfc_state.target))
			return IFD_SUCCESS;
		else {
			ifdnlnfc_state.card_present = 0;
			return IFD_COMMUNICATION_ERROR;
		}
	}
	return IFD_ICC_NOT_PRESENT;
}

RESPONSECODE
IFDHControl(DWORD Lun, DWORD dwControlCode, PUCHAR TxBuffer, DWORD TxLength,
	PUCHAR RxBuffer, DWORD RxLength, LPDWORD pdwBytesReturned)
{
	return IFD_ERROR_NOT_SUPPORTED;
}
