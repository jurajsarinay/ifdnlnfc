/*
 *
 *  libnlnfc - PCSC driver for Linux Kernel NFC devices
 *
 *  Copyright (C) 2024 Juraj Šarinay <juraj@sarinay.com>
 *
 *  uses code from neard & nfctool by Intel
 *  https://github.com/linux-nfc/neard
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
 */

#include "config.h"
#include <ifdhandler.h>
#include <inttypes.h>

static struct nl_sock *cmd_sock, *event_sock;
static int nfc_family_id;

struct nfc_adapter {
	uint32_t idx;
	int poll_active;
	uint8_t initial_power;
	uint8_t initial_mode;
	uint32_t protocols;
};

struct nfc_target {
	uint32_t idx;
	uint32_t supported_protocols;
	uint32_t active_protocol;
	uint8_t  atr[MAX_ATR_SIZE];
	int atr_len;
};

struct ifdnlnfc_state {
	struct nfc_adapter adapter;
	struct nfc_target target;
	int channel_open;
	int card_present;
	int socket;
};

struct list_adapters_cb_state {
	const char * name;
	int found;
	struct nfc_adapter * adapter;
};

struct get_adapter_cb_state {
	int found;
	uint32_t idx;
	struct nfc_adapter * adapter;
};

struct list_targets_cb_state {
	int found;
	struct nfc_target *target;
};
