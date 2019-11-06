#ifndef __CONTROLLER_TEAM_H
#define __CONTROLLER_TEAM_H

struct team_port_info {
	struct nlmsghdr *nlh;
	char *topic;
	uint32_t port_ifindex;
	int changed;
	int linkup;
	int removed;
	uint32_t speed;
	uint8_t duplex;
};

struct team_option_info {
	struct nlmsghdr *nlh;
	char *topic;
	uint32_t port_ifindex;
	uint32_t changed;
	union {
		uint8_t u8;
		uint32_t u32;
		char *str;
		void *binary;
	} data;
	char name[16];
	uint32_t removed;
	uint32_t array_index;
	uint16_t payload_len;
	uint8_t type;
};

struct team_msg_desc {
	zlist_t *infolist;
	struct nlmsghdr orighdr;
	uint32_t ifindex;
	int cmd;
};

int process_genetlink_teamcmd(const struct nlmsghdr *nlh,
			      struct team_msg_desc *desc);

void team_msg_data_free(struct team_msg_desc *desc);

int team_query_portlist(struct mnl_socket *s, int family_id,
			unsigned long ifindex, unsigned int dumpseq);
int team_query_options(struct mnl_socket *s, int family_id,
		       unsigned long ifindex, unsigned int dump_seq);
#endif
