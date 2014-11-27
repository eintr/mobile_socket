#ifndef PROTOCOL_H
#define PROTOCOL_H

#define	FRAME_FLAG_MASK_PRIO	0x38

#define	FRAME_FLAG_MASK_CRYPT	0x07
#define	FRAME_FLAG_CRYPT_NULL	0
#define	FRAME_FLAG_CRYPT_BLOWFISH	1

struct frame_st {
    uint16_t body_len;
    uint8_t version;
    uint8_t frame_flags;
    uint8_t frame_body[0];
};
#define	FRAME_CRYPT(X)	(((X)->frame_flags)&FRAME_FLAG_MASK_CRYPT)
#define	FRAME_PRIO(X)	((((X)->frame_flags)&FRAME_FLAG_MASK_PRIO)>>3)

struct frame_body_data_st {
	uint32_t msg_type:1;	/* Must == 0 */
	uint32_t flow_id:31;
	uint8_t data[0];
};

enum opcode_enum {
//	OP_TRUNKER_INIT		=0x01,
	OP_TRUNKER_CONFIG	=0x02,
	OP_TRUNKER_OK		=0x03,
	OP_TRUNKER_FAILURE	=0x04,

	OP_FRAMER_OPEN		=0x11,
	OP_FRAMER_FAILURE	=0x12,
	OP_FRAMER_CLOSE		=0x13,
};

#if 0
struct frame_body_ctl_truncer_init_st {	/* Client to server. For load balancer friendly,
											this frame should NEVER be encrypted! */
	uint32_t msg_type:1;	/* Must == 1 */
	uint32_t opcode:31;		/* Must == OP_TRUNKER_INIT */
	uint32_t client_cookie;		/* 0 means request a new one. */
	//uint8_t certificate_of_client[0];	/*  */
};
#endif

struct frame_body_ctl_truncer_config_st {	/* server to client */
	uint32_t msg_type:1;	/* Must == 1 */
	uint32_t opcode:31;		/* Must == OP_TRUNKER_CONFIG */
	uint8_t certificate_of_server[0];
};

struct frame_body_ctl_truncer_ok_st {	/* client to server */
	uint32_t msg_type:1;	/* Must == 1 */
	uint32_t opcode:31;		/* Must == OP_TRUNKER_OK */
	uint8_t encrypted_shared_key[0];
};

struct frame_body_ctl_truncer_failure_st {
	uint32_t msg_type:1;	/* Must == 1 */
	uint32_t opcode:31;		/* Must == OP_TRUNKER_FAILURE */
	uint8_t error_msg[0]
};

struct frame_body_ctl_framer_open_st {
	uint32_t msg_type:1;	/* Must == 1 */
	uint32_t opcode:31;		/* Must == OP_FRAMER_OPEN */
	uint32_t flow_id;
	uint8_t http_request[0]
};

struct frame_body_ctl_framer_failure_st {
	uint32_t msg_type:1;	/* Must == 1 */
	uint32_t opcode:31;		/* Must == OP_FRAMER_FAILURE */
	uint32_t flow_id;		/* */
	uint8_t error_msg[0]
};

struct frame_body_ctl_framer_close_st {
	uint32_t msg_type:1;	/* Must == 1 */
	uint32_t opcode:31;		/* Must == OP_FRAMER_CLOSE */
	uint32_t flow_id;
};


//struct frame_body_ctl_ack_st {
//	uint32_t msg_type:1;	/* Must == 1 */
//	uint32_t opcode:31;		/* Must == OP_ACK */
//	uint32_t ack_serial;	/* */
//};

#endif

