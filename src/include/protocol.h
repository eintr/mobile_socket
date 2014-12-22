#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

typedef uint32_t flowid_t;

struct frame_st { 
	uint16_t body_len; 
	uint8_t version;
	uint8_t frame_flags; 
	uint8_t frame_body[0]; 
} __attribute__((packed)); 
#define	FRAME_FLAG_MASK_CRYPT		0x07
#define	FRAME_FLAG_NOCRYPT			0
#define	FRAME_FLAG_CRYPT_PRND		1
#define	FRAME_FLAG_CRYPT_BLOWFISH	2
#define	FRAME_CRYPT(X)	(((X)->frame_flags)&FRAME_FLAG_MASK_CRYPT)

struct frame_body_data_st { 
	uint32_t msg_type:1;	/* Must == 0 */ 
	uint32_t flow_id:31; 
	uint8_t data[0]; 
} __attribute__((packed)); 

enum opcode_enum {
	OP_TRUNK_CONFIG		=0x02,
	OP_TRUNK_OK			=0x03,
	OP_TRUNK_FAILURE	=0x04,

	OP_FLOW_OPEN	=0x11,
	OP_FLOW_FAILURE	=0x12,
	OP_FLOW_CLOSE	=0x13,
};

struct frame_body_ctl_trunk_config_st {	/* server to client */
	uint32_t msg_type:1;	/* Must == 1 */
	uint32_t opcode:31;		/* Must == OP_TRUNK_CONFIG */
	uint8_t x509_certificate[0];
} __attribute__((packed));

struct frame_body_ctl_trunk_ok_st {		/* client to server */
	uint32_t msg_type:1;	/* Must == 1 */
	uint32_t opcode:31;		/* Must == OP_TRUNK_OK */
	uint8_t encrypted_shared_key[0];
} __attribute__((packed));

struct frame_body_ctl_trunk_failure_st {
	uint32_t msg_type:1;	/* Must == 1 */
	uint32_t opcode:31;		/* Must == OP_TRUNK_FAILURE */
	uint8_t error_msg[0];
} __attribute__((packed));

struct frame_body_ctl_flow_open_st {
	uint32_t msg_type:1;	/* Must == 1 */
	uint32_t opcode:31;		/* Must == OP_FLOW_OPEN */
	uint32_t flow_id; 
	uint16_t max_delay_in_ms;
	uint8_t request_url[0] ;
} __attribute__((packed)); 

struct frame_body_ctl_flow_failure_st { 
	uint32_t msg_type:1;	/* Must == 1 */
	uint32_t opcode:31;		/* Must == OP_FLOW_FAILURE */
	uint32_t flow_id;
	uint8_t error_msg[0];
} __attribute__((packed));

struct frame_body_ctl_flow_close_st { 
	uint32_t msg_type:1;	/* Must == 1 */
	uint32_t opcode:31;		/* Must == OP__CLOSE */
	uint32_t flow_id;
} __attribute__((packed));

#endif

