#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

#define SHAREDKEY_BYTESIZE  16

struct frame_st { 
	uint16_t body_len; 
	uint8_t frame_flags; 
	uint8_t frame_body[0]; 
} __attribute__((packed)); 
#define	FRAME_FLAG_MASK_VERSION		0xE0
#define	FRAME_FLAG_VERSION1			1
#define FRAME_VERSION(X)  ((((X)->frame_flags)&FRAME_FLAG_MASK_VERSION)>>5)

#define	FRAME_FLAG_MASK_CRYPT		0x18
#define	FRAME_FLAG_NOCRYPT			0
#define	FRAME_FLAG_CRYPT_BLOWFISH	1
#define	FRAME_CRYPT(X)	((((X)->frame_flags)&FRAME_FLAG_MASK_CRYPT)>>3)

#define FRAME_FLAG_MASK_ZIP			0x04
#define FRAME_FLAG_NOZIP			0
#define FRAME_FLAG_ZIP				1
#define FRAME_ZIP(X)  ((((X)->frame_flags)&FRAME_FLAG_MASK_ZIP)>>2)

struct frame_body_data_st { 
	uint16_t msg_type:1;	/* Must == 0 */ 
	uint16_t pileline_id:15; 
	uint8_t data[0]; 
} __attribute__((packed)); 

enum ctl_code_enum {
	CTL_SOCKET_CERT_REQ	=0x01,
	CTL_SOCKET_CERT		=0x02,
	CTL_SOCKET_KEY_SYNC	=0x03,
	CTL_SOCKET_KEY_OK	=0x04,
	CTL_SOCKET_KEY_REJ	=0x05,

	CTL_PIPELINE_OPEN	=0x11,
	CTL_PIPELINE_FAILURE	=0x12,
	CTL_PIPELINE_CLOSE	=0x13,
};

struct frame_body_ctl_socket_cert_req_st {	/* client to server */
	uint16_t msg_type:1;	/* Must == 1 */
	uint16_t opcode:15;		/* Must == OP_SOCKET_CERT_REQ */
} __attribute__((packed));

struct frame_body_ctl_socket_cert_st {	/* server to client */
	uint16_t msg_type:1;	/* Must == 1 */
	uint16_t opcode:15;		/* Must == OP_SOCKET_CERT */
	uint8_t x509_certificate[0];
} __attribute__((packed));

struct frame_body_ctl_socket_key_sync_st {		/* client to server */
	uint16_t msg_type:1;	/* Must == 1 */
	uint16_t opcode:15;		/* Must == OP_SOCKET_KEY_SYNC */
	uint32_t crc32;			/* crc32 of shared_key */
	uint8_t encrypted_shared_key[0];
} __attribute__((packed));

struct frame_body_ctl_socket_key_rej_st {		/* server to client */
	uint16_t msg_type:1;	/* Must == 1 */
	uint16_t opcode:15;		/* Must == OP_SOCKET_KEY_REJ */
} __attribute__((packed));

struct frame_body_ctl_pipeline_open_st {
	uint16_t msg_type:1;	/* Must == 1 */
	uint16_t opcode:15;		/* Must == OP_PIPELINE_OPEN */
	uint16_t pipeline_id; 
	uint16_t max_delay_in_ms;
	uint8_t	reply_frame_flags;
	uint8_t data[0] ;
} __attribute__((packed)); 

struct frame_body_ctl_pipeline_failure_st { 
	uint16_t msg_type:1;	/* Must == 1 */
	uint16_t opcode:15;		/* Must == OP_PIPELINE_FAILURE */
	uint16_t pipeline_id;
	uint8_t error_msg[0];
} __attribute__((packed));

struct frame_body_ctl_pipeline_close_st { 
	uint16_t msg_type:1;	/* Must == 1 */
	uint16_t opcode:15;		/* Must == OP_PIPELINE_CLOSE */
	uint16_t pipeline_id;
} __attribute__((packed));

#endif

