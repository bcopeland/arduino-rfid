/*
 * RFID/NFC Arduino sketch for Sparkfun evaluation board
 * Based on sample code, heavily rewritten.
 *
 * (C) 2015 Bob Copeland
 */
#include <SoftwareSerial.h>

typedef unsigned char u8;

SoftwareSerial rfid(2, 8);

static void hexdump(u8 *buf, size_t len)
{
	char tmp[4] = {};

	unsigned int i;
	for (i=0; i < len; i++) {
		sprintf(tmp, "%02x ", buf[i]);
		Serial.print(tmp);
	}
	Serial.print("\r\n");
}

//#define DEBUG
#ifdef DEBUG
static void dump_response(u8 *buf, size_t len)
{
	hexdump(buf, len);
}
#else
static void dump_response(u8 *buf, size_t len)
{
}
#endif

void send_cmd(u8 *cmd, size_t len)
{
	unsigned int i;
	u8 csum = 0;
	/* compute checksum */
	for (i=1; i < len-1; i++) {
		csum += cmd[i];
	}
	cmd[len-1] = csum;

	for (i=0; i < len; i++) {
		rfid.write(cmd[i]);
	}
}

#define NUM_KEYS 9
void authenticate(u8 sector, int keyidx)
{
	u8 some_keys[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7,
		0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
		0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5,
		0x4d, 0x3a, 0x99, 0xc3, 0x51, 0xdd,
		0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xab, 0xcd, 0xef, 0x12, 0x34, 0x56,
	};

	if (keyidx >= NUM_KEYS)
		return;

	u8 auth_cmd[] = {
		0xff, 0x00, 0x09, 0x85, 0x00, 0xaa,
		/* key: well known NDEF key */
		0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
		0x00
	};
	auth_cmd[4] = sector;
	memcpy(&auth_cmd[6], &some_keys[keyidx * 6], 6);
	send_cmd(auth_cmd, sizeof(auth_cmd));
}

void read_block(u8 block)
{
	u8 read_cmd[] = {
		0xff, 0x00, 0x02, 0x86, 0x00, 0x00
	};
	read_cmd[4] = block;
	send_cmd(read_cmd, sizeof(read_cmd));
}

void seek()
{
	u8 seek_cmd[] = {
		0xff, 0x00, 0x01, 0x82, 0x83
	};
	send_cmd(seek_cmd, sizeof(seek_cmd));
}

void halt()
{
	u8 halt_cmd[] = {
		0xff, 0x00, 0x01, 0x93, 0x94
	};
	send_cmd(halt_cmd, sizeof(halt_cmd));
}

size_t read_packet(u8 *buf, size_t len)
{
	unsigned int i;
	u8 header = rfid.read();

	/* start of frame */
	if (header != 0xff)
		return 0;

	rfid.read(); /* reserved */

	u8 plen = rfid.read();
	u8 csum = 0;
	u8 check;

	csum += plen;
	for (i=0; i < plen && i < len; i++) {
		*buf = rfid.read();
		csum += *buf;
		buf++;
	}
	check = rfid.read();

	dump_response(buf, i);

	if (csum != check)
		return 0;

	return i;
}

void print_serial_num(u8 *buf, int len)
{
	switch(buf[0]) {
	case 1:
		Serial.print("Mifare UL: ");
		break;
	case 2:
		Serial.print("Mifare 1k: ");
		break;
	case 3:
		Serial.print("Mifare 4k: ");
		break;
	default:
		Serial.print("Tag Type ");
		hexdump(buf, 1);
		Serial.print(": ");
	}

	hexdump(&buf[1], len-1);
}

bool handle_response()
{
	size_t len;
	u8 buf[128];

	while (rfid.available()) {
		len = read_packet(buf, sizeof(buf));
		if (len < 1)
			break;
		switch(buf[0]) {
		case 0x82:
			if (len == 6 || len == 9) {
				print_serial_num(&buf[1], len-1);
				return true;
			}
			break;
		case 0x85:
			/* auth response */
			if (len != 2)
				break;
			if (buf[1] == 0x4c)
				return true;
			Serial.print("Auth failed: ");
			hexdump(&buf[1], 1);
			break;
		case 0x86:
			/* read response */
			if (len == 2) {
				Serial.print("Read failed: ");
				hexdump(&buf[1], 1);
				return false;
			}
			hexdump(&buf[1], len-1);
			return true;
		case 0x93:
			/* halt, ignore */
		default:
			break;
		}
	}
	return false;
}

void dump_device()
{
	int i;
	bool ok;

	for (i=0; i < 64; i++) {
		authenticate(i, 0);
		delay(10);
		ok = handle_response();
		if (!ok)
			return;

		read_block(i);
		delay(10);
		ok = handle_response();
		if (!ok)
			return;
	}
}

void setup()
{
	Serial.begin(9600);
	Serial.println("listening...");

	rfid.begin(19200);
	delay(10);
	halt();
}

void loop()
{
	seek();
	delay(20);
	if (!handle_response())
		goto next;

	dump_device();
next:
	delay(100);
}
