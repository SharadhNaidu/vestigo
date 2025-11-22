;--------------------------------------------------------
; File Created by SDCC : free open source ANSI-C Compiler
; Version 4.0.0 #11528 (Linux)
;--------------------------------------------------------
	.module aes_192
	.optsdcc -mz80
	
;--------------------------------------------------------
; Public variables in this module
;--------------------------------------------------------
	.globl _main
	.globl _AES192_Encrypt
	.globl _KeyExpansion
	.globl _ShiftRows
	.globl _SubBytes
	.globl _AddRoundKey
	.globl _puts
	.globl _printf
	.globl _putchar
;--------------------------------------------------------
; special function registers
;--------------------------------------------------------
;--------------------------------------------------------
; ram data
;--------------------------------------------------------
	.area _DATA
;--------------------------------------------------------
; ram data
;--------------------------------------------------------
	.area _INITIALIZED
;--------------------------------------------------------
; absolute external ram data
;--------------------------------------------------------
	.area _DABS (ABS)
;--------------------------------------------------------
; global & static initialisations
;--------------------------------------------------------
	.area _HOME
	.area _GSINIT
	.area _GSFINAL
	.area _GSINIT
;--------------------------------------------------------
; Home
;--------------------------------------------------------
	.area _HOME
	.area _HOME
;--------------------------------------------------------
; code
;--------------------------------------------------------
	.area _CODE
;aes_192.c:6: int putchar(int c) {
;	---------------------------------
; Function putchar
; ---------------------------------
_putchar::
;aes_192.c:7: return c;
	pop	bc
	pop	hl
	push	hl
	push	bc
;aes_192.c:8: }
	ret
;aes_192.c:35: void AddRoundKey(uint8_t round, uint8_t* state, const uint8_t* RoundKey) {
;	---------------------------------
; Function AddRoundKey
; ---------------------------------
_AddRoundKey::
	push	ix
	ld	ix,#0
	add	ix,sp
	push	af
	dec	sp
;aes_192.c:36: for (int i = 0; i < 16; ++i) state[i] ^= RoundKey[(round * 16) + i];
	ld	bc, #0x0000
00103$:
	ld	a, c
	sub	a, #0x10
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00105$
	ld	a, 5 (ix)
	add	a, c
	ld	e, a
	ld	a, 6 (ix)
	adc	a, b
	ld	d, a
	ld	a, (de)
	ld	-3 (ix), a
	ld	l, 4 (ix)
	ld	h, #0x00
	add	hl, hl
	add	hl, hl
	add	hl, hl
	add	hl, hl
	add	hl, bc
	ld	-2 (ix), l
	ld	-1 (ix), h
	ld	a, -2 (ix)
	add	a, 7 (ix)
	ld	l, a
	ld	a, -1 (ix)
	adc	a, 8 (ix)
	ld	h, a
	ld	a, (hl)
	xor	a, -3 (ix)
	ld	(de), a
	inc	bc
	jr	00103$
00105$:
;aes_192.c:37: }
	ld	sp, ix
	pop	ix
	ret
_sbox:
	.db #0x63	; 99	'c'
	.db #0x7c	; 124
	.db #0x77	; 119	'w'
	.db #0x7b	; 123
	.db #0xf2	; 242
	.db #0x6b	; 107	'k'
	.db #0x6f	; 111	'o'
	.db #0xc5	; 197
	.db #0x30	; 48	'0'
	.db #0x01	; 1
	.db #0x67	; 103	'g'
	.db #0x2b	; 43
	.db #0xfe	; 254
	.db #0xd7	; 215
	.db #0xab	; 171
	.db #0x76	; 118	'v'
	.db #0xca	; 202
	.db #0x82	; 130
	.db #0xc9	; 201
	.db #0x7d	; 125
	.db #0xfa	; 250
	.db #0x59	; 89	'Y'
	.db #0x47	; 71	'G'
	.db #0xf0	; 240
	.db #0xad	; 173
	.db #0xd4	; 212
	.db #0xa2	; 162
	.db #0xaf	; 175
	.db #0x9c	; 156
	.db #0xa4	; 164
	.db #0x72	; 114	'r'
	.db #0xc0	; 192
	.db #0xb7	; 183
	.db #0xfd	; 253
	.db #0x93	; 147
	.db #0x26	; 38
	.db #0x36	; 54	'6'
	.db #0x3f	; 63
	.db #0xf7	; 247
	.db #0xcc	; 204
	.db #0x34	; 52	'4'
	.db #0xa5	; 165
	.db #0xe5	; 229
	.db #0xf1	; 241
	.db #0x71	; 113	'q'
	.db #0xd8	; 216
	.db #0x31	; 49	'1'
	.db #0x15	; 21
	.db #0x04	; 4
	.db #0xc7	; 199
	.db #0x23	; 35
	.db #0xc3	; 195
	.db #0x18	; 24
	.db #0x96	; 150
	.db #0x05	; 5
	.db #0x9a	; 154
	.db #0x07	; 7
	.db #0x12	; 18
	.db #0x80	; 128
	.db #0xe2	; 226
	.db #0xeb	; 235
	.db #0x27	; 39
	.db #0xb2	; 178
	.db #0x75	; 117	'u'
	.db #0x09	; 9
	.db #0x83	; 131
	.db #0x2c	; 44
	.db #0x1a	; 26
	.db #0x1b	; 27
	.db #0x6e	; 110	'n'
	.db #0x5a	; 90	'Z'
	.db #0xa0	; 160
	.db #0x52	; 82	'R'
	.db #0x3b	; 59
	.db #0xd6	; 214
	.db #0xb3	; 179
	.db #0x29	; 41
	.db #0xe3	; 227
	.db #0x2f	; 47
	.db #0x84	; 132
	.db #0x53	; 83	'S'
	.db #0xd1	; 209
	.db #0x00	; 0
	.db #0xed	; 237
	.db #0x20	; 32
	.db #0xfc	; 252
	.db #0xb1	; 177
	.db #0x5b	; 91
	.db #0x6a	; 106	'j'
	.db #0xcb	; 203
	.db #0xbe	; 190
	.db #0x39	; 57	'9'
	.db #0x4a	; 74	'J'
	.db #0x4c	; 76	'L'
	.db #0x58	; 88	'X'
	.db #0xcf	; 207
	.db #0xd0	; 208
	.db #0xef	; 239
	.db #0xaa	; 170
	.db #0xfb	; 251
	.db #0x43	; 67	'C'
	.db #0x4d	; 77	'M'
	.db #0x33	; 51	'3'
	.db #0x85	; 133
	.db #0x45	; 69	'E'
	.db #0xf9	; 249
	.db #0x02	; 2
	.db #0x7f	; 127
	.db #0x50	; 80	'P'
	.db #0x3c	; 60
	.db #0x9f	; 159
	.db #0xa8	; 168
	.db #0x51	; 81	'Q'
	.db #0xa3	; 163
	.db #0x40	; 64
	.db #0x8f	; 143
	.db #0x92	; 146
	.db #0x9d	; 157
	.db #0x38	; 56	'8'
	.db #0xf5	; 245
	.db #0xbc	; 188
	.db #0xb6	; 182
	.db #0xda	; 218
	.db #0x21	; 33
	.db #0x10	; 16
	.db #0xff	; 255
	.db #0xf3	; 243
	.db #0xd2	; 210
	.db #0xcd	; 205
	.db #0x0c	; 12
	.db #0x13	; 19
	.db #0xec	; 236
	.db #0x5f	; 95
	.db #0x97	; 151
	.db #0x44	; 68	'D'
	.db #0x17	; 23
	.db #0xc4	; 196
	.db #0xa7	; 167
	.db #0x7e	; 126
	.db #0x3d	; 61
	.db #0x64	; 100	'd'
	.db #0x5d	; 93
	.db #0x19	; 25
	.db #0x73	; 115	's'
	.db #0x60	; 96
	.db #0x81	; 129
	.db #0x4f	; 79	'O'
	.db #0xdc	; 220
	.db #0x22	; 34
	.db #0x2a	; 42
	.db #0x90	; 144
	.db #0x88	; 136
	.db #0x46	; 70	'F'
	.db #0xee	; 238
	.db #0xb8	; 184
	.db #0x14	; 20
	.db #0xde	; 222
	.db #0x5e	; 94
	.db #0x0b	; 11
	.db #0xdb	; 219
	.db #0xe0	; 224
	.db #0x32	; 50	'2'
	.db #0x3a	; 58
	.db #0x0a	; 10
	.db #0x49	; 73	'I'
	.db #0x06	; 6
	.db #0x24	; 36
	.db #0x5c	; 92
	.db #0xc2	; 194
	.db #0xd3	; 211
	.db #0xac	; 172
	.db #0x62	; 98	'b'
	.db #0x91	; 145
	.db #0x95	; 149
	.db #0xe4	; 228
	.db #0x79	; 121	'y'
	.db #0xe7	; 231
	.db #0xc8	; 200
	.db #0x37	; 55	'7'
	.db #0x6d	; 109	'm'
	.db #0x8d	; 141
	.db #0xd5	; 213
	.db #0x4e	; 78	'N'
	.db #0xa9	; 169
	.db #0x6c	; 108	'l'
	.db #0x56	; 86	'V'
	.db #0xf4	; 244
	.db #0xea	; 234
	.db #0x65	; 101	'e'
	.db #0x7a	; 122	'z'
	.db #0xae	; 174
	.db #0x08	; 8
	.db #0xba	; 186
	.db #0x78	; 120	'x'
	.db #0x25	; 37
	.db #0x2e	; 46
	.db #0x1c	; 28
	.db #0xa6	; 166
	.db #0xb4	; 180
	.db #0xc6	; 198
	.db #0xe8	; 232
	.db #0xdd	; 221
	.db #0x74	; 116	't'
	.db #0x1f	; 31
	.db #0x4b	; 75	'K'
	.db #0xbd	; 189
	.db #0x8b	; 139
	.db #0x8a	; 138
	.db #0x70	; 112	'p'
	.db #0x3e	; 62
	.db #0xb5	; 181
	.db #0x66	; 102	'f'
	.db #0x48	; 72	'H'
	.db #0x03	; 3
	.db #0xf6	; 246
	.db #0x0e	; 14
	.db #0x61	; 97	'a'
	.db #0x35	; 53	'5'
	.db #0x57	; 87	'W'
	.db #0xb9	; 185
	.db #0x86	; 134
	.db #0xc1	; 193
	.db #0x1d	; 29
	.db #0x9e	; 158
	.db #0xe1	; 225
	.db #0xf8	; 248
	.db #0x98	; 152
	.db #0x11	; 17
	.db #0x69	; 105	'i'
	.db #0xd9	; 217
	.db #0x8e	; 142
	.db #0x94	; 148
	.db #0x9b	; 155
	.db #0x1e	; 30
	.db #0x87	; 135
	.db #0xe9	; 233
	.db #0xce	; 206
	.db #0x55	; 85	'U'
	.db #0x28	; 40
	.db #0xdf	; 223
	.db #0x8c	; 140
	.db #0xa1	; 161
	.db #0x89	; 137
	.db #0x0d	; 13
	.db #0xbf	; 191
	.db #0xe6	; 230
	.db #0x42	; 66	'B'
	.db #0x68	; 104	'h'
	.db #0x41	; 65	'A'
	.db #0x99	; 153
	.db #0x2d	; 45
	.db #0x0f	; 15
	.db #0xb0	; 176
	.db #0x54	; 84	'T'
	.db #0xbb	; 187
	.db #0x16	; 22
_Rcon:
	.db #0x8d	; 141
	.db #0x01	; 1
	.db #0x02	; 2
	.db #0x04	; 4
	.db #0x08	; 8
	.db #0x10	; 16
	.db #0x20	; 32
	.db #0x40	; 64
	.db #0x80	; 128
	.db #0x1b	; 27
	.db #0x36	; 54	'6'
;aes_192.c:39: void SubBytes(uint8_t* state) {
;	---------------------------------
; Function SubBytes
; ---------------------------------
_SubBytes::
	push	ix
	ld	ix,#0
	add	ix,sp
;aes_192.c:40: for (int i = 0; i < 16; ++i) state[i] = sbox[state[i]];
	ld	bc, #0x0000
00103$:
	ld	a, c
	sub	a, #0x10
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00105$
	ld	a, 4 (ix)
	add	a, c
	ld	e, a
	ld	a, 5 (ix)
	adc	a, b
	ld	d, a
	ld	a, (de)
	add	a, #<(_sbox)
	ld	l, a
	ld	a, #0x00
	adc	a, #>(_sbox)
	ld	h, a
	ld	a, (hl)
	ld	(de), a
	inc	bc
	jr	00103$
00105$:
;aes_192.c:41: }
	pop	ix
	ret
;aes_192.c:43: void ShiftRows(uint8_t* state) {
;	---------------------------------
; Function ShiftRows
; ---------------------------------
_ShiftRows::
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-18
	add	hl, sp
	ld	sp, hl
;aes_192.c:45: temp[0] = state[0];  temp[1] = state[5];  temp[2] = state[10]; temp[3] = state[15];
	ld	hl, #0
	add	hl, sp
	ld	c, l
	ld	b, h
	ld	a, 4 (ix)
	ld	-2 (ix), a
	ld	a, 5 (ix)
	ld	-1 (ix), a
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	a, (hl)
	ld	(bc), a
	ld	e, c
	ld	d, b
	inc	de
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	inc	hl
	inc	hl
	inc	hl
	inc	hl
	inc	hl
	ld	a, (hl)
	ld	(de), a
	ld	e, c
	ld	d, b
	inc	de
	inc	de
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	push	bc
	ld	bc, #0x000a
	add	hl, bc
	pop	bc
	ld	a, (hl)
	ld	(de), a
	ld	e, c
	ld	d, b
	inc	de
	inc	de
	inc	de
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	push	bc
	ld	bc, #0x000f
	add	hl, bc
	pop	bc
	ld	a, (hl)
	ld	(de), a
;aes_192.c:46: temp[4] = state[4];  temp[5] = state[9];  temp[6] = state[14]; temp[7] = state[3];
	ld	hl, #0x0004
	add	hl, bc
	ex	de, hl
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	inc	hl
	inc	hl
	inc	hl
	inc	hl
	ld	a, (hl)
	ld	(de), a
	ld	hl, #0x0005
	add	hl, bc
	ex	de, hl
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	push	bc
	ld	bc, #0x0009
	add	hl, bc
	pop	bc
	ld	a, (hl)
	ld	(de), a
	ld	hl, #0x0006
	add	hl, bc
	ex	de, hl
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	push	bc
	ld	bc, #0x000e
	add	hl, bc
	pop	bc
	ld	a, (hl)
	ld	(de), a
	ld	hl, #0x0007
	add	hl, bc
	ex	de, hl
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	inc	hl
	inc	hl
	inc	hl
	ld	a, (hl)
	ld	(de), a
;aes_192.c:47: temp[8] = state[8];  temp[9] = state[13]; temp[10] = state[2]; temp[11] = state[7];
	ld	hl, #0x0008
	add	hl, bc
	ex	de, hl
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	push	bc
	ld	bc, #0x0008
	add	hl, bc
	pop	bc
	ld	a, (hl)
	ld	(de), a
	ld	hl, #0x0009
	add	hl, bc
	ex	de, hl
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	push	bc
	ld	bc, #0x000d
	add	hl, bc
	pop	bc
	ld	a, (hl)
	ld	(de), a
	ld	hl, #0x000a
	add	hl, bc
	ex	de, hl
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	inc	hl
	inc	hl
	ld	a, (hl)
	ld	(de), a
	ld	hl, #0x000b
	add	hl, bc
	ex	de, hl
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	push	bc
	ld	bc, #0x0007
	add	hl, bc
	pop	bc
	ld	a, (hl)
	ld	(de), a
;aes_192.c:48: temp[12] = state[12]; temp[13] = state[1]; temp[14] = state[6]; temp[15] = state[11];
	ld	hl, #0x000c
	add	hl, bc
	ex	de, hl
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	push	bc
	ld	bc, #0x000c
	add	hl, bc
	pop	bc
	ld	a, (hl)
	ld	(de), a
	ld	hl, #0x000d
	add	hl, bc
	ex	de, hl
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	inc	hl
	ld	a, (hl)
	ld	(de), a
	ld	hl, #0x000e
	add	hl, bc
	ex	de, hl
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	push	bc
	ld	bc, #0x0006
	add	hl, bc
	pop	bc
	ld	a, (hl)
	ld	(de), a
	ld	hl, #0x000f
	add	hl, bc
	ex	de, hl
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	push	bc
	ld	bc, #0x000b
	add	hl, bc
	pop	bc
	ld	a, (hl)
	ld	(de), a
;aes_192.c:49: memcpy(state, temp, 16);
	ld	e, 4 (ix)
	ld	d, 5 (ix)
	ld	l, c
	ld	h, b
	ld	bc, #0x0010
	ldir
;aes_192.c:50: }
	ld	sp, ix
	pop	ix
	ret
;aes_192.c:55: void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key) {
;	---------------------------------
; Function KeyExpansion
; ---------------------------------
_KeyExpansion::
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-16
	add	hl, sp
	ld	sp, hl
;aes_192.c:62: for (i = 0; i < nk * 4; ++i) RoundKey[i] = Key[i];
	ld	bc, #0x0000
00106$:
	ld	a, c
	sub	a, #0x18
	ld	a, b
	sbc	a, #0x00
	jr	NC,00101$
	ld	a, 4 (ix)
	add	a, c
	ld	e, a
	ld	a, 5 (ix)
	adc	a, b
	ld	d, a
	ld	l, 6 (ix)
	ld	h, 7 (ix)
	add	hl, bc
	ld	a, (hl)
	ld	(de), a
	inc	bc
	jr	00106$
00101$:
;aes_192.c:64: for (i = nk; i < 4 * (nr + 1); ++i) {
	ld	bc, #0x0006
00109$:
	ld	a, c
	sub	a, #0x34
	ld	a, b
	sbc	a, #0x00
	jp	NC, 00111$
;aes_192.c:65: k = (i - 1) * 4;
	ld	l, c
	ld	h, b
	dec	hl
	add	hl, hl
	add	hl, hl
	ld	-4 (ix), l
	ld	-3 (ix), h
;aes_192.c:66: tempa[0]=RoundKey[k + 0]; tempa[1]=RoundKey[k + 1];
	ld	hl, #0
	add	hl, sp
	ld	-2 (ix), l
	ld	-1 (ix), h
	ld	a, 4 (ix)
	add	a, -4 (ix)
	ld	e, a
	ld	a, 5 (ix)
	adc	a, -3 (ix)
	ld	d, a
	ld	a, (de)
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	(hl), a
	ld	a, -2 (ix)
	add	a, #0x01
	ld	-12 (ix), a
	ld	a, -1 (ix)
	adc	a, #0x00
	ld	-11 (ix), a
	ld	e, -4 (ix)
	ld	d, -3 (ix)
	inc	de
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	add	hl, de
	ld	a, (hl)
	ld	l, -12 (ix)
	ld	h, -11 (ix)
	ld	(hl), a
;aes_192.c:67: tempa[2]=RoundKey[k + 2]; tempa[3]=RoundKey[k + 3];
	ld	a, -2 (ix)
	add	a, #0x02
	ld	-10 (ix), a
	ld	a, -1 (ix)
	adc	a, #0x00
	ld	-9 (ix), a
	ld	e, -4 (ix)
	ld	d, -3 (ix)
	inc	de
	inc	de
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	add	hl, de
	ld	a, (hl)
	ld	l, -10 (ix)
	ld	h, -9 (ix)
	ld	(hl), a
	ld	a, -2 (ix)
	add	a, #0x03
	ld	-8 (ix), a
	ld	a, -1 (ix)
	adc	a, #0x00
	ld	-7 (ix), a
	ld	e, -4 (ix)
	ld	d, -3 (ix)
	inc	de
	inc	de
	inc	de
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	add	hl, de
	ld	a, (hl)
	ld	l, -8 (ix)
	ld	h, -7 (ix)
	ld	(hl), a
;aes_192.c:69: if (i % nk == 0) {
	push	bc
	ld	hl, #0x0006
	push	hl
	push	bc
	call	__moduint
	pop	af
	pop	af
	pop	bc
	ld	a, h
	or	a, l
	jp	NZ, 00103$
;aes_192.c:70: k = tempa[0];
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	a, (hl)
	ld	-6 (ix), a
	xor	a, a
	ld	-5 (ix), a
;aes_192.c:71: tempa[0] = tempa[1]; tempa[1] = tempa[2]; tempa[2] = tempa[3]; tempa[3] = k;
	ld	l, -12 (ix)
	ld	h, -11 (ix)
	ld	a, (hl)
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	(hl), a
	ld	l, -10 (ix)
	ld	h, -9 (ix)
	push	af
	ld	a, (hl)
	ld	-4 (ix), a
	pop	af
	ld	l, -12 (ix)
	ld	h, -11 (ix)
	push	af
	ld	a, -4 (ix)
	ld	(hl), a
	pop	af
	ld	l, -8 (ix)
	ld	h, -7 (ix)
	ld	d, (hl)
	ld	l, -10 (ix)
	ld	h, -9 (ix)
	ld	(hl), d
	ld	e, -6 (ix)
	ld	l, -8 (ix)
	ld	h, -7 (ix)
	ld	(hl), e
;aes_192.c:72: tempa[0] = sbox[tempa[0]]; tempa[1] = sbox[tempa[1]];
	add	a, #<(_sbox)
	ld	l, a
	ld	a, #0x00
	adc	a, #>(_sbox)
	ld	h, a
	ld	a, (hl)
	ld	-3 (ix), a
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	a, -3 (ix)
	ld	(hl), a
	ld	a, -4 (ix)
	add	a, #<(_sbox)
	ld	l, a
	ld	a, #0x00
	adc	a, #>(_sbox)
	ld	h, a
	ld	a, (hl)
	ld	l, -12 (ix)
	ld	h, -11 (ix)
	ld	(hl), a
;aes_192.c:73: tempa[2] = sbox[tempa[2]]; tempa[3] = sbox[tempa[3]];
	ld	a, d
	add	a, #<(_sbox)
	ld	l, a
	ld	a, #0x00
	adc	a, #>(_sbox)
	ld	h, a
	ld	a, (hl)
	ld	l, -10 (ix)
	ld	h, -9 (ix)
	ld	(hl), a
	ld	hl, #_sbox
	ld	d, #0x00
	add	hl, de
	ld	a, (hl)
	ld	l, -8 (ix)
	ld	h, -7 (ix)
	ld	(hl), a
;aes_192.c:74: tempa[0] = tempa[0] ^ Rcon[i/nk];
	push	bc
	ld	hl, #0x0006
	push	hl
	push	bc
	call	__divuint
	pop	af
	pop	af
	pop	bc
	ld	de, #_Rcon
	add	hl, de
	ld	a, (hl)
	xor	a, -3 (ix)
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	(hl), a
00103$:
;aes_192.c:77: j = i * 4; k = (i - nk) * 4;
	ld	-6 (ix), c
	ld	-5 (ix), b
	ld	a, #0x02+1
	jr	00141$
00140$:
	sla	-6 (ix)
	rl	-5 (ix)
00141$:
	dec	a
	jr	NZ,00140$
	ld	a, c
	add	a, #0xfa
	ld	l, a
	ld	a, b
	adc	a, #0xff
	ld	h, a
	add	hl, hl
	add	hl, hl
	ld	-4 (ix), l
	ld	-3 (ix), h
;aes_192.c:78: RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
	ld	a, 4 (ix)
	add	a, -6 (ix)
	ld	e, a
	ld	a, 5 (ix)
	adc	a, -5 (ix)
	ld	d, a
	ld	a, 4 (ix)
	add	a, -4 (ix)
	ld	l, a
	ld	a, 5 (ix)
	adc	a, -3 (ix)
	ld	h, a
	ld	a, (hl)
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	l, (hl)
	xor	a, l
	ld	(de), a
;aes_192.c:79: RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
	ld	e, -6 (ix)
	ld	d, -5 (ix)
	inc	de
	ld	a, e
	add	a, 4 (ix)
	ld	-2 (ix), a
	ld	a, d
	adc	a, 5 (ix)
	ld	-1 (ix), a
	ld	e, -4 (ix)
	ld	d, -3 (ix)
	inc	de
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	add	hl, de
	ld	a, (hl)
	ld	l, -12 (ix)
	ld	h, -11 (ix)
	ld	e, (hl)
	xor	a, e
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	(hl), a
;aes_192.c:80: RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
	ld	e, -6 (ix)
	ld	d, -5 (ix)
	inc	de
	inc	de
	ld	a, e
	add	a, 4 (ix)
	ld	-2 (ix), a
	ld	a, d
	adc	a, 5 (ix)
	ld	-1 (ix), a
	ld	e, -4 (ix)
	ld	d, -3 (ix)
	inc	de
	inc	de
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	add	hl, de
	ld	a, (hl)
	ld	l, -10 (ix)
	ld	h, -9 (ix)
	ld	e, (hl)
	xor	a, e
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	(hl), a
;aes_192.c:81: RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
	ld	e, -6 (ix)
	ld	d, -5 (ix)
	inc	de
	inc	de
	inc	de
	ld	a, e
	add	a, 4 (ix)
	ld	-2 (ix), a
	ld	a, d
	adc	a, 5 (ix)
	ld	-1 (ix), a
	ld	e, -4 (ix)
	ld	d, -3 (ix)
	inc	de
	inc	de
	inc	de
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	add	hl, de
	ld	a, (hl)
	ld	l, -8 (ix)
	ld	h, -7 (ix)
	ld	e, (hl)
	xor	a, e
	ld	l, -2 (ix)
	ld	h, -1 (ix)
	ld	(hl), a
;aes_192.c:64: for (i = nk; i < 4 * (nr + 1); ++i) {
	inc	bc
	jp	00109$
00111$:
;aes_192.c:83: }
	ld	sp, ix
	pop	ix
	ret
;aes_192.c:86: void AES192_Encrypt(uint8_t* buffer, const uint8_t* key) {
;	---------------------------------
; Function AES192_Encrypt
; ---------------------------------
_AES192_Encrypt::
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-211
	add	hl, sp
	ld	sp, hl
;aes_192.c:88: KeyExpansion(RoundKey, key);
	ld	hl, #0
	add	hl, sp
	ex	de, hl
	ld	c, e
	ld	b, d
	push	de
	ld	l, 6 (ix)
	ld	h, 7 (ix)
	push	hl
	push	bc
	call	_KeyExpansion
	pop	af
	pop	af
	pop	de
;aes_192.c:90: AddRoundKey(0, buffer, RoundKey); 
	ld	c, e
	ld	b, d
	push	de
	push	bc
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	push	hl
	xor	a, a
	push	af
	inc	sp
	call	_AddRoundKey
	pop	af
	pop	af
	inc	sp
	pop	de
;aes_192.c:93: for (int round = 1; round < 12; ++round) {
	ld	-3 (ix), e
	ld	-2 (ix), d
	ld	bc, #0x0001
00103$:
	ld	a, c
	sub	a, #0x0c
	ld	a, b
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00101$
;aes_192.c:94: SubBytes(buffer);
	push	bc
	push	de
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	push	hl
	call	_SubBytes
	pop	af
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	push	hl
	call	_ShiftRows
	pop	af
	pop	de
	pop	bc
;aes_192.c:96: AddRoundKey(round, buffer, RoundKey);
	ld	l, -3 (ix)
	ld	h, -2 (ix)
	ld	-1 (ix), c
	push	bc
	push	de
	push	hl
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	push	hl
	ld	a, -1 (ix)
	push	af
	inc	sp
	call	_AddRoundKey
	pop	af
	pop	af
	inc	sp
	pop	de
	pop	bc
;aes_192.c:93: for (int round = 1; round < 12; ++round) {
	inc	bc
	jr	00103$
00101$:
;aes_192.c:100: SubBytes(buffer);
	push	de
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	push	hl
	call	_SubBytes
	pop	af
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	push	hl
	call	_ShiftRows
	pop	af
	ld	l, 4 (ix)
	ld	h, 5 (ix)
	push	hl
	ld	a, #0x0c
	push	af
	inc	sp
	call	_AddRoundKey
;aes_192.c:103: }
	ld	sp,ix
	pop	ix
	ret
;aes_192.c:105: int main() {
;	---------------------------------
; Function main
; ---------------------------------
_main::
	push	ix
	ld	ix,#0
	add	ix,sp
	ld	hl, #-40
	add	hl, sp
	ld	sp, hl
;aes_192.c:106: uint8_t data[16] = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };
	ld	hl, #0
	add	hl, sp
	ld	c, l
	ld	b, h
	ld	a, #0x32
	ld	(bc), a
	ld	l, c
	ld	h, b
	inc	hl
	ld	(hl), #0x43
	ld	l, c
	ld	h, b
	inc	hl
	inc	hl
	ld	(hl), #0xf6
	ld	l, c
	ld	h, b
	inc	hl
	inc	hl
	inc	hl
	ld	(hl), #0xa8
	ld	hl, #0x0004
	add	hl, bc
	ld	(hl), #0x88
	ld	hl, #0x0005
	add	hl, bc
	ld	(hl), #0x5a
	ld	hl, #0x0006
	add	hl, bc
	ld	(hl), #0x30
	ld	hl, #0x0007
	add	hl, bc
	ld	(hl), #0x8d
	ld	hl, #0x0008
	add	hl, bc
	ld	(hl), #0x31
	ld	hl, #0x0009
	add	hl, bc
	ld	(hl), #0x31
	ld	hl, #0x000a
	add	hl, bc
	ld	(hl), #0x98
	ld	hl, #0x000b
	add	hl, bc
	ld	(hl), #0xa2
	ld	hl, #0x000c
	add	hl, bc
	ld	(hl), #0xe0
	ld	hl, #0x000d
	add	hl, bc
	ld	(hl), #0x37
	ld	hl, #0x000e
	add	hl, bc
	ld	(hl), #0x07
	ld	hl, #0x000f
	add	hl, bc
	ld	(hl), #0x34
;aes_192.c:107: uint8_t key[24] = { 
	ld	hl, #16
	add	hl, sp
	ex	de, hl
	ld	a, #0x8e
	ld	(de), a
	ld	l, e
	ld	h, d
	inc	hl
	ld	(hl), #0x73
	ld	l, e
	ld	h, d
	inc	hl
	inc	hl
	ld	(hl), #0xb0
	ld	l, e
	ld	h, d
	inc	hl
	inc	hl
	inc	hl
	ld	(hl), #0xf7
	ld	hl, #0x0004
	add	hl, de
	ld	(hl), #0xda
	ld	hl, #0x0005
	add	hl, de
	ld	(hl), #0x0e
	ld	hl, #0x0006
	add	hl, de
	ld	(hl), #0x64
	ld	hl, #0x0007
	add	hl, de
	ld	(hl), #0x52
	ld	hl, #0x0008
	add	hl, de
	ld	(hl), #0xc8
	ld	hl, #0x0009
	add	hl, de
	ld	(hl), #0x10
	ld	hl, #0x000a
	add	hl, de
	ld	(hl), #0xf3
	ld	hl, #0x000b
	add	hl, de
	ld	(hl), #0x2b
	ld	hl, #0x000c
	add	hl, de
	ld	(hl), #0x80
	ld	hl, #0x000d
	add	hl, de
	ld	(hl), #0x90
	ld	hl, #0x000e
	add	hl, de
	ld	(hl), #0x79
	ld	hl, #0x000f
	add	hl, de
	ld	(hl), #0xe5
	ld	hl, #0x0010
	add	hl, de
	ld	(hl), #0x62
	ld	hl, #0x0011
	add	hl, de
	ld	(hl), #0xf8
	ld	hl, #0x0012
	add	hl, de
	ld	(hl), #0xea
	ld	hl, #0x0013
	add	hl, de
	ld	(hl), #0xd2
	ld	hl, #0x0014
	add	hl, de
	ld	(hl), #0x52
	ld	hl, #0x0015
	add	hl, de
	ld	(hl), #0x2c
	ld	hl, #0x0016
	add	hl, de
	ld	(hl), #0x6b
	ld	hl, #0x0017
	add	hl, de
	ld	(hl), #0x7b
;aes_192.c:112: printf("--- Running AES-192 ---\n");
	push	bc
	push	de
	ld	hl, #___str_1
	push	hl
	call	_puts
	pop	af
	pop	de
	pop	bc
;aes_192.c:113: AES192_Encrypt(data, key);
	ld	l, c
	ld	h, b
	push	bc
	push	de
	push	hl
	call	_AES192_Encrypt
	pop	af
	ld	hl, #___str_2
	ex	(sp),hl
	call	_printf
	pop	af
	pop	bc
;aes_192.c:116: for(int i=0; i<16; i++) printf("%02x ", data[i]);
	ld	de, #0x0000
00103$:
	ld	a, e
	sub	a, #0x10
	ld	a, d
	rla
	ccf
	rra
	sbc	a, #0x80
	jr	NC,00101$
	ld	l, c
	ld	h, b
	add	hl, de
	ld	l, (hl)
	ld	h, #0x00
	push	bc
	push	de
	push	hl
	ld	hl, #___str_3
	push	hl
	call	_printf
	pop	af
	pop	af
	pop	de
	pop	bc
	inc	de
	jr	00103$
00101$:
;aes_192.c:117: printf("\n");
	ld	hl, #___str_5
	push	hl
	call	_puts
	pop	af
;aes_192.c:119: return 0;
	ld	hl, #0x0000
;aes_192.c:120: }
	ld	sp, ix
	pop	ix
	ret
___str_1:
	.ascii "--- Running AES-192 ---"
	.db 0x00
___str_2:
	.ascii "Encrypted: "
	.db 0x00
___str_3:
	.ascii "%02x "
	.db 0x00
___str_5:
	.db 0x00
	.area _CODE
	.area _INITIALIZER
	.area _CABS (ABS)
