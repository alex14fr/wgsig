/* test_chacha20 - RFC 8439 Chacha20 2.4.2 test vector 
 *
 * BSD 2-Clause License
 *
 * Copyright (c) 2022, Alexandre Janon <alex14fr@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "chacha20.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>

void main(void) {
	uint8_t k[32]={0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13, 0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
	uint8_t nonce[12]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x4a,0x00,0x00,0x00,0x00};
	uint32_t ic=1;
	uint8_t m[]="Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
	uint8_t c[strlen(m)+1];
	c[strlen(m)]=0;
	chacha_ctx chactx;
	chacha_keysetup(&chactx, k);
	chacha_ivsetup(&chactx, nonce, ic);
	chacha_encrypt_bytes(&chactx, m, c, strlen(m));
	printf("%s",c);
}
