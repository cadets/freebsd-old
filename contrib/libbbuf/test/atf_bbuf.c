/*-
 * Copyright (c) 2018 (Graeme Jenkinson)
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
 * 
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/sbuf.h>

#include <atf-c.h>
#include <stdlib.h>
#include <strings.h>

#include "bbuf.h"

unsigned short PRIO_LOG = PRIO_LOW;

const bbuf_malloc_func bbuf_alloc = malloc;
const bbuf_free_func bbuf_free = free;

/* Test 1
 * bbuf_new_auto() - Ctor auto resizing buffer.
 */
ATF_TC_WITHOUT_HEAD(test1);
ATF_TC_BODY(test1, tc)
{
	struct bbuf *buffer = NULL;
	int rc = -1;

	rc = bbuf_new_auto(&buffer);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);

	bbuf_delete(buffer);
}

/* Test 2
 * bbuf_new() - Ctor valid params.
 */
ATF_TC_WITHOUT_HEAD(test2);
ATF_TC_BODY(test2, tc)
{
	struct bbuf *buffer = NULL;
	int rc = -1, capacity = 100;

	rc = bbuf_new(&buffer, NULL, capacity, BBUF_AUTOEXTEND);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);
	ATF_REQUIRE(bbuf_pos(buffer) == 0);
	ATF_REQUIRE(bbuf_len(buffer) == capacity);

	bbuf_delete(buffer);
}

/* Test 3
 * bbuf_put_int8() - BBUF_FIXEDLEN.
 */
ATF_TC_WITHOUT_HEAD(test3);
ATF_TC_BODY(test3, tc)
{
	struct bbuf *buffer = NULL;
	int rc = - 1, i, capacity = 10;

	rc = bbuf_new(&buffer, NULL, capacity, BBUF_FIXEDLEN);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);

	for (i = 0; i < capacity; i++) {
		rc = bbuf_put_int8(buffer, i);	
		ATF_REQUIRE(rc == 0);
	}
	       
	rc = bbuf_put_int8(buffer, 0);	
	ATF_REQUIRE(rc == -1);

	bbuf_delete(buffer);
}

/* Test 4
 * bbuf_put_int8() - bbuf_AUTOEXTEND.
 */
ATF_TC_WITHOUT_HEAD(test4);
ATF_TC_BODY(test4, tc)
{
	struct bbuf *buffer = NULL;
	int rc = - 1, i, capacity = 10;

	rc = bbuf_new(&buffer, NULL, capacity, BBUF_AUTOEXTEND);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);

	for (i = 0; i < capacity; i++) {
		rc = bbuf_put_int8(buffer, i);	
		ATF_REQUIRE(rc == 0);
	}
	       
	rc = bbuf_put_int8(buffer, 0);	
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);

	bbuf_delete(buffer);
}

/* Test 5
 * bbuf_get|put_int16() - store and return int16.
 */
ATF_TC_WITHOUT_HEAD(test5);
ATF_TC_BODY(test5, tc)
{
	struct bbuf *buffer;
	int rc;
	int16_t load_val = 0, store_val = 10 << 8;

	rc = bbuf_new(&buffer, NULL, 100, BBUF_AUTOEXTEND);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);

	rc = bbuf_put_int16(buffer, store_val);
	ATF_REQUIRE(rc == 0);

	bbuf_flip(buffer);

	rc = bbuf_get_int16(buffer, &load_val);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(load_val == store_val);

	bbuf_delete(buffer);
}

/* Test 6
 * bbuf_get|put_int32() - store and return int32.
 */
ATF_TC_WITHOUT_HEAD(test6);
ATF_TC_BODY(test6, tc)
{
	struct bbuf *buffer;
	int rc;
	int32_t load_val = 0, store_val = 10 << 16;

	rc = bbuf_new(&buffer, NULL, 100, BBUF_AUTOEXTEND);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);

	rc = bbuf_put_int32(buffer, store_val);
	ATF_REQUIRE(rc == 0);

	bbuf_flip(buffer);

	rc = bbuf_get_int32(buffer, &load_val);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(load_val == store_val);

	bbuf_delete(buffer);
}

/* Test 7
 * bbuf_get|put_int64() - store and return int64.
 */
ATF_TC_WITHOUT_HEAD(test7);
ATF_TC_BODY(test7, tc)
{
	struct bbuf *buffer;
	int rc;
	int64_t load_val = 0, store_val = 10 << 24;

	rc = bbuf_new(&buffer, NULL, 100, BBUF_AUTOEXTEND);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);

	rc = bbuf_put_int64(buffer, store_val);
	ATF_REQUIRE(rc == 0);

	bbuf_flip(buffer);

	rc = bbuf_get_int64(buffer, &load_val);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(load_val == store_val);

	bbuf_delete(buffer);
}

/* Test 8
 * bbuf_get_flags() - bbuf_AUTOEXTEND|bbuf_BIGENDIAN.
 */
ATF_TC_WITHOUT_HEAD(test8);
ATF_TC_BODY(test8, tc)
{
	struct bbuf *buffer = NULL;
	int rc = - 1, i, capacity = 10;
	bbuf_flags flags;

	rc = bbuf_new_auto(&buffer);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);
	       
	flags = bbuf_get_flags(buffer);	
	ATF_REQUIRE(flags != 0);
	ATF_REQUIRE((flags & BBUF_AUTOEXTEND) != 0);

	bbuf_delete(buffer);
}

/* Test 9
 * bbuf_new() - external buffer.
 */
ATF_TC_WITHOUT_HEAD(test9);
ATF_TC_BODY(test9, tc)
{
	struct bbuf *buffer = NULL;
	bbuf_flags flags;
	unsigned char *ext_buffer;
	int rc = - 1, i, capacity = 10;

	ext_buffer = (unsigned char *) malloc(capacity * sizeof(unsigned char));
	rc = bbuf_new(&buffer, ext_buffer, capacity, BBUF_FIXEDLEN);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);

	for (i = 0; i < capacity; i++) {
		rc = bbuf_put_int8(buffer, i);	
		ATF_REQUIRE(rc == 0);
	}
	       
	rc = bbuf_put_int8(buffer, 0);	
	ATF_REQUIRE(rc == -1);

	for (i = 0; i < capacity; i++)
		ATF_REQUIRE(ext_buffer[i] == i);

	bbuf_delete(buffer);
	free(ext_buffer);
}

/* Test 10
 * bbuf_data() - external buffer.
 */
ATF_TC_WITHOUT_HEAD(test10);
ATF_TC_BODY(test10, tc)
{
	struct bbuf *buffer = NULL;
	bbuf_flags flags;
	unsigned char *ext_buffer;
	int rc = - 1, i, capacity = 10;

	ext_buffer = (unsigned char *) malloc(capacity * sizeof(unsigned char));
	rc = bbuf_new(&buffer, ext_buffer, capacity, BBUF_FIXEDLEN);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);
	ATF_REQUIRE(bbuf_data(buffer) == ext_buffer);

	bbuf_delete(buffer);
	free(ext_buffer);
}

/* Test 11
 * bbuf_pos() - bbuf_put_int8()
 */
ATF_TC_WITHOUT_HEAD(test11);
ATF_TC_BODY(test11, tc)
{
	struct bbuf *buffer = NULL;
	int rc = - 1, i, capacity = 10;

	rc = bbuf_new(&buffer, NULL, capacity, BBUF_FIXEDLEN);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);

	for (i = 0; i < capacity; i++) {
		ATF_REQUIRE(bbuf_pos(buffer) == i);
		rc = bbuf_put_int8(buffer, i);	
		ATF_REQUIRE(rc == 0);
		ATF_REQUIRE(bbuf_pos(buffer) == i+1);
		ATF_REQUIRE(bbuf_len(buffer) == capacity);
	}
	       
	bbuf_delete(buffer);
}

/* Test 12 
 * bbuf_put_int16|get_int8() - BBUF_FIXEDLEN|BBUF_BIGENDIAN.
 */
ATF_TC_WITHOUT_HEAD(test12);
ATF_TC_BODY(test12, tc)
{
	struct bbuf *buffer = NULL;
	int rc = - 1, i, capacity = 10;
	int16_t store_val = 0xABCD;
	int8_t load_val;

	rc = bbuf_new(&buffer, NULL, capacity,
		     	BBUF_FIXEDLEN|BBUF_BIGENDIAN);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);
	       
	bbuf_put_int16(buffer, store_val);

	bbuf_flip(buffer);

	rc = bbuf_get_int8(buffer, &load_val);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(load_val == (int8_t) ((store_val >> 8) & 0xFF));

	rc = bbuf_get_int8(buffer, &load_val);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(load_val == (int8_t) ((store_val >> 0) & 0xFF));

	bbuf_delete(buffer);
}

/* Test 13 
 * bbuf_put_int16|get_int8() - bbuf_FIXEDLEN|bbuf_LITTLEENDIAN.
 */
ATF_TC_WITHOUT_HEAD(test13);
ATF_TC_BODY(test13, tc)
{
	struct bbuf *buffer = NULL;
	int rc = - 1, i, capacity = 10;
	int16_t store_val = 0xABCD;
	int8_t load_val;

	rc = bbuf_new(&buffer, NULL, capacity,
		     	BBUF_FIXEDLEN|BBUF_LITTLEENDIAN);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);
	       
	rc = bbuf_put_int16(buffer, store_val);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(bbuf_pos(buffer) == sizeof(int16_t));

	bbuf_flip(buffer);

	rc = bbuf_get_int8(buffer, &load_val);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(load_val == (int8_t) ((store_val >> 0) & 0xFF));

	rc = bbuf_get_int8(buffer, &load_val);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(load_val == (int8_t) ((store_val >> 8) & 0xFF));

	bbuf_delete(buffer);
}

/* Test 14
 * bbuf_clear()
 */
ATF_TC_WITHOUT_HEAD(test14);
ATF_TC_BODY(test14, tc)
{
	struct bbuf *buffer = NULL;
	int rc = - 1, i, capacity = 10;

	rc = bbuf_new(&buffer, NULL, capacity, BBUF_FIXEDLEN);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);

	for (i = 0; i < capacity; i++) {
		rc = bbuf_put_int8(buffer, i);	
	}

	bbuf_clear(buffer);
	ATF_REQUIRE(bbuf_pos(buffer) == 0);
	       
	bbuf_delete(buffer);
}

/* Test 15
 * bbuf_concat()
 */
ATF_TC_WITHOUT_HEAD(test15);
ATF_TC_BODY(test15, tc)
{
	struct bbuf *buffer1 = NULL, *buffer2 = NULL;
	int rc = - 1, i, capacity = 10;
	int8_t load_val;

	rc = bbuf_new(&buffer1, NULL, capacity, BBUF_FIXEDLEN);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer1 != NULL);
	ATF_REQUIRE(bbuf_pos(buffer1) == 0);

	rc = bbuf_new(&buffer2, NULL, capacity, BBUF_FIXEDLEN);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer2 != NULL);

	for (i = 0; i < capacity; i++) {
		rc = bbuf_put_int8(buffer2, i);	
		ATF_REQUIRE(rc == 0);
	}
	ATF_REQUIRE(bbuf_pos(buffer2) == capacity);

	rc = bbuf_concat(buffer1, buffer2);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(bbuf_pos(buffer1) == capacity);

	bbuf_flip(buffer1); 
	ATF_REQUIRE(bbuf_pos(buffer1) == 0);

	for (i = 0; i < capacity; i++) {
		rc = bbuf_get_int8(buffer1, &load_val);
		ATF_REQUIRE(rc == 0);
		ATF_REQUIRE(load_val == i);
	}
 
	bbuf_delete(buffer1);
	bbuf_delete(buffer2);
}

/* Test 16 
 * bbuf_put_int8_at(..., 0) - bbuf_FIXEDLEN.
 */
ATF_TC_WITHOUT_HEAD(test16);
ATF_TC_BODY(test16, tc)
{
	struct bbuf *buffer = NULL;
	int rc = - 1, i, capacity = 10;
	int8_t store_val = 100, load_val;

	rc = bbuf_new(&buffer, NULL, capacity, BBUF_FIXEDLEN);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);

	for (i = 0; i < capacity; i++) {
		rc = bbuf_put_int8(buffer, i);	
		ATF_REQUIRE(rc == 0);
	}
	       
	rc = bbuf_put_int8_at(buffer, store_val, 0);	
	ATF_REQUIRE(rc == 0);

	bbuf_flip(buffer);

	rc = bbuf_get_int8(buffer, &load_val);
	ATF_REQUIRE(load_val == store_val);

	bbuf_delete(buffer);
}

/* Test 17 
 * bbuf_put_int8_at(..., 1) - bbuf_FIXEDLEN.
 */
ATF_TC_WITHOUT_HEAD(test17);
ATF_TC_BODY(test17, tc)
{
	struct bbuf *buffer = NULL;
	int rc = - 1, i, capacity = 10;
	int8_t store_val = 100, load_val;

	rc = bbuf_new(&buffer, NULL, capacity, BBUF_FIXEDLEN);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);

	for (i = 0; i < capacity; i++) {
		rc = bbuf_put_int8(buffer, i);	
		ATF_REQUIRE(rc == 0);
	}
	       
	rc = bbuf_put_int8_at(buffer, store_val, 1);	
	ATF_REQUIRE(rc == 0);

	bbuf_flip(buffer);

	rc = bbuf_get_int8(buffer, &load_val);
	ATF_REQUIRE(rc == 0);

	rc = bbuf_get_int8(buffer, &load_val);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(load_val == store_val);

	bbuf_delete(buffer);
}

/* Test 18 
 * bbuf_put_int16_at(..., 0) - bbuf_FIXEDLEN.
 */
ATF_TC_WITHOUT_HEAD(test18);
ATF_TC_BODY(test18, tc)
{
	struct bbuf *buffer = NULL;
	int rc = - 1, i, capacity = 10;
	int16_t store_val = 100, load_val;

	rc = bbuf_new(&buffer, NULL, capacity, BBUF_FIXEDLEN);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer != NULL);

	for (i = 0; i < capacity; i++) {
		rc = bbuf_put_int8(buffer, i);	
		ATF_REQUIRE(rc == 0);
	}
	       
	rc = bbuf_put_int16_at(buffer, store_val, 0);	
	ATF_REQUIRE(rc == 0);

	bbuf_flip(buffer);

	rc = bbuf_get_int16(buffer, &load_val);
	ATF_REQUIRE(load_val == store_val);

	bbuf_delete(buffer);
}

/* Test 19
 * bbuf_bcat()
 */
ATF_TC_WITHOUT_HEAD(test19);
ATF_TC_BODY(test19, tc)
{
	struct bbuf *buffer1 = NULL;
	char *buffer2 = NULL;
	int rc = - 1, i, capacity = 10;
	int8_t load_val;

	rc = bbuf_new(&buffer1, NULL, capacity, BBUF_FIXEDLEN);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(buffer1 != NULL);
	ATF_REQUIRE(bbuf_pos(buffer1) == 0);

	buffer2 = malloc(capacity * sizeof(char));
	ATF_REQUIRE(buffer2 != NULL);

	for (i = 0; i < capacity; i++) {
		buffer2[i] = i;
	}

	rc = bbuf_bcat(buffer1, buffer2, capacity);
	ATF_REQUIRE(rc == 0);
	ATF_REQUIRE(bbuf_pos(buffer1) == capacity);

	bbuf_flip(buffer1); 
	ATF_REQUIRE(bbuf_pos(buffer1) == 0);

	for (i = 0; i < capacity; i++) {
		rc = bbuf_get_int8(buffer1, &load_val);
		ATF_REQUIRE(rc == 0);
		ATF_REQUIRE(load_val == i);
	}
 
	bbuf_delete(buffer1);
	free(buffer2);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, test1);
	ATF_TP_ADD_TC(tp, test2);
	ATF_TP_ADD_TC(tp, test3);
	ATF_TP_ADD_TC(tp, test4);
	ATF_TP_ADD_TC(tp, test5);
	ATF_TP_ADD_TC(tp, test6);
	ATF_TP_ADD_TC(tp, test7);
	ATF_TP_ADD_TC(tp, test8);
	ATF_TP_ADD_TC(tp, test9);
	ATF_TP_ADD_TC(tp, test10);
	ATF_TP_ADD_TC(tp, test11);
	ATF_TP_ADD_TC(tp, test12);
	ATF_TP_ADD_TC(tp, test13);
	ATF_TP_ADD_TC(tp, test14);
	ATF_TP_ADD_TC(tp, test15);
	ATF_TP_ADD_TC(tp, test16);
	ATF_TP_ADD_TC(tp, test17);
	ATF_TP_ADD_TC(tp, test18);
	ATF_TP_ADD_TC(tp, test19);

	return atf_no_error();
}
