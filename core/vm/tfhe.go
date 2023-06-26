// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

/*
#cgo CFLAGS: -O3 -I.
#cgo LDFLAGS: -Llib -ltfhe

#include <tfhe.h>

#undef NDEBUG
#include <assert.h>

void* deserialize_server_key(BufferView in) {
	ServerKey* sks = NULL;
	const int r = server_key_deserialize(in, &sks);
	assert(r == 0);
	return sks;
}

void* deserialize_client_key(BufferView in) {
	ClientKey* cks = NULL;
	const int r = client_key_deserialize(in, &cks);
	assert(r == 0);
	return cks;
}

void* deserialize_compact_public_key(BufferView in) {
	CompactPublicKey* pks = NULL;
	const int r = compact_public_key_deserialize(in, &pks);
	assert(r == 0);
	return pks;
}

void checked_set_server_key(void *sks) {
	const int r = set_server_key(sks);
	assert(r == 0);
}

void serialize_fhe_uint8(void *ct, Buffer* out) {
	const int r = fhe_uint8_serialize(ct, out);
	assert(r == 0);
}

void* deserialize_fhe_uint8(BufferView in) {
	FheUint8* ct = NULL;
	const int r = fhe_uint8_deserialize(in, &ct);
	if(r != 0) {
		return NULL;
	}
	return ct;
}

void* deserialize_compact_fhe_uint8(BufferView in) {
	CompactFheUint8List* list = NULL;
	FheUint8* ct = NULL;

	int r = compact_fhe_uint8_list_deserialize(in, &list);
	if(r != 0) {
		return NULL;
	}
	size_t len = 0;
	r = compact_fhe_uint8_list_len(list, &len);
	// Expect only 1 ciphertext in the list.
	if(r != 0 || len != 1) {
		r = compact_fhe_uint8_list_destroy(list);
		assert(r == 0);
		return NULL;
	}
	r = compact_fhe_uint8_list_expand(list, &ct, 1);
	if(r != 0) {
		ct = NULL;
	}
	r = compact_fhe_uint8_list_destroy(list);
	assert(r == 0);
	return ct;
}

void serialize_fhe_uint16(void *ct, Buffer* out) {
	const int r = fhe_uint16_serialize(ct, out);
	assert(r == 0);
}

void* deserialize_fhe_uint16(BufferView in) {
	FheUint16* ct = NULL;
	const int r = fhe_uint16_deserialize(in, &ct);
	if(r != 0) {
		return NULL;
	}
	return ct;
}

void* deserialize_compact_fhe_uint16(BufferView in) {
	CompactFheUint16List* list = NULL;
	FheUint16* ct = NULL;

	int r = compact_fhe_uint16_list_deserialize(in, &list);
	if(r != 0) {
		return NULL;
	}
	size_t len = 0;
	r = compact_fhe_uint16_list_len(list, &len);
	// Expect only 1 ciphertext in the list.
	if(r != 0 || len != 1) {
		r = compact_fhe_uint16_list_destroy(list);
		assert(r == 0);
		return NULL;
	}
	r = compact_fhe_uint16_list_expand(list, &ct, 1);
	if(r != 0) {
		ct = NULL;
	}
	r = compact_fhe_uint16_list_destroy(list);
	assert(r == 0);
	return ct;
}

void serialize_fhe_uint32(void *ct, Buffer* out) {
	const int r = fhe_uint32_serialize(ct, out);
	assert(r == 0);
}

void* deserialize_fhe_uint32(BufferView in) {
	FheUint32* ct = NULL;
	const int r = fhe_uint32_deserialize(in, &ct);
	if(r != 0) {
		return NULL;
	}
	return ct;
}

void* deserialize_compact_fhe_uint32(BufferView in) {
	CompactFheUint32List* list = NULL;
	FheUint32* ct = NULL;

	int r = compact_fhe_uint32_list_deserialize(in, &list);
	if(r != 0) {
		return NULL;
	}
	size_t len = 0;
	r = compact_fhe_uint32_list_len(list, &len);
	// Expect only 1 ciphertext in the list.
	if(r != 0 || len != 1) {
		r = compact_fhe_uint32_list_destroy(list);
		assert(r == 0);
		return NULL;
	}
	r = compact_fhe_uint32_list_expand(list, &ct, 1);
	if(r != 0) {
		ct = NULL;
	}
	r = compact_fhe_uint32_list_destroy(list);
	assert(r == 0);
	return ct;
}

void destroy_fhe_uint8(void* ct) {
	fhe_uint8_destroy(ct);
}

void destroy_fhe_uint16(void* ct) {
	fhe_uint16_destroy(ct);
}

void destroy_fhe_uint32(void* ct) {
	fhe_uint32_destroy(ct);
}

void* add_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_add(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* add_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_add(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* add_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_add(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* scalar_add_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_add(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* scalar_add_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_add(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* scalar_add_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_add(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* sub_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_sub(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* sub_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_sub(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* sub_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_sub(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* scalar_sub_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_sub(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* scalar_sub_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_sub(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* scalar_sub_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_sub(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* mul_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_mul(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* mul_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_mul(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* mul_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_mul(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* scalar_mul_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_mul(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* scalar_mul_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_mul(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* scalar_mul_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_mul(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* bitand_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_bitand(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* bitand_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_bitand(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* bitand_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_bitand(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* bitor_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_bitor(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* bitor_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_bitor(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* bitor_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_bitor(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* bitxor_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_bitxor(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* bitxor_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_bitxor(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* bitxor_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_bitxor(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* shl_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_shl(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* shl_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_shl(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* shl_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_shl(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* scalar_shl_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_shl(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* scalar_shl_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_shl(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* scalar_shl_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_shl(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* shr_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_shr(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* shr_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_shr(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* shr_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_shr(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* scalar_shr_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_shr(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* scalar_shr_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_shr(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* scalar_shr_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_shr(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* eq_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_eq(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* eq_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_eq(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* eq_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_eq(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* scalar_eq_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_eq(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* scalar_eq_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_eq(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* scalar_eq_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_eq(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* ne_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_ne(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* ne_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_ne(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* ne_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_ne(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* scalar_ne_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_ne(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* scalar_ne_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_ne(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* scalar_ne_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_ne(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* ge_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_ge(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* ge_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_ge(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* ge_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_ge(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* scalar_ge_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_ge(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* scalar_ge_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_ge(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* scalar_ge_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_ge(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* gt_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_gt(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* gt_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_gt(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* gt_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_gt(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* scalar_gt_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_gt(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* scalar_gt_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_gt(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* scalar_gt_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_gt(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* le_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_le(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* le_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_le(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* le_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_le(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* lt_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_lt(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* scalar_le_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_le(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* scalar_le_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_le(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* scalar_le_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_le(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* lt_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_lt(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* lt_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_lt(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* scalar_lt_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_lt(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* scalar_lt_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_lt(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* scalar_lt_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_lt(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* min_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_min(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* min_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_min(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* min_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_min(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* scalar_min_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_min(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* scalar_min_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_min(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* scalar_min_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_min(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* max_fhe_uint8(void* ct1, void* ct2, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_max(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* max_fhe_uint16(void* ct1, void* ct2, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_max(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* max_fhe_uint32(void* ct1, void* ct2, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_max(ct1, ct2, &result);
	assert(r == 0);
	return result;
}

void* scalar_max_fhe_uint8(void* ct, uint8_t pt, void* sks)
{
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_scalar_max(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* scalar_max_fhe_uint16(void* ct, uint16_t pt, void* sks)
{
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_scalar_max(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* scalar_max_fhe_uint32(void* ct, uint32_t pt, void* sks)
{
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_scalar_max(ct, pt, &result);
	assert(r == 0);
	return result;
}

void* neg_fhe_uint8(void* ct, void* sks) {
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_neg(ct, &result);
	assert(r == 0);
	return result;
}

void* neg_fhe_uint16(void* ct, void* sks) {
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_neg(ct, &result);
	assert(r == 0);
	return result;
}

void* neg_fhe_uint32(void* ct, void* sks) {
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_neg(ct, &result);
	assert(r == 0);
	return result;
}

void* not_fhe_uint8(void* ct, void* sks) {
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_not(ct, &result);
	assert(r == 0);
	return result;
}

void* not_fhe_uint16(void* ct, void* sks) {
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_not(ct, &result);
	assert(r == 0);
	return result;
}

void* not_fhe_uint32(void* ct, void* sks) {
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_not(ct, &result);
	assert(r == 0);
	return result;
}

uint8_t decrypt_fhe_uint8(void* cks, void* ct)
{
	uint8_t res = 0;
	const int r = fhe_uint8_decrypt(ct, cks, &res);
	assert(r == 0);
	return res;
}

uint16_t decrypt_fhe_uint16(void* cks, void* ct)
{
	uint16_t res = 0;
	const int r = fhe_uint16_decrypt(ct, cks, &res);
	assert(r == 0);
	return res;
}

uint32_t decrypt_fhe_uint32(void* cks, void* ct)
{
	uint32_t res = 0;
	const int r = fhe_uint32_decrypt(ct, cks, &res);
	assert(r == 0);
	return res;
}

void* public_key_encrypt_fhe_uint8(void* pks, uint8_t value) {
	CompactFheUint8List* list = NULL;
	FheUint8* ct = NULL;

	int r = compact_fhe_uint8_list_try_encrypt_with_compact_public_key_u8(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint8_list_expand(list, &ct, 1);
	assert(r == 0);

	r = compact_fhe_uint8_list_destroy(list);
	assert(r == 0);

	return ct;
}

void* public_key_encrypt_fhe_uint16(void* pks, uint16_t value) {
	CompactFheUint16List* list = NULL;
	FheUint16* ct = NULL;

	int r = compact_fhe_uint16_list_try_encrypt_with_compact_public_key_u16(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint16_list_expand(list, &ct, 1);
	assert(r == 0);

	r = compact_fhe_uint16_list_destroy(list);
	assert(r == 0);

	return ct;
}

void* public_key_encrypt_fhe_uint32(void* pks, uint32_t value) {
	CompactFheUint32List* list = NULL;
	FheUint32* ct = NULL;

	int r = compact_fhe_uint32_list_try_encrypt_with_compact_public_key_u32(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint32_list_expand(list, &ct, 1);
	assert(r == 0);

	r = compact_fhe_uint32_list_destroy(list);
	assert(r == 0);

	return ct;
}

void* trivial_encrypt_fhe_uint8(void* sks, uint8_t value) {
	FheUint8* ct = NULL;

	checked_set_server_key(sks);

	int r = fhe_uint8_try_encrypt_trivial_u8(value, &ct);
  	assert(r == 0);

	return ct;
}

void* trivial_encrypt_fhe_uint16(void* sks, uint16_t value) {
	FheUint16* ct = NULL;

	checked_set_server_key(sks);

	int r = fhe_uint16_try_encrypt_trivial_u16(value, &ct);
  	assert(r == 0);

	return ct;
}

void* trivial_encrypt_fhe_uint32(void* sks, uint32_t value) {
	FheUint32* ct = NULL;

	checked_set_server_key(sks);

	int r = fhe_uint32_try_encrypt_trivial_u32(value, &ct);
  	assert(r == 0);

	return ct;
}

void public_key_encrypt_and_serialize_fhe_uint8_list(void* pks, uint8_t value, Buffer* out) {
	CompactFheUint8List* list = NULL;

	int r = compact_fhe_uint8_list_try_encrypt_with_compact_public_key_u8(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint8_list_serialize(list, out);
	assert(r == 0);
}

void public_key_encrypt_and_serialize_fhe_uint16_list(void* pks, uint16_t value, Buffer* out) {
	CompactFheUint16List* list = NULL;

	int r = compact_fhe_uint16_list_try_encrypt_with_compact_public_key_u16(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint16_list_serialize(list, out);
	assert(r == 0);
}

void public_key_encrypt_and_serialize_fhe_uint32_list(void* pks, uint32_t value, Buffer* out) {
	CompactFheUint32List* list = NULL;

	int r = compact_fhe_uint32_list_try_encrypt_with_compact_public_key_u32(&value, 1, pks, &list);
  	assert(r == 0);

	r = compact_fhe_uint32_list_serialize(list, out);
	assert(r == 0);
}

void* cast_8_16(void* ct, void* sks) {
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_cast_into_fhe_uint16(ct, &result);
	assert(r == 0);
	return result;
}

void* cast_8_32(void* ct, void* sks) {
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint8_cast_into_fhe_uint32(ct, &result);
	assert(r == 0);
	return result;
}

void* cast_16_8(void* ct, void* sks) {
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_cast_into_fhe_uint8(ct, &result);
	assert(r == 0);
	return result;
}

void* cast_16_32(void* ct, void* sks) {
	FheUint32* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint16_cast_into_fhe_uint32(ct, &result);
	assert(r == 0);
	return result;
}

void* cast_32_8(void* ct, void* sks) {
	FheUint8* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_cast_into_fhe_uint8(ct, &result);
	assert(r == 0);
	return result;
}

void* cast_32_16(void* ct, void* sks) {
	FheUint16* result = NULL;

	checked_set_server_key(sks);

	const int r = fhe_uint32_cast_into_fhe_uint16(ct, &result);
	assert(r == 0);
	return result;
}

*/
import "C"

import (
	"errors"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func toBufferView(in []byte) C.BufferView {
	return C.BufferView{
		pointer: (*C.uint8_t)(unsafe.Pointer(&in[0])),
		length:  (C.size_t)(len(in)),
	}
}

func homeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	return home
}

// TFHE ciphertext sizes by type, in bytes.
// Note: These sizes are for expanded (non-compacted) ciphertexts.
var expandedFheCiphertextSize map[fheUintType]uint

var sks unsafe.Pointer
var cks unsafe.Pointer
var pks unsafe.Pointer
var pksBytes []byte
var pksHash common.Hash
var networkKeysDir string
var usersKeysDir string

var allocatedCiphertexts uint64

// TODO: We assume that contracts.go's init() runs before the init() in this file,
// making the TOML configuration available here.
func runGc() {
	for range time.Tick(time.Duration(tomlConfig.Tfhe.CiphertextsGarbageCollectIntervalSecs) * time.Second) {
		if atomic.LoadUint64(&allocatedCiphertexts) >= tomlConfig.Tfhe.CiphertextsToGarbageCollect {
			atomic.StoreUint64(&allocatedCiphertexts, 0)
			runtime.GC()
		}
	}
}

func init() {
	expandedFheCiphertextSize = make(map[fheUintType]uint)

	go runGc()

	home := homeDir()
	networkKeysDir = home + "/.evmosd/zama/keys/network-fhe-keys/"
	usersKeysDir = home + "/.evmosd/zama/keys/users-fhe-keys/"

	sksBytes, err := os.ReadFile(networkKeysDir + "sks")
	if err != nil {
		fmt.Println("WARNING: file sks not found.")
		return
	}
	sks = C.deserialize_server_key(toBufferView(sksBytes))

	expandedFheCiphertextSize[FheUint8] = uint(len(new(tfheCiphertext).trivialEncrypt(*big.NewInt(0), FheUint8).serialize()))
	expandedFheCiphertextSize[FheUint16] = uint(len(new(tfheCiphertext).trivialEncrypt(*big.NewInt(0), FheUint16).serialize()))
	expandedFheCiphertextSize[FheUint32] = uint(len(new(tfheCiphertext).trivialEncrypt(*big.NewInt(0), FheUint32).serialize()))

	cksBytes, err := os.ReadFile(networkKeysDir + "cks")
	if err != nil {
		fmt.Println("WARNING: file cks not found.")
		return
	}
	cks = C.deserialize_client_key(toBufferView(cksBytes))

	pksBytes, err = os.ReadFile(networkKeysDir + "pks")
	if err != nil {
		pksBytes = nil
		fmt.Println("WARNING: file pks not found.")
		return
	}
	pksHash = crypto.Keccak256Hash(pksBytes)
	pks = C.deserialize_compact_public_key(toBufferView(pksBytes))
}

// Represents a TFHE ciphertext type, i.e. its bit capacity.
type fheUintType uint8

const (
	FheUint8  fheUintType = 0
	FheUint16 fheUintType = 1
	FheUint32 fheUintType = 2
)

// Represents an expanded TFHE ciphertext.
//
// Once a ciphertext has a value (i.e. from deserialization), it must not be set
// another value. If that is needed, a new ciphertext must be created.
type tfheCiphertext struct {
	ptr           unsafe.Pointer
	serialization []byte
	hash          *common.Hash
	value         *big.Int
	fheUintType   fheUintType
}

// Deserializes a TFHE ciphertext.
func (ct *tfheCiphertext) deserialize(in []byte, t fheUintType) error {
	if ct.initialized() {
		panic("cannot deserialize to an existing ciphertext")
	}
	var ptr unsafe.Pointer
	switch t {
	case FheUint8:
		ptr = C.deserialize_fhe_uint8(toBufferView((in)))
	case FheUint16:
		ptr = C.deserialize_fhe_uint16(toBufferView((in)))
	case FheUint32:
		ptr = C.deserialize_fhe_uint32(toBufferView((in)))
	}
	if ptr == nil {
		return errors.New("TFHE ciphertext deserialization failed")
	}
	ct.setPtr(ptr)
	ct.fheUintType = t
	ct.serialization = in
	return nil
}

// Deserializes a compact TFHE ciphetext.
// Note: After the compact thfe ciphertext has been serialized, subsequent calls to serialize()
// will produce non-compact ciphertext serialziations.
func (ct *tfheCiphertext) deserializeCompact(in []byte, t fheUintType) error {
	if ct.initialized() {
		panic("cannot deserialize to an existing ciphertext")
	}
	var ptr unsafe.Pointer
	switch t {
	case FheUint8:
		ptr = C.deserialize_compact_fhe_uint8(toBufferView((in)))
	case FheUint16:
		ptr = C.deserialize_compact_fhe_uint16(toBufferView((in)))
	case FheUint32:
		ptr = C.deserialize_compact_fhe_uint32(toBufferView((in)))
	}
	if ptr == nil {
		return errors.New("TFHE ciphertext deserialization failed")
	}
	ct.setPtr(ptr)
	ct.fheUintType = t
	return nil
}

// Encrypts a value as a TFHE ciphertext, using the compact public FHE key.
// The resulting ciphertext is automaticaly expanded.
func (ct *tfheCiphertext) encrypt(value big.Int, t fheUintType) *tfheCiphertext {
	if ct.initialized() {
		panic("cannot encrypt to an existing ciphertext")
	}

	switch t {
	case FheUint8:
		ct.setPtr(C.public_key_encrypt_fhe_uint8(pks, C.uint8_t(value.Uint64())))
	case FheUint16:
		ct.setPtr(C.public_key_encrypt_fhe_uint16(pks, C.uint16_t(value.Uint64())))
	case FheUint32:
		ct.setPtr(C.public_key_encrypt_fhe_uint32(pks, C.uint32_t(value.Uint64())))
	}
	ct.fheUintType = t
	ct.value = &value
	return ct
}

func (ct *tfheCiphertext) trivialEncrypt(value big.Int, t fheUintType) *tfheCiphertext {
	if ct.initialized() {
		panic("cannot encrypt to an existing ciphertext")
	}

	switch t {
	case FheUint8:
		ct.setPtr(C.trivial_encrypt_fhe_uint8(sks, C.uint8_t(value.Uint64())))
	case FheUint16:
		ct.setPtr(C.trivial_encrypt_fhe_uint16(sks, C.uint16_t(value.Uint64())))
	case FheUint32:
		ct.setPtr(C.trivial_encrypt_fhe_uint32(sks, C.uint32_t(value.Uint64())))
	}
	ct.fheUintType = t
	ct.value = &value
	return ct
}

func (ct *tfheCiphertext) serialize() []byte {
	if !ct.initialized() {
		panic("cannot serialize a non-initialized ciphertext")
	} else if ct.serialization != nil {
		return ct.serialization
	}
	out := &C.Buffer{}
	switch ct.fheUintType {
	case FheUint8:
		C.serialize_fhe_uint8(ct.ptr, out)
	case FheUint16:
		C.serialize_fhe_uint16(ct.ptr, out)
	case FheUint32:
		C.serialize_fhe_uint32(ct.ptr, out)
	}
	ct.serialization = C.GoBytes(unsafe.Pointer(out.pointer), C.int(out.length))
	C.destroy_buffer(out)
	return ct.serialization
}

func (lhs *tfheCiphertext) add(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	if !lhs.availableForOps() || !rhs.availableForOps() {
		panic("cannot add on a non-initialized ciphertext")
	}

	if lhs.fheUintType != rhs.fheUintType {
		return nil, errors.New("binary operations are only well-defined for identical types")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.add_fhe_uint8(lhs.ptr, rhs.ptr, sks))
	case FheUint16:
		res.setPtr(C.add_fhe_uint16(lhs.ptr, rhs.ptr, sks))
	case FheUint32:
		res.setPtr(C.add_fhe_uint32(lhs.ptr, rhs.ptr, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) scalarAdd(rhs uint64) (*tfheCiphertext, error) {
	if !lhs.availableForOps() {
		panic("cannot scalar add on a non-initialized ciphertext")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		pt := C.uint8_t(rhs)
		res.setPtr(C.scalar_add_fhe_uint8(lhs.ptr, pt, sks))
	case FheUint16:
		pt := C.uint16_t(rhs)
		res.setPtr(C.scalar_add_fhe_uint16(lhs.ptr, pt, sks))
	case FheUint32:
		pt := C.uint32_t(rhs)
		res.setPtr(C.scalar_add_fhe_uint32(lhs.ptr, pt, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) sub(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	if !lhs.availableForOps() || !rhs.availableForOps() {
		panic("cannot sub on a non-initialized ciphertext")
	}

	if lhs.fheUintType != rhs.fheUintType {
		return nil, errors.New("binary operations are only well-defined for identical types")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.sub_fhe_uint8(lhs.ptr, rhs.ptr, sks))
	case FheUint16:
		res.setPtr(C.sub_fhe_uint16(lhs.ptr, rhs.ptr, sks))
	case FheUint32:
		res.setPtr(C.sub_fhe_uint32(lhs.ptr, rhs.ptr, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) scalarSub(rhs uint64) (*tfheCiphertext, error) {
	if !lhs.availableForOps() {
		panic("cannot scalar sub on a non-initialized ciphertext")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		pt := C.uint8_t(rhs)
		res.setPtr(C.scalar_sub_fhe_uint8(lhs.ptr, pt, sks))
	case FheUint16:
		pt := C.uint16_t(rhs)
		res.setPtr(C.scalar_sub_fhe_uint16(lhs.ptr, pt, sks))
	case FheUint32:
		pt := C.uint32_t(rhs)
		res.setPtr(C.scalar_sub_fhe_uint32(lhs.ptr, pt, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) mul(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	if !lhs.availableForOps() || !rhs.availableForOps() {
		panic("cannot mul on a non-initialized ciphertext")
	}

	if lhs.fheUintType != rhs.fheUintType {
		return nil, errors.New("binary operations are only well-defined for identical types")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.mul_fhe_uint8(lhs.ptr, rhs.ptr, sks))
	case FheUint16:
		res.setPtr(C.mul_fhe_uint16(lhs.ptr, rhs.ptr, sks))
	case FheUint32:
		res.setPtr(C.mul_fhe_uint32(lhs.ptr, rhs.ptr, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) scalarMul(rhs uint64) (*tfheCiphertext, error) {
	if !lhs.availableForOps() {
		panic("cannot scalar mul on a non-initialized ciphertext")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		pt := C.uint8_t(rhs)
		res.setPtr(C.scalar_mul_fhe_uint8(lhs.ptr, pt, sks))
	case FheUint16:
		pt := C.uint16_t(rhs)
		res.setPtr(C.scalar_mul_fhe_uint16(lhs.ptr, pt, sks))
	case FheUint32:
		pt := C.uint32_t(rhs)
		res.setPtr(C.scalar_mul_fhe_uint32(lhs.ptr, pt, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) bitand(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	if !lhs.availableForOps() || !rhs.availableForOps() {
		panic("cannot bitwise AND on a non-initialized ciphertext")
	}

	if lhs.fheUintType != rhs.fheUintType {
		return nil, errors.New("binary operations are only well-defined for identical types")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.bitand_fhe_uint8(lhs.ptr, rhs.ptr, sks))
	case FheUint16:
		res.setPtr(C.bitand_fhe_uint16(lhs.ptr, rhs.ptr, sks))
	case FheUint32:
		res.setPtr(C.bitand_fhe_uint32(lhs.ptr, rhs.ptr, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) bitor(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	if !lhs.availableForOps() || !rhs.availableForOps() {
		panic("cannot bitwise OR on a non-initialized ciphertext")
	}

	if lhs.fheUintType != rhs.fheUintType {
		return nil, errors.New("binary operations are only well-defined for identical types")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.bitor_fhe_uint8(lhs.ptr, rhs.ptr, sks))
	case FheUint16:
		res.setPtr(C.bitor_fhe_uint16(lhs.ptr, rhs.ptr, sks))
	case FheUint32:
		res.setPtr(C.bitor_fhe_uint32(lhs.ptr, rhs.ptr, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) bitxor(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	if !lhs.availableForOps() || !rhs.availableForOps() {
		panic("cannot bitwise XOR on a non-initialized ciphertext")
	}

	if lhs.fheUintType != rhs.fheUintType {
		return nil, errors.New("binary operations are only well-defined for identical types")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.bitxor_fhe_uint8(lhs.ptr, rhs.ptr, sks))
	case FheUint16:
		res.setPtr(C.bitxor_fhe_uint16(lhs.ptr, rhs.ptr, sks))
	case FheUint32:
		res.setPtr(C.bitxor_fhe_uint32(lhs.ptr, rhs.ptr, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) shl(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	if !lhs.availableForOps() || !rhs.availableForOps() {
		panic("cannot shl on a non-initialized ciphertext")
	}

	if lhs.fheUintType != rhs.fheUintType {
		return nil, errors.New("binary operations are only well-defined for identical types")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.shl_fhe_uint8(lhs.ptr, rhs.ptr, sks))
	case FheUint16:
		res.setPtr(C.shl_fhe_uint16(lhs.ptr, rhs.ptr, sks))
	case FheUint32:
		res.setPtr(C.shl_fhe_uint32(lhs.ptr, rhs.ptr, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) scalarShl(rhs uint64) (*tfheCiphertext, error) {
	if !lhs.availableForOps() {
		panic("cannot scalar shl on a non-initialized ciphertext")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		pt := C.uint8_t(rhs)
		res.setPtr(C.scalar_shl_fhe_uint8(lhs.ptr, pt, sks))
	case FheUint16:
		pt := C.uint16_t(rhs)
		res.setPtr(C.scalar_shl_fhe_uint16(lhs.ptr, pt, sks))
	case FheUint32:
		pt := C.uint32_t(rhs)
		res.setPtr(C.scalar_shl_fhe_uint32(lhs.ptr, pt, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) shr(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	if !lhs.availableForOps() || !rhs.availableForOps() {
		panic("cannot shr on a non-initialized ciphertext")
	}

	if lhs.fheUintType != rhs.fheUintType {
		return nil, errors.New("binary operations are only well-defined for identical types")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.shr_fhe_uint8(lhs.ptr, rhs.ptr, sks))
	case FheUint16:
		res.setPtr(C.shr_fhe_uint16(lhs.ptr, rhs.ptr, sks))
	case FheUint32:
		res.setPtr(C.shr_fhe_uint32(lhs.ptr, rhs.ptr, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) scalarShr(rhs uint64) (*tfheCiphertext, error) {
	if !lhs.availableForOps() {
		panic("cannot scalar shr on a non-initialized ciphertext")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		pt := C.uint8_t(rhs)
		res.setPtr(C.scalar_shr_fhe_uint8(lhs.ptr, pt, sks))
	case FheUint16:
		pt := C.uint16_t(rhs)
		res.setPtr(C.scalar_shr_fhe_uint16(lhs.ptr, pt, sks))
	case FheUint32:
		pt := C.uint32_t(rhs)
		res.setPtr(C.scalar_shr_fhe_uint32(lhs.ptr, pt, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) eq(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	if !lhs.availableForOps() || !rhs.availableForOps() {
		panic("cannot eq on a non-initialized ciphertext")
	}

	if lhs.fheUintType != rhs.fheUintType {
		return nil, errors.New("binary operations are only well-defined for identical types")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.eq_fhe_uint8(lhs.ptr, rhs.ptr, sks))
	case FheUint16:
		res.setPtr(C.eq_fhe_uint16(lhs.ptr, rhs.ptr, sks))
	case FheUint32:
		res.setPtr(C.eq_fhe_uint32(lhs.ptr, rhs.ptr, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) scalarEq(rhs uint64) (*tfheCiphertext, error) {
	if !lhs.availableForOps() {
		panic("cannot scalar eq on a non-initialized ciphertext")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		pt := C.uint8_t(rhs)
		res.setPtr(C.scalar_eq_fhe_uint8(lhs.ptr, pt, sks))
	case FheUint16:
		pt := C.uint16_t(rhs)
		res.setPtr(C.scalar_eq_fhe_uint16(lhs.ptr, pt, sks))
	case FheUint32:
		pt := C.uint32_t(rhs)
		res.setPtr(C.scalar_eq_fhe_uint32(lhs.ptr, pt, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) ne(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	if !lhs.availableForOps() || !rhs.availableForOps() {
		panic("cannot ne on a non-initialized ciphertext")
	}

	if lhs.fheUintType != rhs.fheUintType {
		return nil, errors.New("binary operations are only well-defined for identical types")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.ne_fhe_uint8(lhs.ptr, rhs.ptr, sks))
	case FheUint16:
		res.setPtr(C.ne_fhe_uint16(lhs.ptr, rhs.ptr, sks))
	case FheUint32:
		res.setPtr(C.ne_fhe_uint32(lhs.ptr, rhs.ptr, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) scalarNe(rhs uint64) (*tfheCiphertext, error) {
	if !lhs.availableForOps() {
		panic("cannot scalar ne on a non-initialized ciphertext")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		pt := C.uint8_t(rhs)
		res.setPtr(C.scalar_ne_fhe_uint8(lhs.ptr, pt, sks))
	case FheUint16:
		pt := C.uint16_t(rhs)
		res.setPtr(C.scalar_ne_fhe_uint16(lhs.ptr, pt, sks))
	case FheUint32:
		pt := C.uint32_t(rhs)
		res.setPtr(C.scalar_ne_fhe_uint32(lhs.ptr, pt, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) ge(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	if !lhs.availableForOps() || !rhs.availableForOps() {
		panic("cannot ge on a non-initialized ciphertext")
	}

	if lhs.fheUintType != rhs.fheUintType {
		return nil, errors.New("binary operations are only well-defined for identical types")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.ge_fhe_uint8(lhs.ptr, rhs.ptr, sks))
	case FheUint16:
		res.setPtr(C.ge_fhe_uint16(lhs.ptr, rhs.ptr, sks))
	case FheUint32:
		res.setPtr(C.ge_fhe_uint32(lhs.ptr, rhs.ptr, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) scalarGe(rhs uint64) (*tfheCiphertext, error) {
	if !lhs.availableForOps() {
		panic("cannot scalar ge on a non-initialized ciphertext")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		pt := C.uint8_t(rhs)
		res.setPtr(C.scalar_ge_fhe_uint8(lhs.ptr, pt, sks))
	case FheUint16:
		pt := C.uint16_t(rhs)
		res.setPtr(C.scalar_ge_fhe_uint16(lhs.ptr, pt, sks))
	case FheUint32:
		pt := C.uint32_t(rhs)
		res.setPtr(C.scalar_ge_fhe_uint32(lhs.ptr, pt, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) gt(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	if !lhs.availableForOps() || !rhs.availableForOps() {
		panic("cannot gt on a non-initialized ciphertext")
	}

	if lhs.fheUintType != rhs.fheUintType {
		return nil, errors.New("binary operations are only well-defined for identical types")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.gt_fhe_uint8(lhs.ptr, rhs.ptr, sks))
	case FheUint16:
		res.setPtr(C.gt_fhe_uint16(lhs.ptr, rhs.ptr, sks))
	case FheUint32:
		res.setPtr(C.gt_fhe_uint32(lhs.ptr, rhs.ptr, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) scalarGt(rhs uint64) (*tfheCiphertext, error) {
	if !lhs.availableForOps() {
		panic("cannot scalar gt on a non-initialized ciphertext")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		pt := C.uint8_t(rhs)
		res.setPtr(C.scalar_gt_fhe_uint8(lhs.ptr, pt, sks))
	case FheUint16:
		pt := C.uint16_t(rhs)
		res.setPtr(C.scalar_gt_fhe_uint16(lhs.ptr, pt, sks))
	case FheUint32:
		pt := C.uint32_t(rhs)
		res.setPtr(C.scalar_gt_fhe_uint32(lhs.ptr, pt, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) le(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	if !lhs.availableForOps() || !rhs.availableForOps() {
		panic("cannot le on a non-initialized ciphertext")
	}

	if lhs.fheUintType != rhs.fheUintType {
		return nil, errors.New("binary operations are only well-defined for identical types")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.le_fhe_uint8(lhs.ptr, rhs.ptr, sks))
	case FheUint16:
		res.setPtr(C.le_fhe_uint16(lhs.ptr, rhs.ptr, sks))
	case FheUint32:
		res.setPtr(C.le_fhe_uint32(lhs.ptr, rhs.ptr, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) scalarLe(rhs uint64) (*tfheCiphertext, error) {
	if !lhs.availableForOps() {
		panic("cannot scalar le on a non-initialized ciphertext")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		pt := C.uint8_t(rhs)
		res.setPtr(C.scalar_le_fhe_uint8(lhs.ptr, pt, sks))
	case FheUint16:
		pt := C.uint16_t(rhs)
		res.setPtr(C.scalar_le_fhe_uint16(lhs.ptr, pt, sks))
	case FheUint32:
		pt := C.uint32_t(rhs)
		res.setPtr(C.scalar_le_fhe_uint32(lhs.ptr, pt, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) lt(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	if !lhs.availableForOps() || !rhs.availableForOps() {
		panic("cannot lt on a non-initialized ciphertext")
	}

	if lhs.fheUintType != rhs.fheUintType {
		return nil, errors.New("binary operations are only well-defined for identical types")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.lt_fhe_uint8(lhs.ptr, rhs.ptr, sks))
	case FheUint16:
		res.setPtr(C.lt_fhe_uint16(lhs.ptr, rhs.ptr, sks))
	case FheUint32:
		res.setPtr(C.lt_fhe_uint32(lhs.ptr, rhs.ptr, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) scalarLt(rhs uint64) (*tfheCiphertext, error) {
	if !lhs.availableForOps() {
		panic("cannot scalar lt on a non-initialized ciphertext")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		pt := C.uint8_t(rhs)
		res.setPtr(C.scalar_lt_fhe_uint8(lhs.ptr, pt, sks))
	case FheUint16:
		pt := C.uint16_t(rhs)
		res.setPtr(C.scalar_lt_fhe_uint16(lhs.ptr, pt, sks))
	case FheUint32:
		pt := C.uint32_t(rhs)
		res.setPtr(C.scalar_lt_fhe_uint32(lhs.ptr, pt, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) min(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	if !lhs.availableForOps() || !rhs.availableForOps() {
		panic("cannot min on a non-initialized ciphertext")
	}

	if lhs.fheUintType != rhs.fheUintType {
		return nil, errors.New("binary operations are only well-defined for identical types")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.min_fhe_uint8(lhs.ptr, rhs.ptr, sks))
	case FheUint16:
		res.setPtr(C.min_fhe_uint16(lhs.ptr, rhs.ptr, sks))
	case FheUint32:
		res.setPtr(C.min_fhe_uint32(lhs.ptr, rhs.ptr, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) scalarMin(rhs uint64) (*tfheCiphertext, error) {
	if !lhs.availableForOps() {
		panic("cannot scalar min on a non-initialized ciphertext")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		pt := C.uint8_t(rhs)
		res.setPtr(C.scalar_min_fhe_uint8(lhs.ptr, pt, sks))
	case FheUint16:
		pt := C.uint16_t(rhs)
		res.setPtr(C.scalar_min_fhe_uint16(lhs.ptr, pt, sks))
	case FheUint32:
		pt := C.uint32_t(rhs)
		res.setPtr(C.scalar_min_fhe_uint32(lhs.ptr, pt, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) max(rhs *tfheCiphertext) (*tfheCiphertext, error) {
	if !lhs.availableForOps() || !rhs.availableForOps() {
		panic("cannot max on a non-initialized ciphertext")
	}

	if lhs.fheUintType != rhs.fheUintType {
		return nil, errors.New("binary operations are only well-defined for identical types")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.max_fhe_uint8(lhs.ptr, rhs.ptr, sks))
	case FheUint16:
		res.setPtr(C.max_fhe_uint16(lhs.ptr, rhs.ptr, sks))
	case FheUint32:
		res.setPtr(C.max_fhe_uint32(lhs.ptr, rhs.ptr, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) scalarMax(rhs uint64) (*tfheCiphertext, error) {
	if !lhs.availableForOps() {
		panic("cannot scalar max on a non-initialized ciphertext")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		pt := C.uint8_t(rhs)
		res.setPtr(C.scalar_max_fhe_uint8(lhs.ptr, pt, sks))
	case FheUint16:
		pt := C.uint16_t(rhs)
		res.setPtr(C.scalar_max_fhe_uint16(lhs.ptr, pt, sks))
	case FheUint32:
		pt := C.uint32_t(rhs)
		res.setPtr(C.scalar_max_fhe_uint32(lhs.ptr, pt, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) neg() (*tfheCiphertext, error) {
	if !lhs.availableForOps() {
		panic("cannot neg on a non-initialized ciphertext")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.neg_fhe_uint8(lhs.ptr, sks))
	case FheUint16:
		res.setPtr(C.neg_fhe_uint16(lhs.ptr, sks))
	case FheUint32:
		res.setPtr(C.neg_fhe_uint32(lhs.ptr, sks))
	}
	return res, nil
}

func (lhs *tfheCiphertext) not() (*tfheCiphertext, error) {
	if !lhs.availableForOps() {
		panic("cannot not on a non-initialized ciphertext")
	}

	res := new(tfheCiphertext)
	res.fheUintType = lhs.fheUintType
	switch lhs.fheUintType {
	case FheUint8:
		res.setPtr(C.not_fhe_uint8(lhs.ptr, sks))
	case FheUint16:
		res.setPtr(C.not_fhe_uint16(lhs.ptr, sks))
	case FheUint32:
		res.setPtr(C.not_fhe_uint32(lhs.ptr, sks))
	}
	return res, nil
}

func (ct *tfheCiphertext) castTo(castToType fheUintType) (*tfheCiphertext, error) {
	if !ct.availableForOps() {
		panic("cannot cast a non-initialized ciphertext")
	}

	if ct.fheUintType == castToType {
		return nil, errors.New("casting to same type is not supported")
	}

	if !castToType.isValid() {
		return nil, errors.New("invalid type to cast to")
	}

	res := new(tfheCiphertext)
	res.fheUintType = castToType

	switch ct.fheUintType {
	case FheUint8:
		switch castToType {
		case FheUint16:
			res.setPtr(C.cast_8_16(ct.ptr, sks))
		case FheUint32:
			res.setPtr(C.cast_8_32(ct.ptr, sks))
		}
	case FheUint16:
		switch castToType {
		case FheUint8:
			res.setPtr(C.cast_16_8(ct.ptr, sks))
		case FheUint32:
			res.setPtr(C.cast_16_32(ct.ptr, sks))
		}
	case FheUint32:
		switch castToType {
		case FheUint8:
			res.setPtr(C.cast_32_8(ct.ptr, sks))
		case FheUint16:
			res.setPtr(C.cast_32_16(ct.ptr, sks))
		}
	}

	return res, nil
}

func (ct *tfheCiphertext) decrypt() big.Int {
	if !ct.availableForOps() {
		panic("cannot decrypt a null ciphertext")
	} else if ct.value != nil {
		return *ct.value
	}
	var value uint64
	switch ct.fheUintType {
	case FheUint8:
		value = uint64(C.decrypt_fhe_uint8(cks, ct.ptr))
	case FheUint16:
		value = uint64(C.decrypt_fhe_uint16(cks, ct.ptr))
	case FheUint32:
		value = uint64(C.decrypt_fhe_uint32(cks, ct.ptr))
	}
	ct.value = new(big.Int).SetUint64(value)
	return *ct.value
}

func (ct *tfheCiphertext) setPtr(ptr unsafe.Pointer) {
	if ptr == nil {
		panic("setPtr called with nil")
	}
	ct.ptr = ptr
	atomic.AddUint64(&allocatedCiphertexts, 1)
	switch ct.fheUintType {
	case FheUint8:
		runtime.SetFinalizer(ct, func(ct *tfheCiphertext) {
			C.destroy_fhe_uint8(ct.ptr)
		})
	case FheUint16:
		runtime.SetFinalizer(ct, func(ct *tfheCiphertext) {
			C.destroy_fhe_uint16(ct.ptr)
		})
	case FheUint32:
		runtime.SetFinalizer(ct, func(ct *tfheCiphertext) {
			C.destroy_fhe_uint32(ct.ptr)
		})
	}
}

func (ct *tfheCiphertext) getHash() common.Hash {
	if ct.hash != nil {
		return *ct.hash
	}
	if !ct.initialized() {
		panic("cannot get hash of non-initialized ciphertext")
	}
	hash := common.BytesToHash(crypto.Keccak256(ct.serialize()))
	ct.hash = &hash
	return *ct.hash
}

func (ct *tfheCiphertext) availableForOps() bool {
	return (ct.initialized() && ct.ptr != nil)
}

func (ct *tfheCiphertext) initialized() bool {
	return (ct.ptr != nil)
}

func (t *fheUintType) isValid() bool {
	return (*t <= 2)
}

// Used for testing.
func encryptAndSerializeCompact(value uint32, fheUintType fheUintType) []byte {
	out := &C.Buffer{}
	switch fheUintType {
	case FheUint8:
		C.public_key_encrypt_and_serialize_fhe_uint8_list(pks, C.uint8_t(value), out)
	case FheUint16:
		C.public_key_encrypt_and_serialize_fhe_uint16_list(pks, C.uint16_t(value), out)
	case FheUint32:
		C.public_key_encrypt_and_serialize_fhe_uint32_list(pks, C.uint32_t(value), out)
	}

	ser := C.GoBytes(unsafe.Pointer(out.pointer), C.int(out.length))
	C.destroy_buffer(out)
	return ser
}
