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

void client_key_encrypt_and_ser_fhe_uint8(void* cks, uint8_t value, Buffer* out) {
FheUint8* ct = NULL;

const int encrypt_ok = fhe_uint8_try_encrypt_with_client_key_u8(value, cks, &ct);
assert(encrypt_ok == 0);

const int ser_ok = fhe_uint8_serialize(ct, out);
assert(ser_ok == 0);

fhe_uint8_destroy(ct);
}

void client_key_encrypt_and_ser_fhe_uint16(void* cks, uint16_t value, Buffer* out) {
FheUint16* ct = NULL;

const int encrypt_ok = fhe_uint16_try_encrypt_with_client_key_u16(value, cks, &ct);
assert(encrypt_ok == 0);

const int ser_ok = fhe_uint16_serialize(ct, out);
assert(ser_ok == 0);

fhe_uint16_destroy(ct);
}

void client_key_encrypt_and_ser_fhe_uint32(void* cks, uint32_t value, Buffer* out) {
FheUint32* ct = NULL;

const int encrypt_ok = fhe_uint32_try_encrypt_with_client_key_u32(value, cks, &ct);
assert(encrypt_ok == 0);

const int ser_ok = fhe_uint32_serialize(ct, out);
assert(ser_ok == 0);

fhe_uint32_destroy(ct);
}

void* client_key_encrypt_fhe_uint8(void* cks, uint8_t value) {
FheUint8* ct = NULL;

const int r = fhe_uint8_try_encrypt_with_client_key_u8(value, cks, &ct);
assert(r == 0);

return ct;
}

void* client_key_encrypt_fhe_uint16(void* cks, uint16_t value) {
FheUint16* ct = NULL;

const int r = fhe_uint16_try_encrypt_with_client_key_u16(value, cks, &ct);
assert(r == 0);

return ct;
}

void* client_key_encrypt_fhe_uint32(void* cks, uint32_t value) {
FheUint32* ct = NULL;

const int r = fhe_uint32_try_encrypt_with_client_key_u32(value, cks, &ct);
assert(r == 0);

return ct;
}

void public_key_encrypt_fhe_uint8(BufferView pks_buf, uint8_t value, Buffer* out)
{
FheUint8 *ct = NULL;
PublicKey *pks = NULL;

const int deser_ok = public_key_deserialize(pks_buf, &pks);
assert(deser_ok == 0);

const int encrypt_ok = fhe_uint8_try_encrypt_with_public_key_u8(value, pks, &ct);
assert(encrypt_ok == 0);

const int ser_ok = fhe_uint8_serialize(ct, out);
assert(ser_ok == 0);

public_key_destroy(pks);
fhe_uint8_destroy(ct);
}

void public_key_encrypt_fhe_uint16(BufferView pks_buf, uint16_t value, Buffer* out)
{
FheUint16 *ct = NULL;
PublicKey *pks = NULL;

const int deser_ok = public_key_deserialize(pks_buf, &pks);
assert(deser_ok == 0);

const int encrypt_ok = fhe_uint16_try_encrypt_with_public_key_u16(value, pks, &ct);
assert(encrypt_ok == 0);

const int ser_ok = fhe_uint16_serialize(ct, out);
assert(ser_ok == 0);

public_key_destroy(pks);
fhe_uint16_destroy(ct);
}

void public_key_encrypt_fhe_uint32(BufferView pks_buf, uint32_t value, Buffer* out)
{
FheUint32 *ct = NULL;
PublicKey *pks = NULL;

const int deser_ok = public_key_deserialize(pks_buf, &pks);
assert(deser_ok == 0);

const int encrypt_ok = fhe_uint32_try_encrypt_with_public_key_u32(value, pks, &ct);
assert(encrypt_ok == 0);

const int ser_ok = fhe_uint32_serialize(ct, out);
assert(ser_ok == 0);

public_key_destroy(pks);
fhe_uint32_destroy(ct);
}