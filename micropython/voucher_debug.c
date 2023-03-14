#include "py/mpconfig.h"
#include "py/objstr.h"
#include "py/runtime.h"
#include "stdio.h"
#include "string.h"
#include "modvoucher.h"

#if MICROPY_PY_VOUCHER_DEBUG

STATIC mp_obj_t demo(void) {
    printf("[voucher_debug.c] demo(): ^^\n");

    return mp_const_none;
}
MP_DEFINE_CONST_FUN_OBJ_0(debug_demo_obj, demo);

STATIC mp_obj_t test_ffi(void) {
    printf("[voucher_debug.c] test_ffi(): ^^\n");

    { // basic stuff
        int input = 4;
        int output = vi_square(input);
        printf("input: %d output: %d\n", input, output);
    }

    // return misc types

    uint8_t mac[6] = { 0xA0, 0xB1, 0xC2, 0xD3, 0xE4, 0xF5 };
    uint8_t mac2[6] = { 0x00, 0xB1, 0xC2, 0xD3, 0xE4, 0xF5 };

#define SZ 7
    mp_obj_t tuple[SZ] = {
        MP_OBJ_NEW_SMALL_INT(42), // 42
        mp_obj_new_bool(1 == 0), // False
        mp_const_none, // None
        mp_const_true, // True
        mp_const_false, // False
        mp_obj_new_bytes(mac, sizeof(mac)), // b'\xa0\xb1\xc2\xd3\xe4\xf5'
        mp_obj_new_bool(memcmp(mac2, mac, sizeof(mac)) == 0), // False
    };
    printf("sizeof(tuple): %d\n", sizeof(tuple));

    return mp_obj_new_tuple(SZ, tuple);
}
MP_DEFINE_CONST_FUN_OBJ_0(debug_test_ffi_obj, test_ffi);

STATIC mp_obj_t get_vch_jada(void) {
    uint8_t *ptr_static;
    size_t sz;

    sz = vi_get_voucher_jada(&ptr_static);
    return mp_obj_new_bytes(ptr_static, sz);
}
MP_DEFINE_CONST_FUN_OBJ_0(debug_get_vch_jada_obj, get_vch_jada);

STATIC mp_obj_t get_vch_F2_00_02(void) {
    uint8_t *ptr_static;
    size_t sz;

    sz = vi_get_voucher_F2_00_02(&ptr_static);
    return mp_obj_new_bytes(ptr_static, sz);
}
MP_DEFINE_CONST_FUN_OBJ_0(debug_get_vch_F2_00_02_obj, get_vch_F2_00_02);

STATIC mp_obj_t get_masa_pem_F2_00_02(void) {
    uint8_t *ptr_static;
    size_t sz;

    sz = vi_get_masa_pem_F2_00_02(&ptr_static);
    return mp_obj_new_bytes(ptr_static, sz);
}
MP_DEFINE_CONST_FUN_OBJ_0(debug_get_masa_pem_F2_00_02_obj, get_masa_pem_F2_00_02);

STATIC mp_obj_t get_key_pem_F2_00_02(void) {
    uint8_t *ptr_static;
    size_t sz;

    sz = vi_get_key_pem_F2_00_02(&ptr_static);
    return mp_obj_new_bytes(ptr_static, sz);
}
MP_DEFINE_CONST_FUN_OBJ_0(debug_get_key_pem_F2_00_02_obj, get_key_pem_F2_00_02);

STATIC mp_obj_t get_device_crt_F2_00_02(void) {
    uint8_t *ptr_static;
    size_t sz;

    sz = vi_get_device_crt_F2_00_02(&ptr_static);
    return mp_obj_new_bytes(ptr_static, sz);
}
MP_DEFINE_CONST_FUN_OBJ_0(debug_get_device_crt_F2_00_02_obj, get_device_crt_F2_00_02);

STATIC mp_obj_t get_vrq_F2_00_02(void) {
    uint8_t *ptr_static;
    size_t sz;

    sz = vi_get_vrq_F2_00_02(&ptr_static);
    return mp_obj_new_bytes(ptr_static, sz);
}
MP_DEFINE_CONST_FUN_OBJ_0(debug_get_vrq_F2_00_02_obj, get_vrq_F2_00_02);

STATIC mp_obj_t create_vrq_F2_00_02(void) {
    uint8_t *ptr_heap;
    size_t sz_heap;
    mp_obj_t obj;

    sz_heap = vi_create_vrq_F2_00_02(&ptr_heap);
    obj = mp_obj_new_bytes(ptr_heap, sz_heap);
    free(ptr_heap);

    return obj;
}
MP_DEFINE_CONST_FUN_OBJ_0(debug_create_vrq_F2_00_02_obj, create_vrq_F2_00_02);

STATIC mp_obj_t sign(mp_obj_t bs_vch, mp_obj_t bs_key, mp_obj_t alg) {
    if (mp_obj_is_type(bs_vch, &mp_type_bytes) &&
        mp_obj_is_type(bs_key, &mp_type_bytes)) {
        uint8_t *ptr_raw, *ptr_key, *ptr_heap;
        size_t sz_raw, sz_key, sz_heap;
        mp_obj_t obj;

        {
            GET_STR_DATA_LEN(bs_vch, str_data, str_len);
            ptr_raw = (uint8_t *)str_data;
            sz_raw = str_len;
        }

        {
            GET_STR_DATA_LEN(bs_key, str_data, str_len);
            ptr_key = (uint8_t *)str_data;
            sz_key = str_len;
        }

        sz_heap = vi_sign(ptr_raw, sz_raw, ptr_key, sz_key, &ptr_heap, mp_obj_get_int(alg));
        obj = mp_obj_new_bytes(ptr_heap, sz_heap);
        free(ptr_heap);

        return obj;
    } else {
        mp_raise_ValueError(MP_ERROR_TEXT("both 'voucher' and 'key' args must be <class 'bytes'>"));
    }
}
MP_DEFINE_CONST_FUN_OBJ_3(debug_sign_obj, sign);

STATIC mp_obj_t parse(mp_obj_t self_in) {
    if (mp_obj_is_type(self_in, &mp_type_bytes)) {
        GET_STR_DATA_LEN(self_in, str_data, str_len);
        vi_dump(str_data, str_len);
        return mp_const_none;
    } else {
        mp_raise_ValueError(MP_ERROR_TEXT("'voucher' arg must be <class 'bytes'>"));
    }
}
MP_DEFINE_CONST_FUN_OBJ_1(debug_parse_obj, parse);

STATIC mp_obj_t validate(size_t n_args, const mp_obj_t *args) {
    // printf("[voucher_debug.c] validate(): n_args: %d\n", n_args);

    if (n_args == 1) {
        if (mp_obj_is_type(args[0], &mp_type_bytes)) {
            GET_STR_DATA_LEN(args[0], str_data, str_len);
            return mp_obj_new_bool(vi_validate(str_data, str_len));
        } else {
            mp_raise_ValueError(MP_ERROR_TEXT("'voucher' arg must be <class 'bytes'>"));
        }
    } else { // with MASA pem
        if (mp_obj_is_type(args[0], &mp_type_bytes) &&
            mp_obj_is_type(args[1], &mp_type_bytes)) {
            uint8_t *ptr, *ptr_pem;
            size_t sz, sz_pem;

            {
                GET_STR_DATA_LEN(args[0], str_data, str_len);
                ptr = (uint8_t *)str_data;
                sz = str_len;
            }

            {
                GET_STR_DATA_LEN(args[1], str_data, str_len);
                ptr_pem = (uint8_t *)str_data;
                sz_pem = str_len;
            }

            return mp_obj_new_bool(vi_validate_with_pem(ptr, sz, ptr_pem, sz_pem));
        } else {
            mp_raise_ValueError(MP_ERROR_TEXT("both 'voucher' and 'pem' args must be <class 'bytes'>"));
        }
    }
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(debug_validate_obj, 1, 2, validate);

#endif // MICROPY_PY_VOUCHER_DEBUG