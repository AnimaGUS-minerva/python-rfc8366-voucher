#include "py/mpconfig.h"
#include "py/objstr.h"
#include "py/runtime.h"
#include "stdio.h"
#include "string.h"
#include "modvoucher.h"

#if MICROPY_PY_VOUCHER

typedef struct _mp_obj_vou_t {
    mp_obj_base_t base;
    vi_provider_t *provider;
} mp_obj_vou_t;

#define MP_OBJ_TO_PROVIDER_PTR(obj)  (((mp_obj_vou_t *) MP_OBJ_TO_PTR(obj))->provider)

STATIC mp_obj_t mp_vou_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args, bool is_vrq) {
    mp_arg_check_num(n_args, n_kw, 0, 0, false);

    mp_obj_vou_t *obj = m_new_obj_with_finaliser(mp_obj_vou_t);
    obj->base.type = type;
    vi_provider_allocate(&obj->provider, is_vrq);

    return MP_OBJ_FROM_PTR(obj);
}

STATIC mp_obj_t mp_vrq_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    return mp_vou_make_new(type, n_args, n_kw, args, true);
}

STATIC mp_obj_t mp_vch_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    return mp_vou_make_new(type, n_args, n_kw, args, false);
}

STATIC mp_obj_t mp_vou_from_cbor(mp_obj_t cbor) {
    if (!mp_obj_is_type(cbor, &mp_type_bytes)) {
        mp_raise_ValueError(MP_ERROR_TEXT("'cbor' arg must be <class 'bytes'>"));
    }
    GET_STR_DATA_LEN(cbor, str_data, str_len);

    mp_obj_vou_t *obj = m_new_obj_with_finaliser(mp_obj_vou_t);
    if (!vi_provider_allocate_from_cbor(&obj->provider, str_data, str_len)) {
        mp_raise_ValueError(MP_ERROR_TEXT("bad cbor voucher"));
    }
    obj->base.type = vi_provider_is_vrq(obj->provider) ?
        &voucher_vrq_type : &voucher_vch_type;

    return MP_OBJ_FROM_PTR(obj);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mp_vou_from_cbor_obj, mp_vou_from_cbor);

STATIC mp_obj_t into_obj_bytes(uint8_t **pp, size_t sz) {
    mp_obj_t obj;

    if (*pp != NULL) {
        obj = mp_obj_new_bytes(*pp, sz);
        free(*pp);
        *pp = NULL;
    } else {
        obj = mp_const_none;
    }

    return obj;
}

STATIC mp_obj_t mp_vou_to_cbor(mp_obj_t self_in) {
    uint8_t *ptr_heap;
    size_t sz_heap = vi_provider_to_cbor(MP_OBJ_TO_PROVIDER_PTR(self_in), &ptr_heap);

    mp_obj_t obj = into_obj_bytes(&ptr_heap, sz_heap);
    if (obj == mp_const_none) {
        mp_raise_ValueError(MP_ERROR_TEXT("'to_cbor' operation failed"));
    }

    return obj;
}
MP_DEFINE_CONST_FUN_OBJ_1(mp_vou_to_cbor_obj, mp_vou_to_cbor);

STATIC mp_obj_t mp_vou_init_psa_crypto(void) {
    printf("[modvoucher.c] mp_vou_init_psa_crypto(): ^^\n");

    vi_init_psa_crypto();

    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_0(mp_vou_init_psa_crypto_obj, mp_vou_init_psa_crypto);

//

STATIC mp_obj_t mp_vou_del(mp_obj_t self_in) {
    vi_provider_free(&MP_OBJ_TO_PROVIDER_PTR(self_in));

    return mp_const_none;
}
MP_DEFINE_CONST_FUN_OBJ_1(mp_vou_del_obj, mp_vou_del);

STATIC mp_obj_t mp_vou_dump(mp_obj_t self_in) {
    vi_provider_dump(MP_OBJ_TO_PROVIDER_PTR(self_in));

    return self_in;
}
MP_DEFINE_CONST_FUN_OBJ_1(mp_vou_dump_obj, mp_vou_dump);

STATIC mp_obj_t mp_vou_len(mp_obj_t self_in) {
    size_t len = vi_provider_len(MP_OBJ_TO_PROVIDER_PTR(self_in));

    return mp_obj_new_int_from_uint(len);
}
MP_DEFINE_CONST_FUN_OBJ_1(mp_vou_len_obj, mp_vou_len);

STATIC mp_obj_t mp_vou_set(mp_obj_t self_in, mp_obj_t attr_key, mp_obj_t attr_val) {
    vi_provider_t *ptr = MP_OBJ_TO_PROVIDER_PTR(self_in);
    mp_uint_t key = mp_obj_get_int(attr_key);

    // Note: py/obj.h
    //   #define mp_obj_is_type(o, t) (...) // this does not work for checking int, str or fun; use below macros for that
    //   ...
    bool result;
    if (mp_obj_is_int(attr_val)) { // Yang::{Enumeration,DateAndTime}
        mp_uint_t val = mp_obj_get_int(attr_val);
        result = vi_provider_set_attr_int(ptr, key, val);
    } else if (mp_obj_is_bool(attr_val)) { // Yang::Boolean
        bool val = mp_obj_get_int(attr_val);
        result = vi_provider_set_attr_bool(ptr, key, val);
    } else if (mp_obj_is_str(attr_val)) { // Yang::String
        GET_STR_DATA_LEN(attr_val, str_data, str_len);
        result = vi_provider_set_attr_bytes(ptr, key, str_data, str_len);
    } else if (mp_obj_is_type(attr_val, &mp_type_bytes)) { // Yang::Binary
        GET_STR_DATA_LEN(attr_val, str_data, str_len);
        result = vi_provider_set_attr_bytes(ptr, key, str_data, str_len);
    } else {
        mp_raise_ValueError(MP_ERROR_TEXT("invalid 'attr_val' type"));
    }

    if (!result) {
        mp_raise_msg_varg(&mp_type_ValueError,
            MP_ERROR_TEXT("'set' operation failed for attr key(%d)"), key);
    }

    return self_in;
}
MP_DEFINE_CONST_FUN_OBJ_3(mp_vou_set_obj, mp_vou_set);

STATIC mp_obj_t vou_get_inner(vi_provider_t *ptr, mp_uint_t key) {
    mp_obj_t obj;

    if (vi_provider_has_attr_int(ptr, key)) {
        obj = mp_obj_new_int_from_uint(vi_provider_get_attr_int_or_panic(ptr, key));
    } else if (vi_provider_has_attr_bool(ptr, key)) {
        obj = mp_obj_new_bool(vi_provider_get_attr_bool_or_panic(ptr, key));
    } else if (vi_provider_has_attr_bytes(ptr, key)) {
        uint8_t *ptr_heap;
        size_t sz_heap = vi_provider_get_attr_bytes_or_panic(ptr, key, &ptr_heap);
        mp_obj_t obj_bytes = into_obj_bytes(&ptr_heap, sz_heap);
        obj = obj_bytes != mp_const_none ? obj_bytes : mp_obj_new_bytes("", 0);
    } else {
        obj = mp_const_none;
    }

    return obj;
}

STATIC mp_obj_t mp_vou_get(mp_obj_t self_in, mp_obj_t attr_key) {
    return vou_get_inner(MP_OBJ_TO_PROVIDER_PTR(self_in), mp_obj_get_int(attr_key));
}
MP_DEFINE_CONST_FUN_OBJ_2(mp_vou_get_obj, mp_vou_get);

//

typedef struct _mp_obj_vou_iter_t {
    mp_obj_base_t base;
    mp_fun_1_t iternext;
    mp_obj_t vou;
    size_t cur;
} mp_obj_vou_iter_t;

STATIC mp_obj_t vou_iterernext(mp_obj_t self_in) {
    mp_obj_vou_iter_t *self = MP_OBJ_TO_PTR(self_in);
    vi_provider_t *ptr = MP_OBJ_TO_PROVIDER_PTR(self->vou);

    mp_obj_t obj;
    if (self->cur < vi_provider_len(ptr)) {
        mp_uint_t key = vi_provider_attr_key_at(ptr, self->cur);
        self->cur += 1;

        mp_obj_t tpl[2] = { mp_obj_new_int_from_uint(key), vou_get_inner(ptr, key) };
        obj = mp_obj_new_tuple(2, tpl);
    } else {
        obj = MP_OBJ_STOP_ITERATION;
    }

    return obj;
}

STATIC mp_obj_t mp_vou_getiter(mp_obj_t self_in, mp_obj_iter_buf_t *iter_buf) {
    assert(sizeof(mp_obj_vou_iter_t) <= sizeof(mp_obj_iter_buf_t));

    mp_obj_vou_iter_t *obj_iter = (mp_obj_vou_iter_t *)iter_buf;
    obj_iter->base.type = &mp_type_polymorph_iter;
    obj_iter->iternext = vou_iterernext;
    obj_iter->vou = self_in;
    obj_iter->cur = 0;

    return MP_OBJ_FROM_PTR(obj_iter);
}

STATIC mp_obj_t mp_vou_subscr(mp_obj_t self_in, mp_obj_t attr_key, mp_obj_t attr_val) {
    if (mp_obj_is_type(attr_key, &mp_type_slice)) {
        mp_raise_ValueError(MP_ERROR_TEXT("slicing is not supported"));
    }

    return attr_val == MP_OBJ_SENTINEL ?
        mp_vou_get(self_in, attr_key) :
        mp_vou_set(self_in, attr_key, attr_val);
}

//

STATIC mp_obj_t mp_vou_remove(mp_obj_t self_in, mp_obj_t attr_key) {
    vi_provider_t *ptr = MP_OBJ_TO_PROVIDER_PTR(self_in);
    mp_uint_t key = mp_obj_get_int(attr_key);

    return mp_obj_new_bool(vi_provider_remove_attr(ptr, key));
}
MP_DEFINE_CONST_FUN_OBJ_2(mp_vou_remove_obj, mp_vou_remove);

STATIC mp_obj_t mp_vou_sign(mp_obj_t self_in, mp_obj_t privkey_pem, mp_obj_t alg_in) {
    if (!mp_obj_is_type(privkey_pem, &mp_type_bytes)) {
        mp_raise_ValueError(MP_ERROR_TEXT("'pem' arg must be <class 'bytes'>"));
    }
    GET_STR_DATA_LEN(privkey_pem, str_data, str_len);

    mp_uint_t alg = mp_obj_get_int(alg_in);
    if (!vi_provider_sign(MP_OBJ_TO_PROVIDER_PTR(self_in), str_data, str_len, alg)) {
        mp_raise_msg_varg(&mp_type_ValueError,
            MP_ERROR_TEXT("'sign' operation failed for alg(%d)"), alg);
    }

    return self_in;
}
MP_DEFINE_CONST_FUN_OBJ_3(mp_vou_sign_obj, mp_vou_sign);

STATIC mp_obj_t mp_vou_validate(size_t n_args, const mp_obj_t *args) {
    bool result;
    vi_provider_t *ptr = MP_OBJ_TO_PROVIDER_PTR(args[0]);
    if (n_args == 1) { // without PEM (`signer_cert` is used instead)
        result = vi_provider_validate(ptr);
    } else { // with PEM
        if (!mp_obj_is_type(args[1], &mp_type_bytes)) {
            mp_raise_ValueError(MP_ERROR_TEXT("'pem' arg must be <class 'bytes'>"));
        }
        GET_STR_DATA_LEN(args[1], str_data, str_len);
        result = vi_provider_validate_with_pem(ptr, str_data, str_len);
    }

    return mp_obj_new_bool(result);
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mp_vou_validate_obj, 1, 2, mp_vou_validate);

//

STATIC mp_obj_t mp_vou_get_signer_cert(mp_obj_t self_in) {
    uint8_t *ptr_heap;
    size_t sz_heap = vi_provider_get_signer_cert(MP_OBJ_TO_PROVIDER_PTR(self_in), &ptr_heap);

    return into_obj_bytes(&ptr_heap, sz_heap);
}
MP_DEFINE_CONST_FUN_OBJ_1(mp_vou_get_signer_cert_obj, mp_vou_get_signer_cert);

STATIC mp_obj_t mp_vou_set_signer_cert(mp_obj_t self_in, mp_obj_t cert) {
    vi_provider_t *ptr = MP_OBJ_TO_PROVIDER_PTR(self_in);

    if (mp_obj_is_type(cert, &mp_type_bytes)) {
        GET_STR_DATA_LEN(cert, str_data, str_len);
        vi_provider_set_signer_cert(ptr, str_data, str_len);
    } else {
        mp_raise_ValueError(MP_ERROR_TEXT("'cert' type must be bytes"));
    }

    return self_in;
}
MP_DEFINE_CONST_FUN_OBJ_2(mp_vou_set_signer_cert_obj, mp_vou_set_signer_cert);

STATIC mp_obj_t mp_vou_get_content(mp_obj_t self_in) {
    uint8_t *ptr_heap;
    size_t sz_heap = vi_provider_get_content(MP_OBJ_TO_PROVIDER_PTR(self_in), &ptr_heap);

    return into_obj_bytes(&ptr_heap, sz_heap);
}
MP_DEFINE_CONST_FUN_OBJ_1(mp_vou_get_content_obj, mp_vou_get_content);

STATIC mp_obj_t mp_vou_get_signature(mp_obj_t self_in) {
    uint8_t *ptr_heap;
    size_t sz_heap = vi_provider_get_signature_bytes(MP_OBJ_TO_PROVIDER_PTR(self_in), &ptr_heap);

    return into_obj_bytes(&ptr_heap, sz_heap);
}
MP_DEFINE_CONST_FUN_OBJ_1(mp_vou_get_signature_obj, mp_vou_get_signature);

STATIC int8_t vou_get_signature_alg(vi_provider_t *ptr) {
    return vi_provider_get_signature_alg(ptr);
}

STATIC mp_obj_t mp_vou_get_signature_alg(mp_obj_t self_in) {
    int8_t alg = vou_get_signature_alg(MP_OBJ_TO_PROVIDER_PTR(self_in));

    return alg >= 0 ? mp_obj_new_int(alg) : mp_const_none;
}
MP_DEFINE_CONST_FUN_OBJ_1(mp_vou_get_signature_alg_obj, mp_vou_get_signature_alg);

//

STATIC const char * attr_key_to_str(uint8_t attr_key) {
    switch (attr_key) {
        case ATTR_ASSERTION:                       return "ATTR_ASSERTION";
        case ATTR_CREATED_ON:                      return "ATTR_CREATED_ON";
        case ATTR_DOMAIN_CERT_REVOCATION_CHECKS:   return "ATTR_DOMAIN_CERT_REVOCATION_CHECKS";
        case ATTR_EXPIRES_ON:                      return "ATTR_EXPIRES_ON";
        case ATTR_IDEVID_ISSUER:                   return "ATTR_IDEVID_ISSUER";
        case ATTR_LAST_RENEWAL_DATE:               return "ATTR_LAST_RENEWAL_DATE";
        case ATTR_NONCE:                           return "ATTR_NONCE";
        case ATTR_PINNED_DOMAIN_CERT:              return "ATTR_PINNED_DOMAIN_CERT";
        case ATTR_PINNED_DOMAIN_PUBK:              return "ATTR_PINNED_DOMAIN_PUBK";
        case ATTR_PINNED_DOMAIN_PUBK_SHA256:       return "ATTR_PINNED_DOMAIN_PUBK_SHA256";
        case ATTR_PRIOR_SIGNED_VOUCHER_REQUEST:    return "ATTR_PRIOR_SIGNED_VOUCHER_REQUEST";
        case ATTR_PROXIMITY_REGISTRAR_CERT:        return "ATTR_PROXIMITY_REGISTRAR_CERT";
        case ATTR_PROXIMITY_REGISTRAR_PUBK:        return "ATTR_PROXIMITY_REGISTRAR_PUBK";
        case ATTR_PROXIMITY_REGISTRAR_PUBK_SHA256: return "ATTR_PROXIMITY_REGISTRAR_PUBK_SHA256";
        case ATTR_SERIAL_NUMBER:                   return "ATTR_SERIAL_NUMBER";
    }
    return "unknown";
}

STATIC const char * attr_assertion_to_str(uint8_t assertion) {
    switch (assertion) {
        case ASSERTION_VERIFIED:  return "ASSERTION_VERIFIED";
        case ASSERTION_LOGGED:    return "ASSERTION_LOGGED";
        case ASSERTION_PROXIMITY: return "ASSERTION_PROXIMITY";
    }
    return "unknown";
}

STATIC const char * signature_alg_to_str(int8_t alg) {
    switch (alg) {
        case SA_ES256: return "SA_ES256";
        case SA_ES384: return "SA_ES384";
        case SA_ES512: return "SA_ES512";
        case SA_PS256: return "SA_PS256";
    }
    return "unknown";
}

STATIC void mp_vou_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind) {
    vi_provider_t *ptr = MP_OBJ_TO_PROVIDER_PTR(self_in);

    mp_print_str(print, "voucher type: ");
    mp_print_str(print, vi_provider_is_vrq(ptr) ? "'vrq'" : "'vch'");

    size_t len = vi_provider_len(ptr);
    mp_print_str(print, "\n# of attributes: ");
    mp_obj_print_helper(print, mp_obj_new_int(len), PRINT_REPR);
    mp_print_str(print, "\n");

    for (size_t idx = 0; idx < len; idx++) {
        mp_uint_t key = vi_provider_attr_key_at(ptr, idx);

        mp_print_str(print, "  [");
        mp_print_str(print, attr_key_to_str(key));
        mp_print_str(print, "] ");
        if (key == ATTR_ASSERTION) {
            mp_print_str(print,
                attr_assertion_to_str(vi_provider_get_attr_int_or_panic(ptr, key)));
        } else {
            mp_obj_print_helper(print, vou_get_inner(ptr, key), PRINT_REPR);
        }

        if (idx < len - 1) mp_print_str(print, "\n");
    }

    mp_print_str(print, "\nCOSE signature algorithm: ");
    int8_t alg = vou_get_signature_alg(ptr);
    mp_print_str(print, alg >= 0 ? signature_alg_to_str(alg) : "None");

    mp_print_str(print, "\nCOSE signature: ");
    mp_obj_print_helper(print, mp_vou_get_signature(self_in), PRINT_REPR);

    mp_print_str(print, "\nCOSE content: ");
    mp_obj_print_helper(print, mp_vou_get_content(self_in), PRINT_REPR);
}

//

const mp_rom_map_elem_t voucher_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR___del__), MP_ROM_PTR(&mp_vou_del_obj) },
    { MP_ROM_QSTR(MP_QSTR_to_cbor), MP_ROM_PTR(&mp_vou_to_cbor_obj) },
    { MP_ROM_QSTR(MP_QSTR_len), MP_ROM_PTR(&mp_vou_len_obj) },
    { MP_ROM_QSTR(MP_QSTR_set), MP_ROM_PTR(&mp_vou_set_obj) },
    { MP_ROM_QSTR(MP_QSTR_get), MP_ROM_PTR(&mp_vou_get_obj) },
    { MP_ROM_QSTR(MP_QSTR_remove), MP_ROM_PTR(&mp_vou_remove_obj) },
    { MP_ROM_QSTR(MP_QSTR_sign), MP_ROM_PTR(&mp_vou_sign_obj) },
    { MP_ROM_QSTR(MP_QSTR_validate), MP_ROM_PTR(&mp_vou_validate_obj) },
    { MP_ROM_QSTR(MP_QSTR_get_signer_cert), MP_ROM_PTR(&mp_vou_get_signer_cert_obj) },
    { MP_ROM_QSTR(MP_QSTR_set_signer_cert), MP_ROM_PTR(&mp_vou_set_signer_cert_obj) },
    { MP_ROM_QSTR(MP_QSTR_get_content), MP_ROM_PTR(&mp_vou_get_content_obj) },
    { MP_ROM_QSTR(MP_QSTR_get_signature), MP_ROM_PTR(&mp_vou_get_signature_obj) },
    { MP_ROM_QSTR(MP_QSTR_get_signature_alg), MP_ROM_PTR(&mp_vou_get_signature_alg_obj) },
#if MICROPY_PY_VOUCHER_DEBUG
    { MP_ROM_QSTR(MP_QSTR_debug_dump), MP_ROM_PTR(&mp_vou_dump_obj) },
#endif
};

MP_DEFINE_CONST_DICT(voucher_locals_dict, voucher_locals_dict_table);

const mp_obj_type_t voucher_vrq_type = {
    { &mp_type_type },
    .name = MP_QSTR_vrq,
    .make_new = mp_vrq_make_new,
    .getiter = mp_vou_getiter,
    .subscr = mp_vou_subscr,
    .print = mp_vou_print,
    .locals_dict = (void*)&voucher_locals_dict,
};

const mp_obj_type_t voucher_vch_type = {
    { &mp_type_type },
    .name = MP_QSTR_vch,
    .make_new = mp_vch_make_new,
    .getiter = mp_vou_getiter,
    .subscr = mp_vou_subscr,
    .print = mp_vou_print,
    .locals_dict = (void*)&voucher_locals_dict,
};

//

STATIC const mp_rom_map_elem_t mp_module_voucher_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_voucher) },
    { MP_ROM_QSTR(MP_QSTR_vrq), MP_ROM_PTR(&voucher_vrq_type) },
    { MP_ROM_QSTR(MP_QSTR_vch), MP_ROM_PTR(&voucher_vch_type) },
//todo    { MP_ROM_QSTR(MP_QSTR_Vrq), MP_ROM_PTR(&voucher_vrq_type) },
//todo    { MP_ROM_QSTR(MP_QSTR_Vch), MP_ROM_PTR(&voucher_vch_type) },
    { MP_ROM_QSTR(MP_QSTR_from_cbor), MP_ROM_PTR(&mp_vou_from_cbor_obj) },
    { MP_ROM_QSTR(MP_QSTR_init_psa_crypto), MP_ROM_PTR(&mp_vou_init_psa_crypto_obj) },
    { MP_ROM_QSTR(MP_QSTR_ATTR_ASSERTION), MP_ROM_INT(ATTR_ASSERTION) },
    { MP_ROM_QSTR(MP_QSTR_ATTR_CREATED_ON), MP_ROM_INT(ATTR_CREATED_ON) },
    { MP_ROM_QSTR(MP_QSTR_ATTR_DOMAIN_CERT_REVOCATION_CHECKS), MP_ROM_INT(ATTR_DOMAIN_CERT_REVOCATION_CHECKS) },
    { MP_ROM_QSTR(MP_QSTR_ATTR_EXPIRES_ON), MP_ROM_INT(ATTR_EXPIRES_ON) },
    { MP_ROM_QSTR(MP_QSTR_ATTR_IDEVID_ISSUER), MP_ROM_INT(ATTR_IDEVID_ISSUER) },
    { MP_ROM_QSTR(MP_QSTR_ATTR_LAST_RENEWAL_DATE), MP_ROM_INT(ATTR_LAST_RENEWAL_DATE) },
    { MP_ROM_QSTR(MP_QSTR_ATTR_NONCE), MP_ROM_INT(ATTR_NONCE) },
    { MP_ROM_QSTR(MP_QSTR_ATTR_PINNED_DOMAIN_CERT), MP_ROM_INT(ATTR_PINNED_DOMAIN_CERT) },
    { MP_ROM_QSTR(MP_QSTR_ATTR_PINNED_DOMAIN_PUBK), MP_ROM_INT(ATTR_PINNED_DOMAIN_PUBK) },
    { MP_ROM_QSTR(MP_QSTR_ATTR_PINNED_DOMAIN_PUBK_SHA256), MP_ROM_INT(ATTR_PINNED_DOMAIN_PUBK_SHA256) },
    { MP_ROM_QSTR(MP_QSTR_ATTR_PRIOR_SIGNED_VOUCHER_REQUEST), MP_ROM_INT(ATTR_PRIOR_SIGNED_VOUCHER_REQUEST) },
    { MP_ROM_QSTR(MP_QSTR_ATTR_PROXIMITY_REGISTRAR_CERT), MP_ROM_INT(ATTR_PROXIMITY_REGISTRAR_CERT) },
    { MP_ROM_QSTR(MP_QSTR_ATTR_PROXIMITY_REGISTRAR_PUBK), MP_ROM_INT(ATTR_PROXIMITY_REGISTRAR_PUBK) },
    { MP_ROM_QSTR(MP_QSTR_ATTR_PROXIMITY_REGISTRAR_PUBK_SHA256), MP_ROM_INT(ATTR_PROXIMITY_REGISTRAR_PUBK_SHA256) },
    { MP_ROM_QSTR(MP_QSTR_ATTR_SERIAL_NUMBER), MP_ROM_INT(ATTR_SERIAL_NUMBER) },
    { MP_ROM_QSTR(MP_QSTR_ASSERTION_VERIFIED), MP_ROM_INT(ASSERTION_VERIFIED) },
    { MP_ROM_QSTR(MP_QSTR_ASSERTION_LOGGED), MP_ROM_INT(ASSERTION_LOGGED) },
    { MP_ROM_QSTR(MP_QSTR_ASSERTION_PROXIMITY), MP_ROM_INT(ASSERTION_PROXIMITY) },
    { MP_ROM_QSTR(MP_QSTR_SA_ES256), MP_ROM_INT(SA_ES256) },
    { MP_ROM_QSTR(MP_QSTR_SA_ES384), MP_ROM_INT(SA_ES384) },
    { MP_ROM_QSTR(MP_QSTR_SA_ES512), MP_ROM_INT(SA_ES512) },
    { MP_ROM_QSTR(MP_QSTR_SA_PS256), MP_ROM_INT(SA_PS256) },
#if MICROPY_PY_VOUCHER_DEBUG
    { MP_ROM_QSTR(MP_QSTR_debug_demo), MP_ROM_PTR(&debug_demo_obj) },
    { MP_ROM_QSTR(MP_QSTR_debug_test_ffi), MP_ROM_PTR(&debug_test_ffi_obj) },
    { MP_ROM_QSTR(MP_QSTR_debug_get_vch_jada), MP_ROM_PTR(&debug_get_vch_jada_obj) },
    { MP_ROM_QSTR(MP_QSTR_debug_get_vch_F2_00_02), MP_ROM_PTR(&debug_get_vch_F2_00_02_obj) },
    { MP_ROM_QSTR(MP_QSTR_debug_get_masa_pem_F2_00_02), MP_ROM_PTR(&debug_get_masa_pem_F2_00_02_obj) },
    { MP_ROM_QSTR(MP_QSTR_debug_get_key_pem_F2_00_02), MP_ROM_PTR(&debug_get_key_pem_F2_00_02_obj) },
    { MP_ROM_QSTR(MP_QSTR_debug_get_device_crt_F2_00_02), MP_ROM_PTR(&debug_get_device_crt_F2_00_02_obj) },
    { MP_ROM_QSTR(MP_QSTR_debug_get_vrq_F2_00_02), MP_ROM_PTR(&debug_get_vrq_F2_00_02_obj) },
    { MP_ROM_QSTR(MP_QSTR_debug_create_vrq_F2_00_02), MP_ROM_PTR(&debug_create_vrq_F2_00_02_obj) },
    { MP_ROM_QSTR(MP_QSTR_debug_parse), MP_ROM_PTR(&debug_parse_obj) },
    { MP_ROM_QSTR(MP_QSTR_debug_validate), MP_ROM_PTR(&debug_validate_obj) },
    { MP_ROM_QSTR(MP_QSTR_debug_sign), MP_ROM_PTR(&debug_sign_obj) },
#endif
};

STATIC MP_DEFINE_CONST_DICT(mp_module_voucher_globals, mp_module_voucher_globals_table);

const mp_obj_module_t mp_module_voucher = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t*)&mp_module_voucher_globals,
};

#endif // MICROPY_PY_VOUCHER
