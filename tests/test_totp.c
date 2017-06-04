/*
 * Copyright Rodolphe Breard (2015)
 * Author: Rodolphe Breard (2015)
 *
 * This software is a computer program whose purpose is to [describe
 * functionalities and technical features of your software].
 *
 * This software is governed by the CeCILL  license under French law and
 * abiding by the rules of distribution of free software.  You can  use,
 * modify and/ or redistribute the software under the terms of the CeCILL
 * license as circulated by CEA, CNRS and INRIA at the following URL
 * "http://www.cecill.info".
 *
 * As a counterpart to the access to the source code and  rights to copy,
 * modify and redistribute granted by the license, users are provided only
 * with a limited warranty  and the software's author,  the holder of the
 * economic rights,  and the successive licensors  have only  limited
 * liability.
 *
 * In this respect, the user's attention is drawn to the risks associated
 * with loading,  using,  modifying and/or developing or reproducing the
 * software by the user in light of its specific status of free software,
 * that may mean  that it is complicated to manipulate,  and  that  also
 * therefore means  that it is reserved for developers  and  experienced
 * professionals having in-depth computer knowledge. Users are therefore
 * encouraged to load and test the software's suitability as regards their
 * requirements in conditions enabling the security of their systems and/or
 * data to be ensured and,  more generally, to use and operate it in the
 * same conditions as regards security.
 *
 * The fact that you are presently reading this means that you have had
 * knowledge of the CeCILL license and that you accept its terms.
 */


#include <strings.h>
#include <string.h>
#include <assert.h>
#include <boringauth.h>
#include "boringauth_tests.h"

#define DEFAULT_BUFF_LEN 6
#define BIGGER_BUFF_LEN  8


static uint32_t test_basic_totp(void) {
    test_name("totp: test_basic_totp");

    struct boringauth_totp_cfg cfg;
    const char key[] = "12345678901234567890";
    char code[DEFAULT_BUFF_LEN + 1] = {0};


    uint32_t ret = boringauth_totp_init(&cfg);
    assert(ret == LIBREAUTH_OATH_SUCCESS);
    assert(cfg.key == NULL);
    assert(cfg.key_len == 0);
    assert(cfg.timestamp != 0);
    assert(cfg.positive_tolerance == 0);
    assert(cfg.negative_tolerance == 0);
    assert(cfg.period == 30);
    assert(cfg.initial_time == 0);
    assert(cfg.output_len == DEFAULT_BUFF_LEN);
    assert(cfg.output_base == NULL);
    assert(cfg.output_base_len == 0);
    assert(cfg.hash_function == LIBREAUTH_OATH_SHA_1);

    cfg.key = key;
    cfg.key_len = sizeof(key);

    ret = boringauth_totp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_SUCCESS);
    assert(strlen(code) == DEFAULT_BUFF_LEN);
    assert(!boringauth_totp_is_valid(NULL, "755224"));
    assert(!boringauth_totp_is_valid(&cfg, "4755224"));
    assert(!boringauth_totp_is_valid(&cfg, "!@#$%^"));
    assert(!boringauth_totp_is_valid(&cfg, ""));
    assert(!boringauth_totp_is_valid(&cfg, NULL));

    return 1;
}

static uint32_t test_advanced_totp(void) {
    test_name("totp: test_advanced_totp");

    struct boringauth_totp_cfg cfg;
    const char key[] = "12345678901234567890123456789012";
    char code[BIGGER_BUFF_LEN + 1];

    uint32_t ret = boringauth_totp_init(&cfg);
    assert(ret == LIBREAUTH_OATH_SUCCESS);

    cfg.key = key;
    cfg.key_len = sizeof(key);
    cfg.timestamp = 1111111109;
    cfg.output_len = BIGGER_BUFF_LEN;
    cfg.hash_function = LIBREAUTH_OATH_SHA_256;

    ret = boringauth_totp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_SUCCESS);
    assert(strlen(code) == BIGGER_BUFF_LEN);
    assert(strncmp(code, "68084774", BIGGER_BUFF_LEN + 1) == 0);

    assert(boringauth_totp_is_valid(&cfg, "68084774"));
    assert(!boringauth_totp_is_valid(NULL, "68084774"));
    assert(!boringauth_totp_is_valid(&cfg, "68084775"));
    assert(!boringauth_totp_is_valid(&cfg, "46808477"));
    assert(!boringauth_totp_is_valid(&cfg, "!@#$%^&*"));
    assert(!boringauth_totp_is_valid(&cfg, ""));
    assert(!boringauth_totp_is_valid(&cfg, NULL));

    return 1;
}

static uint32_t test_tolerance(void) {
    test_name("totp: test_tolerance");

    struct boringauth_totp_cfg cfg;
    const char key[] = "12345678901234567890";

    uint32_t ret = boringauth_totp_init(&cfg);
    assert(ret == LIBREAUTH_OATH_SUCCESS);

    cfg.key = key;
    cfg.key_len = sizeof(key);
    cfg.timestamp = 1234567890;

    cfg.positive_tolerance = 0;
    cfg.negative_tolerance = 0;
    assert(!boringauth_totp_is_valid(&cfg, "590587"));
    cfg.positive_tolerance = 1;
    cfg.negative_tolerance = 1;
    assert(boringauth_totp_is_valid(&cfg, "590587"));
    cfg.positive_tolerance = 1;
    cfg.negative_tolerance = 1;
    assert(!boringauth_totp_is_valid(&cfg, "240500"));
    cfg.positive_tolerance = 2;
    cfg.negative_tolerance = 2;
    assert(boringauth_totp_is_valid(&cfg, "240500"));
    cfg.positive_tolerance = 0;
    cfg.negative_tolerance = 0;
    assert(!boringauth_totp_is_valid(&cfg, "980357"));
    cfg.positive_tolerance = 1;
    cfg.negative_tolerance = 1;
    assert(boringauth_totp_is_valid(&cfg, "980357"));
    cfg.positive_tolerance = 1;
    cfg.negative_tolerance = 1;
    assert(!boringauth_totp_is_valid(&cfg, "186057"));
    cfg.positive_tolerance = 2;
    cfg.negative_tolerance = 2;
    assert(boringauth_totp_is_valid(&cfg, "186057"));

    return 1;
}

static uint32_t test_init_null_ptr(void) {
    test_name("totp: test_init_null_ptr");

    uint32_t ret = boringauth_totp_init(NULL);
    assert(ret == LIBREAUTH_OATH_CFG_NULL_PTR);

    return 1;
}

static uint32_t test_generate_null_ptr(void) {
    test_name("totp: test_generate_null_ptr");

    struct boringauth_totp_cfg cfg;
    const char key[] = "12345678901234567890";
    char code[] = "qwerty";

    boringauth_totp_init(&cfg);

    uint32_t ret = boringauth_totp_generate(NULL, code);
    assert(ret == LIBREAUTH_OATH_CFG_NULL_PTR);
    assert(strcmp(code, "qwerty") == 0);

    ret = boringauth_totp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_KEY_NULL_PTR);

    cfg.key = key;

    ret = boringauth_totp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_INVALID_KEY_LEN);

    cfg.key_len = sizeof(key);

    ret = boringauth_totp_generate(&cfg, NULL);
    assert(ret == LIBREAUTH_OATH_CODE_NULL_PTR);

    ret = boringauth_totp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_SUCCESS);

    return 1;
}

static uint32_t test_invalid_base(void) {
    test_name("totp: test_invalid_base");

    struct boringauth_totp_cfg cfg;
    const char key[] = "12345678901234567890", base[] = "0123456789ABCDEF";
    char code[DEFAULT_BUFF_LEN + 1];

    boringauth_totp_init(&cfg);

    cfg.key = key;
    cfg.key_len = sizeof(key);
    cfg.output_base = base;

    uint32_t ret = boringauth_totp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_INVALID_BASE_LEN);
    cfg.output_base_len = 1;
    ret = boringauth_totp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_INVALID_BASE_LEN);

    cfg.output_base_len = sizeof(base);

    ret = boringauth_totp_generate(&cfg, code);
    assert(ret == LIBREAUTH_OATH_SUCCESS);

    return 1;
}

uint32_t test_totp(void) {
    uint32_t nb_tests = 0;

    nb_tests += test_basic_totp();
    nb_tests += test_advanced_totp();
    nb_tests += test_tolerance();
    nb_tests += test_init_null_ptr();
    nb_tests += test_generate_null_ptr();
    nb_tests += test_invalid_base();

    return nb_tests;
}
