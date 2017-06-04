/*
 *  This software is a computer program whose purpose is to compute validitiy of
 *  identification data.
 *
 *  Copyright (C) 2017 Th!nk Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, only version 2.0.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

/* Original LibreAuth License */

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

#pragma once

#include <stddef.h>
#include <stdint.h>


/*
 * PASS module
 */

#define LIBREAUTH_PASS_PASSWORD_MIN_LEN 4
#define LIBREAUTH_PASS_PASSWORD_MAX_LEN 128
#define LIBREAUTH_PASS_STORAGE_LEN      1024

typedef enum {
    LIBREAUTH_PASS_SUCCESS                  = 0,
    LIBREAUTH_PASS_PASSWORD_TOO_SHORT       = 1,
    LIBREAUTH_PASS_PASSWORD_TOO_LONG        = 2,
    LIBREAUTH_PASS_INVALID_PASSWORD_FORMAT  = 10,
    LIBREAUTH_PASS_NOT_ENOUGH_SPACE         = 20
} boringauth_pass_errno;

boringauth_pass_errno    boringauth_pass_derive_password(const void *password, void *storage, size_t storage_len);
int32_t                 boringauth_pass_is_valid(const void *password, const void *reference);


/*
 * OATH module
 */

typedef enum {
    LIBREAUTH_OATH_SHA_1   = 1,
    LIBREAUTH_OATH_SHA_256 = 2,
    LIBREAUTH_OATH_SHA_512 = 3
} boringauth_oath_hash_function;

typedef enum {
    LIBREAUTH_OATH_SUCCESS           = 0,

    LIBREAUTH_OATH_CFG_NULL_PTR      = 1,
    LIBREAUTH_OATH_CODE_NULL_PTR     = 2,
    LIBREAUTH_OATH_KEY_NULL_PTR      = 3,

    LIBREAUTH_OATH_INVALID_BASE_LEN  = 10,
    LIBREAUTH_OATH_INVALID_KEY_LEN   = 11,
    LIBREAUTH_OATH_CODE_TOO_SMALL    = 12,
    LIBREAUTH_OATH_CODE_TOO_BIG      = 13,

    LIBREAUTH_OATH_INVALID_KEY       = 20,
    LIBREAUTH_OATH_INVALID_PERIOD    = 21,

    LIBREAUTH_OATH_CODE_INVALID_UTF8 = 30
} boringauth_oath_errno;

/* HOTP */

struct boringauth_hotp_cfg {
    const void                   *key;
    size_t                        key_len;
    uint64_t                      counter;
    size_t                        output_len;
    const char                   *output_base;
    size_t                        output_base_len;
    boringauth_oath_hash_function  hash_function;
};

boringauth_oath_errno boringauth_hotp_init(struct boringauth_hotp_cfg *cfg);
boringauth_oath_errno boringauth_hotp_generate(const struct boringauth_hotp_cfg *cfg, char *code);
int32_t              boringauth_hotp_is_valid(const struct boringauth_hotp_cfg *cfg, const char *code);

/* TOTP */

struct boringauth_totp_cfg {
    const void                   *key;
    size_t                        key_len;
    int64_t                       timestamp;
    uint64_t                      positive_tolerance;
    uint64_t                      negative_tolerance;
    uint32_t                      period;
    uint64_t                      initial_time;
    size_t                        output_len;
    const void                   *output_base;
    size_t                        output_base_len;
    boringauth_oath_hash_function  hash_function;
};

boringauth_oath_errno boringauth_totp_init(struct boringauth_totp_cfg *cfg);
boringauth_oath_errno boringauth_totp_generate(const struct boringauth_totp_cfg *cfg, void *code);
int32_t              boringauth_totp_is_valid(const struct boringauth_totp_cfg *cfg, const void *code);
