/*
 * Copyright Rodolphe Breard (2016)
 * Author: Rodolphe Breard (<year>)
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


#include <assert.h>
#include <boringauth.h>
#include "boringauth_tests.h"


static uint32_t test_valid_pass(void) {
    test_name("pass: test_valid_pass");

    const char password[] = "correct horse battery staple",
          invalid_pass[] = "123456";
    uint8_t storage[LIBREAUTH_PASS_STORAGE_LEN];

    uint32_t ret = boringauth_pass_derive_password(password, storage, LIBREAUTH_PASS_STORAGE_LEN);
    assert(ret == LIBREAUTH_PASS_SUCCESS);
    assert(boringauth_pass_is_valid(password, storage));
    assert(!boringauth_pass_is_valid(invalid_pass, storage));

    return 1;
}

static uint32_t test_invalid_pass(void) {
    test_name("pass: test_invalid_pass");

    const char password[] = "invalid password",
          reference[] = "$pbkdf2-sha256$0$45217803$a607a72c2c92357a4568b998c5f708f801f0b1ffbaea205357e08e4d325830c9";
    assert(!boringauth_pass_is_valid(password, reference));

    return 1;
}

uint32_t test_pass(void) {
    int nb_tests = 0;

    nb_tests += test_valid_pass();
    nb_tests += test_invalid_pass();

    return nb_tests;
}
