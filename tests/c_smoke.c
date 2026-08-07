// SPDX-License-Identifier: MIT
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libmkckks.h"

enum {
    STATUS_OK = 0,
    STATUS_INVALID = 1,
    STATUS_HANDLE = 2,
    STATUS_KEY = 4,
    STATUS_LEVEL = 5,
    STATUS_SERIAL = 6,
    STATUS_SHARE = 7,
    STATUS_PANIC = 255,
};

static void clear_error(char **error) {
    if (*error != NULL) {
        mkckks_v1_error_free(*error);
        *error = NULL;
    }
}

static int require_success(int32_t status, char **error, const char *operation) {
    if (status == STATUS_OK) {
        return 0;
    }
    fprintf(stderr, "%s failed with status %d: %s\n", operation, status,
            *error == NULL ? "(no diagnostic)" : *error);
    clear_error(error);
    return 1;
}

static int require_failure(
        int32_t status, int32_t expected, char **error, uint64_t live_before,
        const char *operation) {
    int bad = 0;
    if (status != expected || status == STATUS_PANIC) {
        fprintf(stderr, "%s returned status %d, expected %d\n", operation, status, expected);
        bad = 1;
    }
    if (*error == NULL) {
        fprintf(stderr, "%s returned no diagnostic\n", operation);
        bad = 1;
    } else if (strstr(*error, "panic") != NULL) {
        fprintf(stderr, "%s exposed a recovered panic: %s\n", operation, *error);
        bad = 1;
    }
    clear_error(error);
    if (mkckks_v1_live_handles() != live_before) {
        fprintf(stderr, "%s changed the live-handle count after failure\n", operation);
        bad = 1;
    }
    return bad;
}

static int remember(uint64_t *handles, size_t *count, uint64_t handle) {
    if (handle == 0 || *count >= 64) {
        return 1;
    }
    handles[(*count)++] = handle;
    return 0;
}

static int check_ciphertext(
        uint64_t party, uint64_t ciphertext, const double *expected_real,
        const double *expected_imag, size_t length, double bound, char **error,
        const char *operation) {
    double decoded_real[8] = {0};
    double decoded_imag[8] = {0};
    uint64_t share = 0;
    uint64_t baseline = mkckks_v1_live_handles();
    if (length > 8 || require_success(
            mkckks_v1_partial_decrypt(party, ciphertext, &share, error),
            error, operation)) {
        return 1;
    }
    if (require_success(
            mkckks_v1_collective_decrypt(
                ciphertext, &share, 1, decoded_real, decoded_imag, length, error),
            error, operation)) {
        mkckks_v1_release(share, error);
        clear_error(error);
        return 1;
    }
    int bad = 0;
    for (size_t index = 0; index < length; index++) {
        if (fabs(decoded_real[index] - expected_real[index]) > bound ||
                fabs(decoded_imag[index] - expected_imag[index]) > bound) {
            fprintf(stderr,
                    "%s slot %zu exceeded %.3e: got %.17g%+.17gi expected %.17g%+.17gi\n",
                    operation, index, bound, decoded_real[index], decoded_imag[index],
                    expected_real[index], expected_imag[index]);
            bad = 1;
        }
    }
    if (require_success(mkckks_v1_release(share, error), error, "release check share")) {
        bad = 1;
    }
    if (mkckks_v1_live_handles() != baseline) {
        fprintf(stderr, "%s leaked its temporary decryption share\n", operation);
        bad = 1;
    }
    return bad;
}

int main(void) {
    uint64_t handles[64] = {0};
    size_t handle_count = 0;
    char *error = NULL;
    uint8_t *bytes = NULL;
    size_t byte_count = 0;

    if (mkckks_v1_abi_version() != 1 || mkckks_v1_live_handles() != 0) {
        return 1;
    }
    if (require_success(
            mkckks_v1_build_info(&bytes, &byte_count, &error), &error, "build_info") ||
            bytes == NULL || byte_count == 0) {
        return 2;
    }
    mkckks_v1_buffer_free(bytes);
    bytes = NULL;

    const char *literal =
        "{\"log_n\":14,\"log_slots\":13,"
        "\"q\":[576460752301785089,4503599626321921,4503599625535489,"
        "4503599625404417,4503599623045121,4503599621472257],"
        "\"p\":[1152921504606584833,1152921504598720513],"
        "\"scale\":4503599627370496,\"sigma\":3.2}";
    uint64_t context = 0;
    if (require_success(
            mkckks_v1_context_create(
                (uint8_t *)literal, strlen(literal), 1, &context, &error),
            &error, "context_create") || remember(handles, &handle_count, context)) {
        return 3;
    }
    uint64_t baseline = mkckks_v1_live_handles();
    if (require_failure(
            mkckks_v1_context_create(
                (uint8_t *)literal, strlen(literal), 1, NULL, &error),
            STATUS_INVALID, &error, baseline, "context_create(NULL output)")) {
        return 4;
    }
    if (require_success(
            mkckks_v1_context_info(context, &bytes, &byte_count, &error),
            &error, "context_info") || bytes == NULL || byte_count == 0) {
        return 5;
    }
    mkckks_v1_buffer_free(bytes);
    bytes = NULL;

    const char *party_id = "c-smoke-party";
    uint64_t party = 0;
    if (require_success(
            mkckks_v1_party_generate(
                context, (uint8_t *)party_id, strlen(party_id), &party, &error),
            &error, "party_generate") || remember(handles, &handle_count, party)) {
        return 6;
    }
    uint64_t public_key = 0;
    if (require_success(
            mkckks_v1_party_public_key(party, &public_key, &error),
            &error, "party_public_key") ||
            remember(handles, &handle_count, public_key)) {
        return 7;
    }

    double real_values[2] = {0.25, -0.5};
    double imag_values[2] = {0.125, 0.25};
    uint64_t ciphertext = 0;
    if (require_success(
            mkckks_v1_encrypt(
                party, real_values, imag_values, 2, 1, &ciphertext, &error),
            &error, "party encrypt") || remember(handles, &handle_count, ciphertext)) {
        return 8;
    }
    uint64_t public_ciphertext = 0;
    if (require_success(
            mkckks_v1_encrypt(
                public_key, real_values, imag_values, 2, 1, &public_ciphertext, &error),
            &error, "public-key encrypt") ||
            remember(handles, &handle_count, public_ciphertext)) {
        return 9;
    }
    baseline = mkckks_v1_live_handles();
    uint64_t failed_output = 0;
    if (require_failure(
            mkckks_v1_encrypt(
                party, real_values, imag_values, 2, 2, &failed_output, &error),
            STATUS_INVALID, &error, baseline, "encrypt(invalid flag)") ||
            failed_output != 0) {
        return 10;
    }
    double nonfinite[1] = {NAN};
    if (require_failure(
            mkckks_v1_encrypt(party, nonfinite, NULL, 1, 0, &failed_output, &error),
            STATUS_INVALID, &error, baseline, "encrypt(non-finite)") ||
            failed_output != 0) {
        return 11;
    }

    uint64_t plaintext = 0;
    if (require_success(
            mkckks_v1_encode_plaintext(
                context, real_values, imag_values, 2, 1, &plaintext, &error),
            &error, "encode_plaintext") || remember(handles, &handle_count, plaintext)) {
        return 12;
    }

    uint64_t add = 0, subtract = 0, add_scalar = 0, add_plaintext = 0;
    uint64_t integer_scalar = 0, complex_scalar = 0, plaintext_product = 0;
    if (require_success(mkckks_v1_add(ciphertext, public_ciphertext, &add, &error),
                        &error, "add") || remember(handles, &handle_count, add) ||
        require_success(mkckks_v1_subtract(add, public_ciphertext, &subtract, &error),
                        &error, "subtract") ||
        remember(handles, &handle_count, subtract) ||
        require_success(mkckks_v1_add_scalar(
                            ciphertext, 0.125, -0.25, 0, &add_scalar, &error),
                        &error, "add_scalar") ||
        remember(handles, &handle_count, add_scalar) ||
        require_success(mkckks_v1_add_plaintext(
                            ciphertext, plaintext, 1, &add_plaintext, &error),
                        &error, "add_plaintext") ||
        remember(handles, &handle_count, add_plaintext) ||
        require_success(mkckks_v1_multiply_scalar(
                            ciphertext, 2.0, 0.0, &integer_scalar, &error),
                        &error, "multiply_scalar(integer)") ||
        remember(handles, &handle_count, integer_scalar) ||
        require_success(mkckks_v1_multiply_scalar(
                            ciphertext, 0.75, -0.125, &complex_scalar, &error),
                        &error, "multiply_scalar(complex)") ||
        remember(handles, &handle_count, complex_scalar) ||
        require_success(mkckks_v1_multiply_plaintext(
                            ciphertext, plaintext, &plaintext_product, &error),
                        &error, "multiply_plaintext") ||
        remember(handles, &handle_count, plaintext_product)) {
        return 13;
    }

    baseline = mkckks_v1_live_handles();
    if (require_failure(mkckks_v1_add(context, ciphertext, &failed_output, &error),
                        STATUS_HANDLE, &error, baseline, "add(wrong kind)") ||
        require_failure(mkckks_v1_multiply_scalar(
                            ciphertext, INFINITY, 0, &failed_output, &error),
                        STATUS_INVALID, &error, baseline, "multiply_scalar(non-finite)")) {
        return 14;
    }

    int32_t rotations[1] = {1};
    uint64_t contribution = 0, empty_contribution = 0;
    if (require_success(mkckks_v1_party_evaluation_keys(
                            party, 1, rotations, 1, 1, &contribution, &error),
                        &error, "party_evaluation_keys") ||
        remember(handles, &handle_count, contribution) ||
        require_success(mkckks_v1_party_evaluation_keys(
                            party, 0, NULL, 0, 0, &empty_contribution, &error),
                        &error, "empty party_evaluation_keys") ||
        remember(handles, &handle_count, empty_contribution)) {
        return 15;
    }
    uint64_t contribution_handles[1] = {contribution};
    uint64_t empty_contribution_handles[1] = {empty_contribution};
    uint64_t keyset = 0, empty_keyset = 0;
    if (require_success(mkckks_v1_evaluation_keys_combine(
                            contribution_handles, 1, &keyset, &error),
                        &error, "evaluation_keys_combine") ||
        remember(handles, &handle_count, keyset) ||
        require_success(mkckks_v1_evaluation_keys_combine(
                            empty_contribution_handles, 1, &empty_keyset, &error),
                        &error, "empty evaluation_keys_combine") ||
        remember(handles, &handle_count, empty_keyset)) {
        return 16;
    }

    uint64_t product = 0, dropped = 0, rescaled = 0, rotated = 0, conjugated = 0;
    if (require_success(mkckks_v1_multiply(
                            keyset, ciphertext, ciphertext, 0, &product, &error),
                        &error, "multiply") || remember(handles, &handle_count, product) ||
        require_success(mkckks_v1_drop_level(ciphertext, 1, &dropped, &error),
                        &error, "drop_level") || remember(handles, &handle_count, dropped) ||
        require_success(mkckks_v1_rescale(
                            product, 4503599627370496.0, &rescaled, &error),
                        &error, "rescale") || remember(handles, &handle_count, rescaled) ||
        require_success(mkckks_v1_rotate(keyset, ciphertext, 1, 0, &rotated, &error),
                        &error, "rotate") || remember(handles, &handle_count, rotated) ||
        require_success(mkckks_v1_conjugate(keyset, ciphertext, &conjugated, &error),
                        &error, "conjugate") || remember(handles, &handle_count, conjugated)) {
        return 17;
    }

    const double basic_bound = ldexp(1.0, -31);  // -log2(scale) + log_slots + 8
    const double rotation_local = ldexp(1.0, -28);  // same formula with +11
    const double multiply_local = ldexp(1.0, -27);  // same formula with +12
    const double maximum_input = hypot(0.5, 0.25);
    const double product_bound = 2 * maximum_input * basic_bound
                               + basic_bound * basic_bound + multiply_local;
    double expected_real[2] = {0}, expected_imag[2] = {0};

#define CHECK_RESULT(handle, expression, tolerance, label) \
    do { \
        expression; \
        if (check_ciphertext( \
                party, handle, expected_real, expected_imag, 2, tolerance, \
                &error, label)) { \
            return 33; \
        } \
    } while (0)

    CHECK_RESULT(ciphertext, {
        memcpy(expected_real, real_values, sizeof(real_values));
        memcpy(expected_imag, imag_values, sizeof(imag_values));
    }, basic_bound, "decrypt encrypt");
    CHECK_RESULT(public_ciphertext, {
        memcpy(expected_real, real_values, sizeof(real_values));
        memcpy(expected_imag, imag_values, sizeof(imag_values));
    }, basic_bound, "decrypt public encrypt");
    CHECK_RESULT(add, {
        for (size_t i = 0; i < 2; i++) {
            expected_real[i] = 2 * real_values[i];
            expected_imag[i] = 2 * imag_values[i];
        }
    }, 3 * basic_bound, "decrypt add");
    CHECK_RESULT(subtract, {
        memcpy(expected_real, real_values, sizeof(real_values));
        memcpy(expected_imag, imag_values, sizeof(imag_values));
    }, 5 * basic_bound, "decrypt subtract");
    CHECK_RESULT(add_scalar, {
        for (size_t i = 0; i < 2; i++) {
            expected_real[i] = real_values[i] + 0.125;
            expected_imag[i] = imag_values[i] - 0.25;
        }
    }, 3 * basic_bound, "decrypt scalar add");
    CHECK_RESULT(add_plaintext, {
        memset(expected_real, 0, sizeof(expected_real));
        memset(expected_imag, 0, sizeof(expected_imag));
    }, 3 * basic_bound, "decrypt plaintext subtract");
    CHECK_RESULT(integer_scalar, {
        for (size_t i = 0; i < 2; i++) {
            expected_real[i] = 2 * real_values[i];
            expected_imag[i] = 2 * imag_values[i];
        }
    }, 3 * basic_bound, "decrypt integer scalar");
    CHECK_RESULT(complex_scalar, {
        for (size_t i = 0; i < 2; i++) {
            expected_real[i] = 0.75 * real_values[i] + 0.125 * imag_values[i];
            expected_imag[i] = 0.75 * imag_values[i] - 0.125 * real_values[i];
        }
    }, hypot(0.75, 0.125) * basic_bound + maximum_input * basic_bound
       + basic_bound * basic_bound + multiply_local, "decrypt complex scalar");
    CHECK_RESULT(plaintext_product, {
        for (size_t i = 0; i < 2; i++) {
            expected_real[i] = real_values[i] * real_values[i]
                             - imag_values[i] * imag_values[i];
            expected_imag[i] = 2 * real_values[i] * imag_values[i];
        }
    }, product_bound, "decrypt plaintext product");
    CHECK_RESULT(product, {
        for (size_t i = 0; i < 2; i++) {
            expected_real[i] = real_values[i] * real_values[i]
                             - imag_values[i] * imag_values[i];
            expected_imag[i] = 2 * real_values[i] * imag_values[i];
        }
    }, product_bound, "decrypt ciphertext product");
    CHECK_RESULT(dropped, {
        memcpy(expected_real, real_values, sizeof(real_values));
        memcpy(expected_imag, imag_values, sizeof(imag_values));
    }, 2 * basic_bound, "decrypt dropped ciphertext");
    CHECK_RESULT(rescaled, {
        for (size_t i = 0; i < 2; i++) {
            expected_real[i] = real_values[i] * real_values[i]
                             - imag_values[i] * imag_values[i];
            expected_imag[i] = 2 * real_values[i] * imag_values[i];
        }
    }, product_bound + basic_bound, "decrypt rescaled ciphertext");
    CHECK_RESULT(rotated, {
        expected_real[0] = real_values[1];
        expected_imag[0] = imag_values[1];
        expected_real[1] = 0;
        expected_imag[1] = 0;
    }, basic_bound + rotation_local, "decrypt rotated ciphertext");
    CHECK_RESULT(conjugated, {
        for (size_t i = 0; i < 2; i++) {
            expected_real[i] = real_values[i];
            expected_imag[i] = -imag_values[i];
        }
    }, basic_bound + rotation_local, "decrypt conjugated ciphertext");

#undef CHECK_RESULT

    baseline = mkckks_v1_live_handles();
    if (require_failure(mkckks_v1_multiply(
                            empty_keyset, ciphertext, ciphertext, 0, &failed_output, &error),
                        STATUS_KEY, &error, baseline, "multiply(missing key)") ||
        require_failure(mkckks_v1_rotate(
                            empty_keyset, ciphertext, 1, 0, &failed_output, &error),
                        STATUS_KEY, &error, baseline, "rotate(missing key)") ||
        require_failure(mkckks_v1_conjugate(
                            empty_keyset, ciphertext, &failed_output, &error),
                        STATUS_KEY, &error, baseline, "conjugate(missing key)") ||
        require_failure(mkckks_v1_conjugate(
                            keyset, dropped, &failed_output, &error),
                        STATUS_LEVEL, &error, baseline, "conjugate(lower level)") ||
        require_failure(mkckks_v1_rescale(
                            ciphertext, 1e-300, &failed_output, &error),
                        STATUS_LEVEL, &error, baseline, "rescale(exhaustion)") ||
        require_failure(mkckks_v1_rescale(
                            product, 1.0, &failed_output, &error),
                        STATUS_LEVEL, &error, baseline, "rescale(precision floor)")) {
        return 18;
    }

    uint64_t share = 0;
    if (require_success(mkckks_v1_partial_decrypt(
                            party, product, &share, &error),
                        &error, "partial_decrypt") || remember(handles, &handle_count, share)) {
        return 19;
    }
    double decoded_real[2] = {0}, decoded_imag[2] = {0};
    if (require_success(mkckks_v1_collective_decrypt(
                            product, &share, 1, decoded_real, decoded_imag, 2, &error),
                        &error, "collective_decrypt")) {
        return 20;
    }
    for (size_t index = 0; index < 2; index++) {
        double expected_real = real_values[index] * real_values[index]
                             - imag_values[index] * imag_values[index];
        double expected_imag = 2 * real_values[index] * imag_values[index];
        if (fabs(decoded_real[index] - expected_real) > product_bound ||
                fabs(decoded_imag[index] - expected_imag) > product_bound) {
            return 21;
        }
    }
    baseline = mkckks_v1_live_handles();
    if (require_failure(mkckks_v1_collective_decrypt(
                            product, NULL, 0, decoded_real, decoded_imag, 2, &error),
                        STATUS_SHARE, &error, baseline, "collective_decrypt(missing share)") ||
        require_failure(mkckks_v1_collective_decrypt(
                            product, &share, 1, NULL, decoded_imag, 2, &error),
                        STATUS_INVALID, &error, baseline, "collective_decrypt(NULL output)")) {
        return 22;
    }

    if (require_success(mkckks_v1_cipher_metadata(
                            ciphertext, &bytes, &byte_count, &error),
                        &error, "cipher_metadata") || bytes == NULL || byte_count == 0) {
        return 23;
    }
    mkckks_v1_buffer_free(bytes);
    bytes = NULL;
    if (require_success(mkckks_v1_object_metadata(
                            plaintext, &bytes, &byte_count, &error),
                        &error, "object_metadata") || bytes == NULL || byte_count == 0) {
        return 24;
    }
    mkckks_v1_buffer_free(bytes);
    bytes = NULL;
    baseline = mkckks_v1_live_handles();
    if (require_failure(mkckks_v1_object_metadata(
                            plaintext, NULL, &byte_count, &error),
                        STATUS_INVALID, &error, baseline, "object_metadata(NULL output)")) {
        return 25;
    }

    if (require_success(mkckks_v1_export_artifact(
                            ciphertext, &bytes, &byte_count, &error),
                        &error, "export_artifact") || bytes == NULL || byte_count == 0) {
        return 26;
    }
    uint64_t imported = 0;
    uint8_t imported_kind = 0;
    if (require_success(mkckks_v1_import_artifact(
                            context, bytes, byte_count, &imported, &imported_kind, &error),
                        &error, "import_artifact") || imported_kind != 7 ||
        remember(handles, &handle_count, imported)) {
        return 27;
    }
    memcpy(expected_real, real_values, sizeof(real_values));
    memcpy(expected_imag, imag_values, sizeof(imag_values));
    if (check_ciphertext(
            party, imported, expected_real, expected_imag, 2, basic_bound,
            &error, "decrypt imported ciphertext")) {
        return 27;
    }
    mkckks_v1_buffer_free(bytes);
    bytes = NULL;
    const uint8_t malformed[3] = {1, 2, 3};
    baseline = mkckks_v1_live_handles();
    if (require_failure(mkckks_v1_import_artifact(
                            context, (uint8_t *)malformed, sizeof(malformed),
                            &failed_output, &imported_kind, &error),
                        STATUS_SERIAL, &error, baseline, "import_artifact(malformed)")) {
        return 28;
    }

    // A successful decryption after every fault proves inputs remained usable.
    if (require_success(mkckks_v1_collective_decrypt(
                            product, &share, 1, decoded_real, decoded_imag, 2, &error),
                        &error, "collective_decrypt(after failures)")) {
        return 29;
    }

    for (size_t index = handle_count; index > 0; index--) {
        if (require_success(mkckks_v1_release(handles[index - 1], &error),
                            &error, "release")) {
            return 30;
        }
    }
    baseline = mkckks_v1_live_handles();
    if (require_failure(mkckks_v1_release(imported, &error), STATUS_HANDLE,
                        &error, baseline, "release(stale)")) {
        return 31;
    }
    return mkckks_v1_live_handles() == 0 ? 0 : 32;
}
