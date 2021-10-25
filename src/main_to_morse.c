

#include <ctype.h>
#include <dc_application/command_line.h>
#include <dc_application/config.h>
#include <dc_application/defaults.h>
#include <dc_application/environment.h>
#include <dc_application/options.h>
#include <dc_posix/dc_stdlib.h>
#include <dc_posix/dc_string.h>
#include <dc_posix/dc_unistd.h>
#include <dc_util/bits.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define BUF_SIZE 1024

struct application_settings
{
    struct dc_opt_settings opts;
    struct dc_setting_string *parity;
    struct dc_setting_string *prefix;
};
const uint8_t MASK_00000001 = UINT8_C(0x00000001);
const uint8_t MASK_00000010 = UINT8_C(0x00000002);
const uint8_t MASK_00000100 = UINT8_C(0x00000004);
const uint8_t MASK_00001000 = UINT8_C(0x00000008);
const uint8_t MASK_00010000 = UINT8_C(0x00000010);
const uint8_t MASK_00100000 = UINT8_C(0x00000020);
const uint8_t MASK_01000000 = UINT8_C(0x00000040);
const uint8_t MASK_10000000 = UINT8_C(0x00000080);

static const uint8_t masks_8[] = {
    MASK_10000000, MASK_01000000, MASK_00100000, MASK_00010000,
    MASK_00001000, MASK_00000100, MASK_00000010, MASK_00000001,
};

void toHamming(struct dc_application_settings *settings, bool input[8],
               bool output[16], const struct dc_posix_env *env,
               struct dc_error *err);
static struct dc_application_settings *create_settings(
    const struct dc_posix_env *env, struct dc_error *err);

static int destroy_settings(const struct dc_posix_env *env,
                            struct dc_error *err,
                            struct dc_application_settings **psettings);

static int run(const struct dc_posix_env *env, struct dc_error *err,
               struct dc_application_settings *settings);

static void error_reporter(const struct dc_error *err);
static void trace_reporter(const struct dc_posix_env *env,
                           const char *file_name, const char *function_name,
                           size_t line_number);
void computeParity(bool *output);
int main(int argc, char *argv[])
{
    dc_posix_tracer tracer;
    dc_error_reporter reporter;
    struct dc_posix_env env;
    struct dc_error err;
    struct dc_application_info *info;
    int ret_val;

    reporter = error_reporter;
    tracer = NULL;
    //    tracer = trace_reporter;
    dc_error_init(&err, reporter);
    dc_posix_env_init(&env, tracer);
    info = dc_application_info_create(&env, &err, "To Morse Application");
    ret_val =
        dc_application_run(&env, &err, info, create_settings, destroy_settings,
                           run, dc_default_create_lifecycle,
                           dc_default_destroy_lifecycle, NULL, argc, argv);
    dc_application_info_destroy(&env, &info);
    dc_error_reset(&err);

    return ret_val;
}
static struct dc_application_settings *create_settings(
    const struct dc_posix_env *env, struct dc_error *err)
{
    static bool default_verbose = false;
    struct application_settings *settings;

    DC_TRACE(env);
    settings = dc_malloc(env, err, sizeof(struct application_settings));

    if (settings == NULL)
    {
        return NULL;
    }

    settings->opts.parent.config_path = dc_setting_path_create(env, err);
    settings->prefix = dc_setting_string_create(env, err);
    settings->parity = dc_setting_string_create(env, err);
    struct options opts[] = {
        {(struct dc_setting *)settings->opts.parent.config_path,
         dc_options_set_path, "config", required_argument, 'c', "CONFIG",
         dc_string_from_string, NULL, dc_string_from_config, NULL},

        {(struct dc_setting *)settings->prefix, dc_options_set_string, "prefix",
         required_argument, 'p', "PREFIX", dc_string_from_string, "prefix",
         dc_string_from_config, "prefix:"},

        {(struct dc_setting *)settings->parity, dc_options_set_string, "parity",
         required_argument, 'a', "PARITY", dc_string_from_string, "parity",
         dc_string_from_config, "Even Parity"},
    };

    // note the trick here - we use calloc and add 1 to ensure the last line is
    // all 0/NULL
    settings->opts.opts_count = (sizeof(opts) / sizeof(struct options)) + 1;
    settings->opts.opts_size = sizeof(struct options);
    settings->opts.opts = dc_calloc(env, err, settings->opts.opts_count,
                                    settings->opts.opts_size);
    dc_memcpy(env, settings->opts.opts, opts, sizeof(opts));
    settings->opts.flags = "m:";
    settings->opts.env_prefix = "DC_EXAMPLE_";

    return (struct dc_application_settings *)settings;
}
void inputToBinary(char *input, size_t inputsize,
                   const struct dc_posix_env *env, struct dc_error *err,
                   struct dc_application_settings *settings);
static int destroy_settings(const struct dc_posix_env *env,
                            __attribute__((unused)) struct dc_error *err,
                            struct dc_application_settings **psettings)
{
    struct application_settings *app_settings;

    DC_TRACE(env);
    app_settings = (struct application_settings *)*psettings;
    dc_setting_string_destroy(env, &app_settings->prefix);
    dc_setting_string_destroy(env, &app_settings->parity);
    dc_free(env, app_settings->opts.opts, app_settings->opts.opts_count);
    dc_free(env, *psettings, sizeof(struct application_settings));

    if (env->null_free)
    {
        *psettings = NULL;
    }

    return 0;
}
static int run(const struct dc_posix_env *env, struct dc_error *err,
               struct dc_application_settings *settings)
{
    struct application_settings *app_settings;
    const char *prefix;
    const char *parity;

    DC_TRACE(env);
    app_settings = (struct application_settings *)settings;
    parity = dc_setting_string_get(env, app_settings->parity);
    prefix = dc_setting_string_get(env, app_settings->prefix);
    // printf("%s\n%s\n", prefix, parity);

    char chars[BUF_SIZE] = {0};
    ssize_t nread;
    int ret_val;

    while ((nread = dc_read(env, err, STDIN_FILENO, chars, BUF_SIZE)) > 0)
    {
        if (dc_error_has_error(err))
        {
            return 1;
        }
        if (dc_error_has_error(err))
        {
            ret_val = 2;
        }
    }

    inputToBinary(chars, (size_t)strlen(chars), env, err, settings);
}
void inputToBinary(char *input, size_t len, const struct dc_posix_env *env,
                   struct dc_error *err,
                   struct dc_application_settings *settings)
{
    for (size_t i = 0; i < len - 1; i++)
    {
        uint8_t item;

        uint16_t item16;
        uint16_t *ptr16;
        ptr16 = &item16;

        bool bits[8];
        bool bits16[16] = {false};
        char binary[9];
        char binary16[17];
        item = (uint8_t)input[i];

        // takes character and converts to binary representation array of bools
        dc_to_binary8(env, item, bits);

        // dc_to_printable_binary8(env, bits, binary);
        // dc_write(env, err, STDOUT_FILENO, binary, sizeof(binary));

        // here we take bits[8] and convert it to 16 bits so we can use
        // from_binary16. start by computing our hamming code.
        // toHamming should take both bool arrays [8] and [16]
        // and compute our hamming code, modifying a ptr
        toHamming(settings, bits, bits16, env, err);

        dc_from_binary16(env, bits16, ptr16);
        // printf("%d\n", sizeof(item16));
        dc_to_binary16(env, item16, bits16);
        dc_to_printable_binary16(env, bits16, binary16);
        printf("%s\n", binary16);
    }
}

void toHamming(struct dc_application_settings *settings, bool input[8],
               bool output[16], const struct dc_posix_env *env,
               struct dc_error *err)
{
    for (size_t i = 0; i < sizeof(input) / sizeof(input[0]); i++)
    {
        output[i] = input[i];
    }
    // pad out 16 bit array

    computeParity(output);
    for (size_t i = 0; i < 16; i++)
    {
        printf("%d", output[i]);
    }
    printf("\n");
}
void computeParity(bool *output)
{
    if ((output[0] + output[1] + output[3] + output[4] + output[6]) % 2)
    {
        output[8] = true;
    }

    if ((output[0] + output[2] + output[3] + output[5] + output[6]) % 2)
    {
        output[9] = true;
    }
    if ((output[1] + output[2] + output[3] + output[7]) % 2)
    {
        output[10] = true;
    }
    if ((output[4] + output[5] + output[6] + output[7]) % 2)
    {
        output[11] = true;
    }
}

static void error_reporter(const struct dc_error *err)
{
    fprintf(stderr, "ERROR: %s : %s : @ %zu : %d\n", err->file_name,
            err->function_name, err->line_number, 0);
    fprintf(stderr, "ERROR: %s\n", err->message);
}

static void trace_reporter(__attribute__((unused))
                           const struct dc_posix_env *env,
                           const char *file_name, const char *function_name,
                           size_t line_number)
{
    fprintf(stdout, "TRACE: %s : %s : @ %zu\n", file_name, function_name,
            line_number);
}
