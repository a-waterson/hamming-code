

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
void toHamming(struct dc_application_settings *settings, char *bin);
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
        bool bits[8];
        char binary[9];

        item = (uint8_t)input[i];
        dc_to_binary8(env, item, bits);
        dc_to_printable_binary8(env, bits, binary);
        dc_write(env, err, STDOUT_FILENO, binary, sizeof(binary));
        // toHamming(settings, binary);
    }
}
void toHamming(struct dc_application_settings *settings, char *bin)
{
    printf("%s\n", bin);
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
