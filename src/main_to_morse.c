#include <ctype.h>
#include <dc_application/command_line.h>
#include <dc_application/config.h>
#include <dc_application/defaults.h>
#include <dc_application/environment.h>
#include <dc_application/options.h>
#include <dc_posix/dc_fcntl.h>
#include <dc_posix/dc_stdlib.h>
#include <dc_posix/dc_string.h>
#include <dc_posix/dc_unistd.h>
#include <dc_util/bits.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define BUF_SIZE 1024

struct application_settings
{
    struct dc_opt_settings    opts;
    struct dc_setting_string *parity;
    struct dc_setting_string *prefix;
};
const uint8_t         MASK_00000001          = UINT8_C(0x00000001);
const uint8_t         MASK_00000010          = UINT8_C(0x00000002);
const uint8_t         MASK_00000100          = UINT8_C(0x00000004);
const uint8_t         MASK_00001000          = UINT8_C(0x00000008);
const uint8_t         MASK_00010000          = UINT8_C(0x00000010);
const uint8_t         MASK_00100000          = UINT8_C(0x00000020);
const uint8_t         MASK_01000000          = UINT8_C(0x00000040);
const uint8_t         MASK_10000000          = UINT8_C(0x00000080);

const uint16_t        MASK_00000001_00000000 = UINT16_C(0x00000100);
const uint16_t        MASK_00000010_00000000 = UINT16_C(0x00000200);
const uint16_t        MASK_00000100_00000000 = UINT16_C(0x00000400);
const uint16_t        MASK_00001000_00000000 = UINT16_C(0x00000800);
const uint16_t        MASK_00010000_00000000 = UINT16_C(0x00001000);
const uint16_t        MASK_00100000_00000000 = UINT16_C(0x00002000);
const uint16_t        MASK_01000000_00000000 = UINT16_C(0x00004000);
const uint16_t        MASK_10000000_00000000 = UINT16_C(0x00008000);

static const uint16_t masks_16[]             = {
    MASK_10000000_00000000,
    MASK_01000000_00000000,
    MASK_00100000_00000000,
    MASK_00010000_00000000,
    MASK_00001000_00000000,
    MASK_00000100_00000000,
    MASK_00000010_00000000,
    MASK_00000001_00000000,
    MASK_10000000,
    MASK_01000000,
    MASK_00100000,
    MASK_00010000,
    MASK_00001000,
    MASK_00000100,
    MASK_00000010,
    MASK_00000001,
};

int *createFiles(int                             fd[],
                 const struct dc_posix_env      *env,
                 struct dc_error                *err,
                 struct dc_application_settings *settings,
                 const char                     *prefix);
void writeFileContent(const uint16_t *codeword, uint16_t fileContents[], uint16_t index);
void toHamming(struct dc_application_settings *settings,
               bool                            input[8],
               bool                            output[16],
               const struct dc_posix_env      *env,
               struct dc_error                *err,
               const char                     *parity);
static struct dc_application_settings *create_settings(const struct dc_posix_env *env, struct dc_error *err);

static int
destroy_settings(const struct dc_posix_env *env, struct dc_error *err, struct dc_application_settings **psettings);

static int  run(const struct dc_posix_env *env, struct dc_error *err, struct dc_application_settings *settings);

static void error_reporter(const struct dc_error *err);
static void
trace_reporter(const struct dc_posix_env *env, const char *file_name, const char *function_name, size_t line_number);
void computeParityBits(bool *output, const char *parity);
int  main(int argc, char *argv[])
{
    dc_posix_tracer             tracer;
    dc_error_reporter           reporter;
    struct dc_posix_env         env;
    struct dc_error             err;
    struct dc_application_info *info;
    int                         ret_val;

    reporter = error_reporter;
    tracer   = NULL;
    //    tracer = trace_reporter;
    dc_error_init(&err, reporter);
    dc_posix_env_init(&env, tracer);
    info    = dc_application_info_create(&env, &err, "To Morse Application");
    ret_val = dc_application_run(&env,
                                 &err,
                                 info,
                                 create_settings,
                                 destroy_settings,
                                 run,
                                 dc_default_create_lifecycle,
                                 dc_default_destroy_lifecycle,
                                 NULL,
                                 argc,
                                 argv);
    dc_application_info_destroy(&env, &info);
    dc_error_reset(&err);

    return ret_val;
}
static struct dc_application_settings *create_settings(const struct dc_posix_env *env, struct dc_error *err)
{
    static bool                  default_verbose = false;
    struct application_settings *settings;

    DC_TRACE(env);
    settings = dc_malloc(env, err, sizeof(struct application_settings));

    if(settings == NULL)
    {
        return NULL;
    }

    settings->opts.parent.config_path = dc_setting_path_create(env, err);
    settings->prefix                  = dc_setting_string_create(env, err);
    settings->parity                  = dc_setting_string_create(env, err);
    struct options opts[]             = {
        {(struct dc_setting *)settings->opts.parent.config_path,
         dc_options_set_path,
         "config",
         required_argument,
         'c',
         "CONFIG",
         dc_string_from_string,
         NULL,
         dc_string_from_config,
         NULL},

        {(struct dc_setting *)settings->prefix,
         dc_options_set_string,
         "prefix",
         required_argument,
         'p',
         "PREFIX",
         dc_string_from_string,
         "prefix",
         dc_string_from_config,
         "prefix:"},

        {(struct dc_setting *)settings->parity,
         dc_options_set_string,
         "parity",
         required_argument,
         'a',
         "PARITY",
         dc_string_from_string,
         "parity",
         dc_string_from_config,
         "Even Parity"},
    };

    // note the trick here - we use calloc and add 1 to ensure the last line is
    // all 0/NULL
    settings->opts.opts_count = (sizeof(opts) / sizeof(struct options)) + 1;
    settings->opts.opts_size  = sizeof(struct options);
    settings->opts.opts       = dc_calloc(env, err, settings->opts.opts_count, settings->opts.opts_size);
    dc_memcpy(env, settings->opts.opts, opts, sizeof(opts));
    settings->opts.flags      = "m:";
    settings->opts.env_prefix = "DC_EXAMPLE_";

    return (struct dc_application_settings *)settings;
}
void       inputToBinary(char                           *input,
                         size_t                          len,
                         const struct dc_posix_env      *env,
                         struct dc_error                *err,
                         struct dc_application_settings *settings,
                         const char                     *prefix,
                         const char                     *parity);
static int destroy_settings(const struct dc_posix_env               *env,
                            __attribute__((unused)) struct dc_error *err,
                            struct dc_application_settings         **psettings)
{
    struct application_settings *app_settings;

    DC_TRACE(env);
    app_settings = (struct application_settings *)*psettings;
    dc_setting_string_destroy(env, &app_settings->prefix);
    dc_setting_string_destroy(env, &app_settings->parity);
    dc_free(env, app_settings->opts.opts, app_settings->opts.opts_count);
    dc_free(env, *psettings, sizeof(struct application_settings));

    if(env->null_free)
    {
        *psettings = NULL;
    }

    return 0;
}
static int run(const struct dc_posix_env *env, struct dc_error *err, struct dc_application_settings *settings)
{
    struct application_settings *app_settings;
    const char                  *prefix;
    const char                  *parity;

    DC_TRACE(env);
    app_settings = (struct application_settings *)settings;
    parity       = dc_setting_string_get(env, app_settings->parity);
    prefix       = dc_setting_string_get(env, app_settings->prefix);
    printf("%s\n%s\n", prefix, parity);

    char    chars[BUF_SIZE];

    ssize_t nread;
    int     ret_val;

    while((nread = dc_read(env, err, STDIN_FILENO, chars, BUF_SIZE)) > 0)
    {
        if(dc_error_has_error(err))
        {
            return 1;
        }
        if(dc_error_has_error(err))
        {
            ret_val = 2;
        }
    }

    inputToBinary(chars, (size_t)strlen(chars), env, err, app_settings, prefix, parity);
}

void inputToBinary(char                           *input,
                   size_t                          len,
                   const struct dc_posix_env      *env,
                   struct dc_error                *err,
                   struct dc_application_settings *settings,
                   const char                     *prefix,
                   const char                     *parity)
{
    int      fds[12];
    uint16_t fileContent[12]          = {0};
    uint8_t  fileContentPrintable[12] = {0};
    uint8_t *ptr;
    for(uint16_t i = 0; i < len - 1; i++)
    {
        uint8_t   item;
        uint16_t  item16;
        uint16_t *ptr16;
        ptr16           = &item16;
        bool bits[8]    = {false};
        bool bits16[16] = {false};
        item            = (uint8_t)input[i];

        // takes character and converts to binary representation array of bools
        dc_to_binary8(env, item, bits);

        // here we take bits[8] and convert it to 16 bits so we can use
        // from_binary16. start by computing our hamming code.
        // toHamming should take both bool arrays [8] and [16]
        // and compute our hamming code, modifying a ptr
        toHamming(settings, bits, bits16, env, err, parity);

        dc_from_binary16(env, bits16, ptr16);

        // printf("%s\n", binary16);

        writeFileContent(ptr16, fileContent, i);
        // dc_write(env, err, STDOUT_FILENO, ptr16, 2);
    }

    createFiles(fds, env, err, settings, prefix);

    for(size_t i = 0; i < 12; i++)
    {
        int fd                  = fds[i];
        fileContentPrintable[i] = (fileContent[i] >> 8);
        ptr                     = &fileContentPrintable[i];
        dc_write(env, err, fd, ptr, 1);
        dc_close(env, err, fd);
    }
}
int *createFiles(int                             fds[],
                 const struct dc_posix_env      *env,
                 struct dc_error                *err,
                 struct dc_application_settings *settings,
                 const char                     *prefix)
{
    int  fd;
    char filename[100] = "";
    for(int i = 0; i < 12; i++)
    {
        sprintf(filename, "%s%d.hamming", prefix, i);
        fd     = dc_open(env, err, filename, DC_O_CREAT | DC_O_TRUNC | DC_O_WRONLY, S_IRUSR | S_IWUSR);
        fds[i] = fd;
    }
    return fds;
}
void writeFileContent(const uint16_t *codeword, uint16_t fileContents[], uint16_t index)
{
    uint16_t i;
    for(i = 0; i < 12; i++)
    {
        uint16_t masked  = (*codeword & masks_16[i]);
        uint16_t aligned = (masked << i);
        uint16_t indexed = (aligned >> index);
        fileContents[i] |= indexed;
    }
}
// convert bool array to 16 bit with parity bits at indices 8-11
void toHamming(struct dc_application_settings *settings,
               bool                            input[8],
               bool                            output[16],
               const struct dc_posix_env      *env,
               struct dc_error                *err,
               const char                     *parity)
{
    for(size_t i = 0; i < sizeof(input) / sizeof(input[0]); i++)
    {
        output[i] = input[i];
    }
    computeParityBits(output, parity);
}
void computeParityBits(bool *data, const char *parity)
{
    if(((data[0] + data[1] + data[3] + data[4] + data[6]) % 2) != 0)
    {
        data[8] = true;
    }
    if(((data[0] + data[2] + data[3] + data[5] + data[6]) % 2) != 0)
    {
        data[9] = true;
    }
    if(((data[1] + data[2] + data[3] + data[7]) % 2) != 0)
    {
        data[10] = true;
    }
    if(((data[4] + data[5] + data[6] + data[7]) % 2) != 0)
    {
        data[11] = true;
    }
}

static void error_reporter(const struct dc_error *err)
{
    fprintf(stderr, "ERROR: %s : %s : @ %zu : %d\n", err->file_name, err->function_name, err->line_number, 0);
    fprintf(stderr, "ERROR: %s\n", err->message);
}

static void trace_reporter(__attribute__((unused)) const struct dc_posix_env *env,
                           const char                                        *file_name,
                           const char                                        *function_name,
                           size_t                                             line_number)
{
    fprintf(stdout, "TRACE: %s : %s : @ %zu\n", file_name, function_name, line_number);
}
