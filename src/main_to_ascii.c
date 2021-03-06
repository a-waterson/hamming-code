

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
#include <math.h>
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
const uint8_t  MASK_00000001          = UINT8_C(0x00000001);
const uint8_t  MASK_00000010          = UINT8_C(0x00000002);
const uint8_t  MASK_00000100          = UINT8_C(0x00000004);
const uint8_t  MASK_00001000          = UINT8_C(0x00000008);
const uint8_t  MASK_00010000          = UINT8_C(0x00000010);
const uint8_t  MASK_00100000          = UINT8_C(0x00000020);
const uint8_t  MASK_01000000          = UINT8_C(0x00000040);
const uint8_t  MASK_10000000          = UINT8_C(0x00000080);

const uint16_t MASK_00000001_00000000 = UINT16_C(0x00000100);
const uint16_t MASK_00000010_00000000 = UINT16_C(0x00000200);
const uint16_t MASK_00000100_00000000 = UINT16_C(0x00000400);
const uint16_t MASK_00001000_00000000 = UINT16_C(0x00000800);
const uint16_t MASK_00010000_00000000 = UINT16_C(0x00001000);
const uint16_t MASK_00100000_00000000 = UINT16_C(0x00002000);
const uint16_t MASK_01000000_00000000 = UINT16_C(0x00004000);
const uint16_t MASK_10000000_00000000 = UINT16_C(0x00008000);

bool           isPowerOfTwo(int n);
void           correctError(bool parityBits[4], bool codeword[12], bool correctedCode[12]);
void validateCodeword(bool *codeword, const char *parity, const struct dc_posix_env *env, struct dc_error *err);
void checkParity(bool codeword[], const char *parity);
int *readFiles(int                             fd[],
               const struct dc_posix_env      *env,
               struct dc_error                *err,
               struct dc_application_settings *settings,
               const char                     *prefix);
void writeFileContent(const uint16_t *codeword, uint16_t fileContents[], uint16_t index);
void toHamming(struct dc_application_settings *settings,
               bool                            input[8],
               bool                            output[16],
               const struct dc_posix_env      *env,
               struct dc_error                *err);
static struct dc_application_settings *create_settings(const struct dc_posix_env *env, struct dc_error *err);

static int
destroy_settings(const struct dc_posix_env *env, struct dc_error *err, struct dc_application_settings **psettings);

static int  run(const struct dc_posix_env *env, struct dc_error *err, struct dc_application_settings *settings);

static void error_reporter(const struct dc_error *err);
static void
trace_reporter(const struct dc_posix_env *env, const char *file_name, const char *function_name, size_t line_number);
void computeParityBits(bool *output);
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

    int      ret_val;
    // open all the files and store each of their data in a buffer
    int      fds[12];
    uint8_t  fileContentPrintable[12] = {0};
    uint8_t *ptr;
    bool     data[12][8]  = {false};
    bool     data2[8][16] = {false};
    readFiles(fds, env, err, settings, prefix);
    // write to 8 bit buffer
    for(size_t i = 0; i < 12; i++)
    {
        int fd = fds[i];
        fileContentPrintable[i];
        ptr = &fileContentPrintable[i];
        dc_read(env, err, fd, ptr, 1);
        dc_close(env, err, fd);
    }
    // convert to matrix of bools

    for(int i = 0; i < 12; i++)
    {
        dc_to_binary8(env, fileContentPrintable[i], data[i]);
    }
    for(size_t i = 0; i < 8; i++)
    {
        for(size_t j = 0; j < 12; j++)
        {
            data2[i][j] = data[j][i];
        }
    }
    printf("here\n");
    for(size_t i = 0; i < 8; i++)
    {
        validateCodeword(data2[i], parity, env, err);
    }
}
/**
 * @brief 
 * 
 * @param data 
 * @param parity 
 * @param env 
 * @param err 
 */
void validateCodeword(bool *data, const char *parity, const struct dc_posix_env *env, struct dc_error *err)
{
    bool parityval;
    bool correctedCode[12];
    parityval       = !strcmp(parity, "odd");
    int  errorCount = 0;

    bool p1         = false;
    bool p2         = false;
    bool p3         = false;
    bool p4         = false;

    if(((data[0] + data[1] + data[3] + data[4] + data[6] + data[8]) % 2) != parityval)
    {
        errorCount += 1;
        p1 = true;
    }
    // check second parity bit
    if(((data[0] + data[2] + data[3] + data[5] + data[6] + data[9]) % 2) != parityval)
    {
        errorCount += 1;
        p2 = true;
    }
    // check third parity bit
    if(((data[1] + data[2] + data[3] + data[7] + data[10]) % 2) != parityval)
    {
        errorCount += 1;
        p3 = true;
    }
    // check fourth parity bit
    if(((data[4] + data[5] + data[6] + data[7] + data[11]) % 2) != parityval)
    {
        errorCount += 1;
        p4 = true;
    }
    bool     pbits[4] = {p1, p2, p3, p4};

    uint8_t  dataword;
    uint8_t *datawordptr;
    datawordptr = &dataword;
    if(errorCount != 0)
    {
        correctError(pbits, data, correctedCode);

        bool correctedDataWord[8];
        int  j = 0;
        for(int i = 0; i < 12; i++)
        {
            if(!isPowerOfTwo(i) || i == 0)
            {
                correctedDataWord[j] = correctedCode[i];
                j                    = i;
            }
        }
        dc_from_binary8(env, correctedDataWord, datawordptr);
    }
    else
    {
        bool correctedDataWord[8] = {data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]};
        dc_from_binary8(env, correctedDataWord, datawordptr);
    }

    dc_write(env, err, STDOUT_FILENO, datawordptr, 1);
}
/**
 * @brief 
 * 
 * @param n 
 * @return true 
 * @return false 
 */
bool isPowerOfTwo(int n)
{
    if(n == 0)
        return 0;
    while(n != 1)
    {
        if(n % 2 != 0)
            return 0;
        n = n / 2;
    }
    return 1;
}
/**
 * @brief 
 * 
 * @param parityBits 
 * @param codeword 
 * @param correctedCode 
 */
void correctError(bool parityBits[4], bool codeword[12], bool correctedCode[12])
{
    bool fittedCodeword[12] = {codeword[8],
                               codeword[9],
                               codeword[0],
                               codeword[10],
                               codeword[1],
                               codeword[2],
                               codeword[3],
                               codeword[11],
                               codeword[4],
                               codeword[5],
                               codeword[6],
                               codeword[7]};
    int  sum                = 0;
    for(int i = 0; i < 4; i++)
    {
        sum += (int)(pow(2, i) * parityBits[i]);
    }
    fittedCodeword[sum - 1] = !fittedCodeword[sum - 1];
    for(size_t i = 0; i < 12; i++)
    {
        correctedCode[i] = fittedCodeword[i];
        // printf("%d", correctedCode[i]);
    }
    // printf("\n");
}
/**
 * @brief 
 * 
 * @param fds 
 * @param env 
 * @param err 
 * @param settings 
 * @param prefix 
 * @return int* 
 */
int *readFiles(int                             fds[],
               const struct dc_posix_env      *env,
               struct dc_error                *err,
               struct dc_application_settings *settings,
               const char                     *prefix)
{
    int  fd;
    char filename[BUF_SIZE] = "";
    for(int i = 0; i < 12; i++)
    {
        sprintf(filename, "%s%d.hamming", prefix, i);
        fd     = dc_open(env, err, filename, DC_O_RDONLY, S_IRUSR);
        fds[i] = fd;
    }
    return fds;
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
