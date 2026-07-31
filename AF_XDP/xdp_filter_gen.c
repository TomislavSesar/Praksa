/* xdp_filter_gen.c
 *
 * Build:
 *   gcc -O2 -Wall xdp_filter_gen.c -o xdp_filter_gen
 *
 * After:
 *   clang -O2 -target bpf -I/usr/include/bpf -c xdp_filter.c -o xdp_filter.o
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CBPFC_GEN_BIN "./cbpfc_gen_bin"

enum filter_action {
    ACTION_PASS,
    ACTION_DROP,
    ACTION_REDIRECT,
};

/** @brief Parse string to enum*/
static int parse_action(const char *s)
{
    if (strcmp(s, "pass") == 0)
        return ACTION_PASS;
    if (strcmp(s, "drop") == 0)
        return ACTION_DROP;
    if (strcmp(s, "redirect") == 0)
        return ACTION_REDIRECT;
    return -1;
}

/** @brief Returns code snippet that runs if packet matches filter*/
static const char *action_match_body(enum filter_action a)
{
    switch (a) {
    case ACTION_PASS:
        return
            //"        return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);\n";
            "        return XDP_PASS;\n";
    case ACTION_DROP:
        return
            //"        return xdpcap_exit(ctx, &xdpcap_hook, XDP_DROP);\n";
            "        return XDP_DROP;\n";
    case ACTION_REDIRECT:
        return
            /*"        long ret = bpf_redirect_map(&xsks_map,
            ctx->rx_queue_index, XDP_PASS);\n" "        if (ret == XDP_REDIRECT)
            {\n" "            return xdpcap_exit(ctx, &xdpcap_hook,
            XDP_REDIRECT);\n" "        }\n" "        return xdpcap_exit(ctx,
            &xdpcap_hook, XDP_PASS);\n";*/
            "       return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, "
            "XDP_PASS);\n";
    }
    return //"        return xdpcap_exit(ctx, &xdpcap_hook, XDP_PASS);\n";
        "        return XDP_PASS;\n";
}

/** @brief Returns XDP verdict if packets is not mathced with filter */
static const char *action_nomatch_expr(enum filter_action a)
{
    switch (a) {
    case ACTION_PASS:
        return "XDP_DROP";
    case ACTION_DROP:
    case ACTION_REDIRECT:
        return "XDP_PASS";
    }
    return "XDP_PASS";
}

static const char *action_name(enum filter_action a)
{
    switch (a) {
    case ACTION_PASS:
        return "pass";
    case ACTION_DROP:
        return "drop";
    case ACTION_REDIRECT:
        return "redirect";
    }
    return "?";
}

/** @brief Function that cleans out C function genrated by cbpfc_gen
 *    It turns:
 *   1. ntohs(...)   -> bpf_ntohs(...)  (nthos() can't be used in BPF contex)
 *   2. uintN_t      -> __uN            (it is not defined in <linux/types.h>)
 *      intN_t       -> __sN
 *   3. false        -> 0               (bool is not defined in BPF contex)
 *      true         -> 1
 */

static char *fix_cbpfc_output(const char *src)
{
    // Replacemnt: { old_string, new_string }
    static const struct {
        const char *from;
        const char *to;
    } subs[] = {
        {"ntohs(", "bpf_ntohs("}, {"uint64_t", "__u64"}, {"uint32_t", "__u32"},
        {"uint16_t", "__u16"},    {"uint8_t", "__u8"},   {"int64_t", "__s64"},
        {"int32_t", "__s32"},     {"int16_t", "__s16"},  {"int8_t", "__s8"},
        {"false", "0"},           {"true", "1"},
    };
    static const int nsubs = sizeof(subs) / sizeof(subs[0]);

    // Replcaments are done one by one becouse order is important
    char *cur = strdup(src);
    if (!cur)
        return NULL;

    for (int i = 0; i < nsubs; i++) {
        const char *from = subs[i].from;
        const char *to = subs[i].to;
        size_t from_len = strlen(from);
        size_t to_len = strlen(to);

        // Counting number of appereances to calculate new size
        size_t count = 0;
        const char *p = cur;
        while ((p = strstr(p, from))) {
            // Checking if there is maybe bpf_nthos
            if (from[0] == 'n') {
                if (p >= cur + 4 && strncmp(p - 4, "bpf_", 4) == 0) {
                    p += from_len;
                    continue;
                }
            }
            count++;
            p += from_len;
        }

        if (count == 0)
            continue;

        size_t cur_len = strlen(cur);
        size_t new_len = cur_len +
                         count * (to_len > from_len ? to_len - from_len : 0) -
                         count * (from_len > to_len ? from_len - to_len : 0);
        char *next = malloc(new_len + 1);
        if (!next) {
            free(cur);
            return NULL;
        }

        char *dst = next;
        p = cur;
        const char *match;
        while ((match = strstr(p, from))) {
            // Same case for bpf_ntohs as above
            if (from[0] == 'n') {
                if (match >= cur + 4 && strncmp(match - 4, "bpf_", 4) == 0) {
                    size_t copy = match - p + from_len;
                    memcpy(dst, p, copy);
                    dst += copy;
                    p = match + from_len;
                    continue;
                }
            }

            size_t prefix = match - p;
            memcpy(dst, p, prefix);
            dst += prefix;

            memcpy(dst, to, to_len);
            dst += to_len;
            p = match + from_len;
        }

        strcpy(dst, p);

        free(cur);
        cur = next;
    }

    return cur;
}

static char *run_cbpfc_gen(const char *filter_str)
{
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "%s \"%s\" 2>&1", CBPFC_GEN_BIN, filter_str);

    FILE *pipe = popen(cmd, "r");
    if (!pipe) {
        fprintf(stderr, "[!] popen failed: %s\n", strerror(errno));
        return NULL;
    }

    size_t buf_size = 4096;
    size_t buf_used = 0;
    char *buf = malloc(buf_size);
    if (!buf) {
        pclose(pipe);
        return NULL;
    }

    char tmp[256];
    while (fgets(tmp, sizeof(tmp), pipe)) {
        size_t len = strlen(tmp);
        if (buf_used + len + 1 > buf_size) {
            buf_size *= 2;
            char *nb = realloc(buf, buf_size);
            if (!nb) {
                free(buf);
                pclose(pipe);
                return NULL;
            }
            buf = nb;
        }
        memcpy(buf + buf_used, tmp, len);
        buf_used += len;
    }
    buf[buf_used] = '\0';

    int exit_code = pclose(pipe);
    if (exit_code != 0) {
        fprintf(stderr, "[!] cbpfc_gen failed:\n%s\n", buf);
        free(buf);
        return NULL;
    }

    return buf;
}

/* XDP structure:
 * #include + hook.h
 * xdpcap_hook map
 * xsks_map map
 * cbpf_filter()     <- cbpfc output
 * xdp_prog()        <- SEC("xdp") with cbpf_filter, returns xdpcap_exit()
 */

static int write_xdp_c_file(const char *output_path, const char *filter_str,
                            const char *filter_c_code,
                            enum filter_action action)
{
    FILE *f = fopen(output_path, "w");
    if (!f) {
        fprintf(stderr, "[!] fopen(%s): %s\n", output_path, strerror(errno));
        return -1;
    }

    fprintf(
        f,
        "// Compile:\n"
        "//   clang -O2 -target bpf -I/usr/include/bpf -c %s -o xdp_filter.o\n"
        "\n"
        "#include <linux/types.h>\n"
        "#include <linux/bpf.h>\n"
        "#include <bpf/bpf_helpers.h>\n"
        "#include <bpf/bpf_endian.h>\n"
        "#include \"hook.h\"\n"
        "\n",
        filter_str, action_name(action), output_path);

    fprintf(f,
            /*"struct {\n"
            "    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);\n"
            "    __uint(key_size, sizeof(__u32));\n"
            "    __uint(value_size, sizeof(__u32));\n"
            "    __uint(max_entries, 5);\n"
            "} xdpcap_hook SEC(\".maps\");\n"*/
            "\n"
            "struct {\n"
            "    __uint(type, BPF_MAP_TYPE_XSKMAP);\n"
            "    __uint(key_size, sizeof(__u32));\n"
            "    __uint(value_size, sizeof(__u32));\n"
            "    __uint(max_entries, 64);\n"
            "} xsks_map SEC(\".maps\");\n"
            "\n");

    char *fixed = fix_cbpfc_output(filter_c_code);
    if (!fixed) {
        fprintf(stderr, "[!] fix_cbpfc_output: alokacija nije uspjela\n");
        fclose(f);
        return -1;
    }

    fprintf(f, "// ---- cbpfc output ----\n");
    fputs(fixed, f);
    fprintf(f, "// ---- kraj cbpfc outputa ----\n\n");

    free(fixed);

    fprintf(f,
            "SEC(\"xdp\")\n"
            "int xdp_prog(struct xdp_md *ctx)\n"
            "{\n"
            "    const __u8 *data     = (void *)(long)ctx->data;\n"
            "    const __u8 *data_end = (void *)(long)ctx->data_end;\n"
            "\n"
            "    if (cbpf_filter(data, data_end)) {\n"
            "%s"
            "    }\n"
            "\n"
            //"    return xdpcap_exit(ctx, &xdpcap_hook, %s);\n"
            "       return %s;\n"
            "}\n"
            "\n"
            "char _license[] SEC(\"license\") = \"GPL\";\n",
            action_match_body(action), action_nomatch_expr(action));

    fclose(f);
    return 0;
}

static void usage(const char *prog)
{
    fprintf(
        stderr,
        "Usage: %s <filter> <output.c> [akcija]\n"
        "\n"
        "  akcija (opcionalno, default: pass):\n"
        "    pass      — paket koji odgovara filtru ide u kernel, ostalo drop\n"
        "    drop      — paket koji odgovara filtru se odbacuje, ostalo pass\n"
        "    redirect  — paket koji odgovara filtru ide u AF_XDP socket,\n"
        "                ostalo pass\n"
        "\n"
        "  Primjeri:\n"
        "    %s \"tcp port 80\" xdp_filter.c redirect\n"
        "    %s \"udp and host 1.2.3.4\" xdp_filter.c drop\n"
        "    %s \"icmp\" xdp_filter.c pass\n",
        prog, prog, prog, prog);
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    const char *filter_str = argv[1];
    const char *output_path = argv[2];

    // Third argument is optional, default is pass.
    enum filter_action action = ACTION_PASS;
    if (argc >= 4) {
        int a = parse_action(argv[3]);
        if (a < 0) {
            fprintf(stderr, "[!] Nepoznata akcija: \"%s\"\n\n", argv[3]);
            usage(argv[0]);
            return 1;
        }
        action = (enum filter_action)a;
    }

    // cbpfc_gen genrated C function
    char *filter_c_code = run_cbpfc_gen(filter_str);
    if (!filter_c_code)
        return 1;

    // Writing C file
    if (write_xdp_c_file(output_path, filter_str, filter_c_code, action) < 0) {
        free(filter_c_code);
        return 1;
    }

    free(filter_c_code);

    fprintf(stdout, "%s\n", output_path);
    return 0;
}