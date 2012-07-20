
#ifdef _MSC_VER
# define XP_WIN
#endif

#include <stdio.h>
#include <string.h>

#include <dnscrypt/plugin.h>
#include <js/jsapi.h>

typedef struct Context_ {
    JSRuntime *rt;
    JSContext *cx;
    JSObject  *global;    
} Context;

static JSClass global_class = {
    "global", JSCLASS_GLOBAL_FLAGS,
    JS_PropertyStub, JS_PropertyStub, JS_PropertyStub, JS_StrictPropertyStub,
    JS_EnumerateStub, JS_ResolveStub, JS_ConvertStub, JS_FinalizeStub,
    JSCLASS_NO_OPTIONAL_MEMBERS
};

static void
reportError(JSContext *cx, const char *message, JSErrorReport *report)
{
    fprintf(stderr, "%s:%u:%s\n",
            report->filename ? report->filename : "<no filename=\"filename\">",
            (unsigned int) report->lineno,
            message);
}

int
dcplugin_init(DCPlugin * const dcplugin, int argc, char *argv[])
{
    FILE      *fp;
    char      *file_name;
    char      *script;
    Context   *ctx;
    JSString  *resvalue;
    jsval      rval;
    size_t     script_len;

    if (argc != 2) {
        return -1;
    }
    file_name = argv[1];
    if ((fp = fopen(file_name, "r")) == NULL) {
        fprintf(stderr, "Unable to read [%s]\n", file_name);
        return -1;
    }
    fseek(fp, 0L, SEEK_END);
    script_len = (size_t) ftello(fp);
    rewind(fp);
    if ((script = malloc(script_len)) == NULL) {
        fclose(fp);
        return -1;
    }
    fread(script, script_len, (size_t) 1U, fp);
    fclose(fp);
    puts(script);
    if ((ctx = malloc(sizeof *ctx)) == NULL) {
        return -1;
    }
    dcplugin_set_user_data(dcplugin, ctx);
    ctx->rt = JS_NewRuntime(8 * 1024 * 1024);
    if (ctx->rt == NULL) {
        return -1;
    }
    ctx->cx = JS_NewContext(ctx->rt, 8192);
    if (ctx->cx == NULL) {
        return -1;
    }
    ctx->global = JS_NewCompartmentAndGlobalObject(ctx->cx,
                                                   &global_class, NULL);
    if (ctx->global == NULL) {
        return -1;
    }
    if (!JS_InitStandardClasses(ctx->cx, ctx->global)) {
        return -1;
    }
    JS_EvaluateScript(ctx->cx, ctx->global, script, script_len,
                      file_name, 1, &rval);
    resvalue = JS_ValueToString(ctx->cx, rval);
    
    return 0;
}

int
dcplugin_destroy(DCPlugin * const dcplugin)
{
    Context *ctx = dcplugin_get_user_data(dcplugin);
    
    JS_DestroyContext(ctx->cx);
    JS_DestroyRuntime(ctx->rt);
    JS_ShutDown();
    
    return 0;
}

DCPluginSyncFilterResult
dcplugin_sync_pre_filter(DCPlugin *dcplugin, DCPluginDNSPacket *dcp_packet)
{
    Context   *ctx = dcplugin_get_user_data(dcplugin);    
    JSString  *resvalue;
    jsval      rval;
    char       script[5000];

    snprintf(script, sizeof script,
             "dcplugin_sync_pre_filter({"
             "wire_data_len: %zu, "
             "wire_data_max_len: %zu})",
             dcplugin_get_wire_data_len(dcp_packet),
             dcplugin_get_wire_data_max_len(dcp_packet));
    JS_EvaluateScript(ctx->cx, ctx->global, script, strlen(script),
                      "plugin", 1, &rval);
    resvalue = JS_ValueToString(ctx->cx, rval);
    printf("%s\n", JS_EncodeString(ctx->cx, resvalue));    
    
    return DCP_SYNC_FILTER_RESULT_OK;
}

DCPluginSyncFilterResult
dcplugin_sync_post_filter(DCPlugin *dcplugin, DCPluginDNSPacket *dcp_packet)
{
    Context   *ctx = dcplugin_get_user_data(dcplugin);    
    JSString  *resvalue;
    jsval      rval;
    char       script[5000];

    snprintf(script, sizeof script,
             "dcplugin_sync_post_filter({"
             "wire_data_len: %zu, "
             "wire_data_max_len: %zu})",
             dcplugin_get_wire_data_len(dcp_packet),
             dcplugin_get_wire_data_max_len(dcp_packet));
    JS_EvaluateScript(ctx->cx, ctx->global, script, strlen(script),
                      "plugin", 1, &rval);
    resvalue = JS_ValueToString(ctx->cx, rval);
    printf("%s\n", JS_EncodeString(ctx->cx, resvalue));    
    
    return DCP_SYNC_FILTER_RESULT_OK;
}
