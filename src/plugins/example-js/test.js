
function dcplugin_sync_pre_filter(packet) {
    var str = "Incoming packet: " + JSON.stringify(packet);

    dcplugin_log(str);
}

function dcplugin_sync_post_filter(packet) {
    var str = "Outgoing packet: " + JSON.stringify(packet);

    dcplugin_log(str);
}
