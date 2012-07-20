
function dcplugin_sync_pre_filter(packet) {
  return "Incoming packet: " + JSON.stringify(packet)
}

function dcplugin_sync_post_filter(packet) {
  return "Outoing packet: " + JSON.stringify(packet)
}
