package io.nekohasekai.sagernet.ui

import io.nekohasekai.sagernet.database.ProxyEntity

internal data class ProfileShareCapabilities(
    val links: Boolean,
    val standardLinks: Boolean,
    val configuration: Boolean,
) {
    companion object {
        fun from(entity: ProxyEntity) = ProfileShareCapabilities(
            links = entity.haveLink(),
            standardLinks = entity.haveStandardLink(),
            // bepass has no sing-box config to export (native engine owns the TUN)
            configuration = entity.nekoBean == null && entity.bepassBean == null,
        )
    }
}
