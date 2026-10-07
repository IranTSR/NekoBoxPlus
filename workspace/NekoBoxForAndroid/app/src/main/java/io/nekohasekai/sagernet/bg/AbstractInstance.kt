package io.nekohasekai.sagernet.bg

import io.nekohasekai.sagernet.bg.proto.ProxyInstance
import io.nekohasekai.sagernet.database.ProxyEntity
import java.io.Closeable

interface AbstractInstance : Closeable {

    fun launch()

}

/**
 * Returns this instance as a sing-box [ProxyInstance], or null when another
 * engine (e.g. the native bepass engine) is active.
 */
internal fun AbstractInstance?.asProxyInstance(): ProxyInstance? = this as? ProxyInstance

/** The profile this instance was created for, regardless of engine. */
internal val AbstractInstance?.activeProfile: ProxyEntity?
    get() = when (this) {
        is ProxyInstance -> profile
        is BepassInstance -> profile
        else -> null
    }
