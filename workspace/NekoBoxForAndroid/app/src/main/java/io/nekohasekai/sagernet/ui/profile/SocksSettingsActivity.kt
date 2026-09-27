package io.nekohasekai.sagernet.ui.profile

import androidx.compose.runtime.Composable
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.fmt.socks.SOCKSBean
import io.nekohasekai.sagernet.ui.compose.SocksProfileSettingsScreen

class SocksSettingsActivity : ProfileSettingsActivity<SOCKSBean>() {
    override val usesComposePreferences = true

    override fun createEntity() = SOCKSBean()

    override fun SOCKSBean.init() {
        DataStore.profileName = name
        DataStore.serverAddress = serverAddress
        DataStore.serverPort = serverPort

        DataStore.serverProtocolInt = protocol
        DataStore.serverUsername = username
        DataStore.serverPassword = password

        DataStore.profileCacheStore.putBoolean("sUoT", sUoT)

        // SNI Spoofing (root sidecar, per-profile)
        DataStore.profileCacheStore.putBoolean("sniSpoofEnabled", sniSpoofEnabled)
        DataStore.profileCacheStore.putString("sniSpoofConnect", sniSpoofConnect)
        DataStore.profileCacheStore.putString("sniSpoofFakeSni", sniSpoofFakeSni)
        DataStore.profileCacheStore.putString("sniSpoofUtls", sniSpoofUtls)
        DataStore.profileCacheStore.putString("sniSpoofInjector", sniSpoofInjector)
    }

    override fun SOCKSBean.serialize() {
        name = DataStore.profileName
        serverAddress = DataStore.serverAddress
        serverPort = DataStore.serverPort

        protocol = DataStore.serverProtocolInt
        username = DataStore.serverUsername
        password = DataStore.serverPassword

        sUoT = DataStore.profileCacheStore.getBoolean("sUoT")

        // SNI Spoofing (root sidecar, per-profile)
        sniSpoofEnabled = DataStore.profileCacheStore.getBoolean("sniSpoofEnabled")
        sniSpoofConnect = DataStore.profileCacheStore.getString("sniSpoofConnect")
        sniSpoofFakeSni = DataStore.profileCacheStore.getString("sniSpoofFakeSni")
        sniSpoofUtls = DataStore.profileCacheStore.getString("sniSpoofUtls")
        sniSpoofInjector = DataStore.profileCacheStore.getString("sniSpoofInjector")
    }

    @Composable
    override fun ComposePreferences() = SocksProfileSettingsScreen()
}
