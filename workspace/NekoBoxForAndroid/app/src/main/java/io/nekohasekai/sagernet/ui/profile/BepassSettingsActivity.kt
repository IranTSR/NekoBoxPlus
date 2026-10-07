package io.nekohasekai.sagernet.ui.profile

import androidx.compose.runtime.Composable
import io.nekohasekai.sagernet.fmt.bepass.BepassBean
import io.nekohasekai.sagernet.ktx.applyDefaultValues
import io.nekohasekai.sagernet.ui.compose.BepassProfileSettingsScreen
import moe.matsuri.nb4a.proxy.PreferenceBinding
import moe.matsuri.nb4a.proxy.PreferenceBindingManager
import moe.matsuri.nb4a.proxy.Type

class BepassSettingsActivity : ProfileSettingsActivity<BepassBean>() {
    override val usesComposePreferences = true
    override fun createEntity() = BepassBean().applyDefaultValues()

    private val binding = PreferenceBindingManager().apply {
        listOf("name", "remoteDnsAddr", "workerAddress", "workerIpPortAddress").forEach {
            add(PreferenceBinding(Type.Text, it))
        }
        listOf(
            "tlsHeaderLength", "tlsPaddingSizeMin", "tlsPaddingSizeMax",
            "chunksBeforeSniMin", "chunksBeforeSniMax",
            "sniChunksMin", "sniChunksMax",
            "chunksAfterSniMin", "chunksAfterSniMax",
            "delayBetweenChunksMin", "delayBetweenChunksMax",
            "dnsCacheTtl", "dnsRequestTimeout",
        ).forEach {
            add(PreferenceBinding(Type.TextToInt, it))
        }
        listOf(
            "tlsPaddingEnabled", "enableDnsFragmentation",
            "workerEnabled", "workerDnsOnly", "enableLowLevelSockets",
        ).forEach {
            add(PreferenceBinding(Type.Bool, it))
        }
    }

    override fun BepassBean.init() = binding.writeToCacheAll(this)
    override fun BepassBean.serialize() = binding.fromCacheAll(this)

    @Composable
    override fun ComposePreferences() = BepassProfileSettingsScreen()
}
