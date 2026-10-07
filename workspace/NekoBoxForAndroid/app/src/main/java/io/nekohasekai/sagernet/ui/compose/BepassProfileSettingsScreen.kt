package io.nekohasekai.sagernet.ui.compose

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import io.nekohasekai.sagernet.R

@Composable
internal fun BepassProfileSettingsScreen() {
    val preferences = remember {
        fun c(title: Int) = CachePreferenceCategory(title)
        fun t(icon: Int, title: Int, key: String, summary: Int? = null, show: Boolean = true,
             secret: Boolean = false, number: Boolean = false, max: Int = Int.MAX_VALUE) =
            CacheTextPreference(icon, title, key, summary, show, secret, number, max)
        fun s(icon: Int, title: Int, key: String, dependency: String? = null) =
            CacheSwitchPreference(icon, title, key, dependency)
        listOf(
            t(R.drawable.ic_social_emoji_symbols, R.string.profile_name, "name"),
            c(R.string.bepass_fragmentation),
            t(R.drawable.ic_baseline_tune_24, R.string.bepass_tls_header_length, "tlsHeaderLength", number = true),
            s(R.drawable.ic_baseline_security_24, R.string.bepass_tls_padding_enabled, "tlsPaddingEnabled"),
            t(R.drawable.ic_baseline_call_split_24, R.string.bepass_tls_padding_size_min, "tlsPaddingSizeMin", number = true),
            t(R.drawable.ic_baseline_call_split_24, R.string.bepass_tls_padding_size_max, "tlsPaddingSizeMax", number = true),
            t(R.drawable.ic_baseline_call_split_24, R.string.bepass_chunks_before_sni_min, "chunksBeforeSniMin", number = true),
            t(R.drawable.ic_baseline_call_split_24, R.string.bepass_chunks_before_sni_max, "chunksBeforeSniMax", number = true),
            t(R.drawable.ic_baseline_call_split_24, R.string.bepass_sni_chunks_min, "sniChunksMin", number = true),
            t(R.drawable.ic_baseline_call_split_24, R.string.bepass_sni_chunks_max, "sniChunksMax", number = true),
            t(R.drawable.ic_baseline_call_split_24, R.string.bepass_chunks_after_sni_min, "chunksAfterSniMin", number = true),
            t(R.drawable.ic_baseline_call_split_24, R.string.bepass_chunks_after_sni_max, "chunksAfterSniMax", number = true),
            t(R.drawable.ic_baseline_timer_24, R.string.bepass_delay_between_chunks_min, "delayBetweenChunksMin", number = true),
            t(R.drawable.ic_baseline_timer_24, R.string.bepass_delay_between_chunks_max, "delayBetweenChunksMax", number = true),
            c(R.string.bepass_dns),
            t(R.drawable.ic_baseline_dns_24, R.string.bepass_remote_dns_addr, "remoteDnsAddr"),
            t(R.drawable.ic_baseline_timer_24, R.string.bepass_dns_cache_ttl, "dnsCacheTtl", number = true),
            t(R.drawable.ic_baseline_timer_24, R.string.bepass_dns_request_timeout, "dnsRequestTimeout", number = true),
            s(R.drawable.ic_baseline_call_split_24, R.string.bepass_dns_fragmentation, "enableDnsFragmentation"),
            c(R.string.bepass_worker),
            s(R.drawable.baseline_public_24, R.string.bepass_worker_enabled, "workerEnabled"),
            t(R.drawable.baseline_public_24, R.string.bepass_worker_address, "workerAddress"),
            t(R.drawable.ic_baseline_grid_3x3_24, R.string.bepass_worker_ip_port, "workerIpPortAddress"),
            s(R.drawable.ic_baseline_dns_24, R.string.bepass_worker_dns_only, "workerDnsOnly", "workerEnabled"),
            c(R.string.bepass_advanced),
            s(R.drawable.ic_action_settings, R.string.bepass_low_level_sockets, "enableLowLevelSockets"),
        )
    }
    CacheProfileSettingsScreen(preferences, includeDialOptions = false)
}
