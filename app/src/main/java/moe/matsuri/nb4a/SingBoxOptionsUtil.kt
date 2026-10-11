package moe.matsuri.nb4a

import io.nekohasekai.sagernet.database.DataStore
import moe.matsuri.nb4a.SingBoxOptions.RuleSet

object SingBoxOptionsUtil {

    fun domainStrategy(tag: String): String {
        fun auto2(key: String, newS: String): String {
            return (DataStore.configurationStore.getString(key) ?: "").replace("auto", newS)
        }
        return when (tag) {
            "dns-remote" -> {
                auto2("domain_strategy_for_remote", "")
            }

            "dns-direct" -> {
                auto2("domain_strategy_for_direct", "")
            }

            // server
            else -> {
                auto2("domain_strategy_for_server", "prefer_ipv4")
            }
        }
    }

}

// Legacy DNS server addresses (e.g. "https://dns.google/dns-query", "tls://1.1.1.1", "8.8.8.8")
// were removed in sing-box 1.14.0, convert them to the typed DNS server format.
fun SingBoxOptions.DNSServerOptions.applyLegacyAddress(address: String) {
    val schemeIndex = address.indexOf("://")
    val scheme = if (schemeIndex < 0) "" else address.substring(0, schemeIndex).lowercase()
    val rest = if (schemeIndex < 0) address else address.substring(schemeIndex + 3)
    val hostPort = rest.substringBefore("/").substringBefore("?")
    when (scheme) {
        "" -> when (address) {
            "local", "fakeip" -> {
                type = address
                return
            }

            else -> type = "udp"
        }

        "local" -> {
            type = "local"
            return
        }

        "udp", "tcp", "tls", "quic", "https", "h3" -> type = scheme
        else -> throw IllegalArgumentException("unsupported DNS server address: $address")
    }
    val defaultPort = when (type) {
        "tls", "quic" -> 853
        "https", "h3" -> 443
        else -> 53
    }
    val host: String
    var port: Int? = null
    if (hostPort.startsWith("[")) {
        host = hostPort.substringAfter("[").substringBefore("]")
        port = hostPort.substringAfter("]:", "").toIntOrNull()
    } else if (hostPort.count { it == ':' } == 1) {
        host = hostPort.substringBefore(":")
        port = hostPort.substringAfter(":").toIntOrNull()
    } else {
        host = hostPort
    }
    if (host.isBlank()) throw IllegalArgumentException("invalid DNS server address: $address")
    server = host
    if (port != null && port != defaultPort) server_port = port
    if (type == "https" || type == "h3") {
        val urlPath = rest.substring(hostPort.length).substringBefore("?")
        if (urlPath.isNotEmpty() && urlPath != "/dns-query") path = urlPath
    }
}

// WireGuard outbound was removed in sing-box 1.13.0, convert legacy custom outbounds to endpoint.
fun migrateLegacyWireGuardOutbound(map: MutableMap<String, Any?>): MutableMap<String, Any?> {
    if (map["type"] != "wireguard" || map.containsKey("private_key") && !map.containsKey("local_address")) {
        return map
    }
    val endpoint = mutableMapOf<String, Any?>("type" to "wireguard")
    val keep = listOf(
        "tag", "mtu", "private_key", "workers", "detour", "bind_interface",
        "inet4_bind_address", "inet6_bind_address", "routing_mark", "reuse_addr",
        "connect_timeout", "tcp_fast_open", "tcp_multi_path", "udp_fragment",
        "domain_strategy", "domain_resolver", "fallback_delay",
    )
    keep.forEach { key -> map[key]?.let { endpoint[key] = it } }
    map["local_address"]?.let { endpoint["address"] = it }
    map["system_interface"]?.let { endpoint["system"] = it }
    map["interface_name"]?.let { endpoint["name"] = it }
    val allIPs = listOf("0.0.0.0/0", "::/0")
    @Suppress("UNCHECKED_CAST")
    val legacyPeers = map["peers"] as? List<Map<String, Any?>>
    endpoint["peers"] = if (!legacyPeers.isNullOrEmpty()) {
        legacyPeers.map { peer ->
            mutableMapOf<String, Any?>(
                "address" to peer["server"],
                "port" to peer["server_port"],
                "public_key" to peer["public_key"],
                "pre_shared_key" to peer["pre_shared_key"],
                "allowed_ips" to (peer["allowed_ips"] ?: allIPs),
                "reserved" to (peer["reserved"] ?: map["reserved"]),
            ).filterValues { it != null }
        }
    } else {
        listOf(
            mutableMapOf<String, Any?>(
                "address" to map["server"],
                "port" to map["server_port"],
                "public_key" to map["peer_public_key"],
                "pre_shared_key" to map["pre_shared_key"],
                "allowed_ips" to allIPs,
                "reserved" to map["reserved"],
            ).filterValues { it != null }
        )
    }
    return endpoint
}

fun SingBoxOptions.DNSRule_DefaultOptions.makeSingBoxRule(list: List<String>) {
    rule_set = mutableListOf<String>()
    domain = mutableListOf<String>()
    domain_suffix = mutableListOf<String>()
    domain_regex = mutableListOf<String>()
    domain_keyword = mutableListOf<String>()
    list.forEach {
        if (it.startsWith("geosite:")) {
            rule_set.plusAssign(it)
        } else if (it.startsWith("full:")) {
            domain.plusAssign(it.removePrefix("full:").lowercase())
        } else if (it.startsWith("domain:")) {
            domain_suffix.plusAssign(it.removePrefix("domain:").lowercase())
        } else if (it.startsWith("regexp:")) {
            domain_regex.plusAssign(it.removePrefix("regexp:").lowercase())
        } else if (it.startsWith("keyword:")) {
            domain_keyword.plusAssign(it.removePrefix("keyword:").lowercase())
        } else {
            domain_suffix.plusAssign(it.lowercase())
        }
    }
    rule_set?.removeIf { it.isNullOrBlank() }
    domain?.removeIf { it.isNullOrBlank() }
    domain_suffix?.removeIf { it.isNullOrBlank() }
    domain_regex?.removeIf { it.isNullOrBlank() }
    domain_keyword?.removeIf { it.isNullOrBlank() }
    if (rule_set?.isEmpty() == true) rule_set = null
    if (domain?.isEmpty() == true) domain = null
    if (domain_suffix?.isEmpty() == true) domain_suffix = null
    if (domain_regex?.isEmpty() == true) domain_regex = null
    if (domain_keyword?.isEmpty() == true) domain_keyword = null
}

fun SingBoxOptions.DNSRule_DefaultOptions.checkEmpty(): Boolean {
    if (rule_set?.isNotEmpty() == true) return false
    if (domain?.isNotEmpty() == true) return false
    if (domain_suffix?.isNotEmpty() == true) return false
    if (domain_regex?.isNotEmpty() == true) return false
    if (domain_keyword?.isNotEmpty() == true) return false
    if (user_id?.isNotEmpty() == true) return false
    return true
}

fun generateRuleSet(ruleSetString: List<String>, ruleSet: MutableList<RuleSet>) {
    ruleSetString.forEach {
        when {
            it.startsWith("geoip:") -> {
                ruleSet.add(RuleSet().apply {
                    type = "local"
                    tag = it
                    format = "binary"
                    path = it
                })
            }

            it.startsWith("geosite:") -> {
                ruleSet.add(RuleSet().apply {
                    type = "local"
                    tag = it
                    format = "binary"
                    path = it
                })
            }
        }
    }
}

fun SingBoxOptions.Rule_DefaultOptions.makeSingBoxRule(list: List<String>, isIP: Boolean) {
    if (isIP) {
        ip_cidr = mutableListOf<String>()
        rule_set = mutableListOf<String>()
    } else {
        rule_set = mutableListOf<String>()
        domain = mutableListOf<String>()
        domain_suffix = mutableListOf<String>()
        domain_regex = mutableListOf<String>()
        domain_keyword = mutableListOf<String>()
    }
    list.forEach {
        if (isIP) {
            if (it.startsWith("geoip:")) {
                if (it == "geoip:private") {
                    ip_is_private = true
                } else {
                    rule_set.plusAssign(it)
                }
            } else {
                ip_cidr.plusAssign(it)
            }
            return@forEach
        }
        if (it.startsWith("geosite:")) {
            rule_set.plusAssign(it)
        } else if (it.startsWith("full:")) {
            domain.plusAssign(it.removePrefix("full:").lowercase())
        } else if (it.startsWith("domain:")) {
            domain_suffix.plusAssign(it.removePrefix("domain:").lowercase())
        } else if (it.startsWith("regexp:")) {
            domain_regex.plusAssign(it.removePrefix("regexp:").lowercase())
        } else if (it.startsWith("keyword:")) {
            domain_keyword.plusAssign(it.removePrefix("keyword:").lowercase())
        } else {
            domain_suffix.plusAssign(it.lowercase())
        }
    }
    ip_cidr?.removeIf { it.isNullOrBlank() }
    rule_set?.removeIf { it.isNullOrBlank() }
    domain?.removeIf { it.isNullOrBlank() }
    domain_suffix?.removeIf { it.isNullOrBlank() }
    domain_regex?.removeIf { it.isNullOrBlank() }
    domain_keyword?.removeIf { it.isNullOrBlank() }
    if (ip_cidr?.isEmpty() == true) ip_cidr = null
    if (domain?.isEmpty() == true) domain = null
    if (domain_suffix?.isEmpty() == true) domain_suffix = null
    if (domain_regex?.isEmpty() == true) domain_regex = null
    if (domain_keyword?.isEmpty() == true) domain_keyword = null
}

fun SingBoxOptions.Rule_DefaultOptions.checkEmpty(): Boolean {
    if (ip_cidr?.isNotEmpty() == true) return false
    if (domain?.isNotEmpty() == true) return false
    if (rule_set?.isNotEmpty() == true) return false
    if (domain_suffix?.isNotEmpty() == true) return false
    if (domain_regex?.isNotEmpty() == true) return false
    if (domain_keyword?.isNotEmpty() == true) return false
    if (user_id?.isNotEmpty() == true) return false
    //
    if (port?.isNotEmpty() == true) return false
    if (port_range?.isNotEmpty() == true) return false
    if (source_ip_cidr?.isNotEmpty() == true) return false
    //
    if (!_hack_custom_config.isNullOrBlank()) return false
    return true
}
