# =====================================================================
#  PROXY Protocol v1 (text) Initiator - BIG-IP 17.x
#  Кладёт текстовую v1-строку в начало LTM→pool-member.
#  Формат: "PROXY <TCP4|TCP6|UNKNOWN> <src> <dst> <sport> <dport>\r\n"
#  Максимум строки - 107 байт включая CRLF (receiver это гарантирует).
#  ОТКЛЮЧИТЕ HEALTHCHECK! он не поддерживается в iRule
# =====================================================================

when RULE_INIT {
    # 0 = дебаг лог выключен, 1 = дебаг лог включен (Важно! пишет IP клиентов в лог если включено)
    set static::pp1_debug 0
}

when CLIENT_ACCEPTED {
    set pp1_data ""

    # канонические адреса; срезаем возможный zone id (%eth0)
    set src [lindex [split [IP::client_addr] "%"] 0]
    set dst [lindex [split [IP::local_addr] "%"] 0]

    switch -exact -- [IP::version] {
        4       { set proto "TCP4" }
        6       { set proto "TCP6" }
        default { set proto "UNKNOWN" }
    }

    if { $proto eq "UNKNOWN" } {
        set pp1_data "PROXY UNKNOWN\r\n"
    } else {
        set pp1_data "PROXY ${proto} ${src} ${dst} [TCP::client_port] [TCP::local_port]\r\n"
        # страховка: receiver обязан поддерживать только до 107 байт
        if { [string length $pp1_data] > 107 } {
            set pp1_data "PROXY UNKNOWN\r\n"
        }
    }

    if { $static::pp1_debug } {
        set shown [string map [list "\r" "<CR>" "\n" "<LF>"] $pp1_data]
        log local0. "PROXY v1 [string length $pp1_data]B : $shown"
    }
}

when SERVER_CONNECTED {
    if { [info exists pp1_data] && $pp1_data ne "" } {
        TCP::respond $pp1_data
    }
}
