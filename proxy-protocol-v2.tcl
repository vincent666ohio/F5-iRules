# =====================================================================
#  PROXY Protocol v2 (PROXY command) Initiator - BIG-IP 17.x
#  Добавляет PROXY v2 header в начало LTM→pool-member, чтобы
#  backend видел реальные L3/L4 данные клиента.
#  Header строится в блоке CLIENT_ACCEPTED, отправляется в блоке SERVER_CONNECTED.
#  ОТКЛЮЧИТЕ HEALTHCHECK! он не поддерживается в iRule
# =====================================================================

when RULE_INIT {
    # 0 = без дебаг лога, 1 = логировать собранный header (Важно! пишет IP клиентов в лог если включено)
    set static::pp2_debug 0
    # 12-байтовая подпись PROXY v2 (так называемый magic header)
    set static::pp2_sighex "0d0a0d0a000d0a515549540a"
}

# --- IPv6 (текст) -> 16 байт; корректное разворачивание '::' в любой позиции согласно RFC
proc pp2_v6bin { addr } {
    set addr [lindex [split $addr "%"] 0]          ;# срезать zone id
    if { [regexp {^(.*?)::(.*)$} $addr -> ls rs] } {   ;# NB: split по "::" брать нельзя -
        set l [split $ls :]                            ;#    2-й аргумент split это МНОЖЕСТВО символов
        set r [split $rs :]
    } else {
        set l [split $addr :]
        set r {}
    }
    # раскрытие "хвостовой" встроенной формы IPv4, например ::ffff:192.168.0.1
    if { [llength $r] > 0 } { set tail [lindex $r end] } else { set tail [lindex $l end] }
    if { $tail ne "" && [string first "." $tail] >= 0 } {
        set o [split $tail .]
        set two [list \
            [format %x [expr {[lindex $o 0] * 256 + [lindex $o 1]}]] \
            [format %x [expr {[lindex $o 2] * 256 + [lindex $o 3]}]]]
        if { [llength $r] > 0 } {
            set r [concat [lrange $r 0 end-1] $two]
        } else {
            set l [concat [lrange $l 0 end-1] $two]
        }
    }
    set zeros [expr {8 - [llength $l] - [llength $r]}]
    if { $zeros < 0 } { return -code error "pp2: bad IPv6 address '$addr'" }
    set out ""
    foreach h $l { append out [binary format S [scan $h %x]] }   ;# 2 байта, для big-endian
    for { set i 0 } { $i < $zeros } { incr i } { append out "\x00\x00" }
    foreach h $r { append out [binary format S [scan $h %x]] }
    return $out
}

# --- IPv4 (текст) -> 4 байта
proc pp2_v4bin { addr } {
    set o [split $addr .]
    if { [llength $o] != 4 } { return -code error "pp2: bad IPv4 address '$addr'" }
    return [binary format c4 $o]
}

when CLIENT_ACCEPTED {
    set pp2_data ""
    set ok 1

    if { [IP::version] == 4 } {
        set fam  "11"        ;# AF_INET + STREAM
        set alen "000c"      ;# размер адресного блока = 12 байт
        if { [catch {
            set src [pp2_v4bin [IP::client_addr]]
            set dst [pp2_v4bin [IP::local_addr]]
        }] } { set ok 0 }
    } elseif { [IP::version] == 6 } {
        set fam  "21"        ;# AF_INET6 + STREAM
        set alen "0024"      ;# размер адресного блока = 36 байт
        if { [catch {
            set src [pp2_v6bin [IP::client_addr]]
            set dst [pp2_v6bin [IP::local_addr]]
        }] } { set ok 0 }
    } else {
        set ok 0
    }

    if { $ok } {
        # подпись(12) + ver/cmd(0x21) + fam/proto + len  |  src + dst + sport + dport
        set pp2_data "[binary format H* "${static::pp2_sighex}21${fam}${alen}"]${src}${dst}[binary format S [TCP::client_port]][binary format S [TCP::local_port]]"
    } else {
        # Fallback: команда LOCAL (0x20), AF=UNSPEC, len=0 - всегда валидный v2-заголовок;
        # Сообщает бэкенду «используй реальный источник соединения»
        set pp2_data [binary format H* "${static::pp2_sighex}20000000"]
        if { $static::pp2_debug } { log local0. "PROXY v2: fallback to LOCAL command" }
    }

    if { $static::pp2_debug } {
        binary scan $pp2_data H* d
        log local0. "PROXY v2 [IP::client_addr]:[TCP::client_port] -> [IP::local_addr]:[TCP::local_port] : $d"
    }
}

when SERVER_CONNECTED {
    if { [info exists pp2_data] && $pp2_data ne "" } {
        TCP::respond $pp2_data
    }
}
