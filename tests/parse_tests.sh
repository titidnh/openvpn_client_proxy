#!/bin/bash
# Tests de parse_vpn_remotes (ne nécessite ni root ni réseau).
# Usage: CODE=/chemin/du/depot bash parse_tests.sh
#        PATH=/chemin/shim-busybox:$PATH CODE=... bash parse_tests.sh   # pour tester avec l'awk de BusyBox (image Alpine)
#   shim: printf '#!/bin/sh\nexec /usr/bin/busybox awk "$@"\n' > shim/awk && chmod +x shim/awk
CODE=${CODE:?indiquer CODE=/chemin/du/depot}
source "$CODE/lib/common.sh" 2>/dev/null
ok=0; ko=0
t() { printf '%b' "$2" > /tmp/p.conf; got=$(parse_vpn_remotes /tmp/p.conf | tr '\n' ';'); if [ "$got" = "$3" ]; then ok=$((ok+1)); printf '   OK %s\n' "$1"; else ko=$((ko+1)); printf '   KO %s\n        obtenu : %s\n        attendu: %s\n' "$1" "$got" "$3"; fi; }
echo "### cas de la v4 (non-régression)"
t "CRLF" 'proto udp\r\nremote 203.0.113.7 1194\r\n' '203.0.113.7 1194 udp;'
t "port directive + remote sans port" 'proto udp\nport 1195\nremote h\n' 'h 1195 udp;'
t "proto tcp + port 443 + remote sans port" 'proto tcp\nport 443\nremote h\n' 'h 443 tcp;'
t "remote AVANT proto tcp" 'remote h 443\nproto tcp\n' 'h 443 tcp;'
t "remote AVANT port et proto" 'remote h\nport 443\nproto tcp\n' 'h 443 tcp;'
t "remote explicite tcp4" 'remote h 443 tcp4\n' 'h 443 tcp;'
echo "### blocs <connection>"
t "2 blocs, port/proto propres (cas de la revue)" 'client\n<connection>\nremote a\nport 1194\nproto udp\n</connection>\n<connection>\nremote b\nport 443\nproto tcp\n</connection>\n' 'a 1194 udp;b 443 tcp;'
t "bloc: port/proto AVANT remote" '<connection>\nport 443\nproto tcp\nremote a\n</connection>\n' 'a 443 tcp;'
t "bloc: remote explicite 'remote a 8443 tcp'" '<connection>\nremote a 8443 tcp\n</connection>\n' 'a 8443 tcp;'
t "2 remotes dans un bloc" '<connection>\nremote a\nremote b\nport 443\nproto tcp\n</connection>\n' 'a 443 tcp;b 443 tcp;'
t "mélange: remote global + bloc" 'proto udp\nremote g 1194\n<connection>\nremote b\nport 443\nproto tcp\n</connection>\n' 'g 1194 udp;b 443 tcp;'
t "CRLF + blocs" '<connection>\r\nremote a\r\nport 443\r\nproto tcp\r\n</connection>\r\n' 'a 443 tcp;'
echo "### HÉRITAGE des options globales par les blocs (sémantique OpenVPN)"
t "global proto tcp, bloc: 'remote a 443' (sans proto)" 'proto tcp\n<connection>\nremote a 443\n</connection>\n' 'a 443 tcp;'
t "global proto tcp + port 443, bloc: 'remote a'" 'proto tcp\nport 443\n<connection>\nremote a\n</connection>\n' 'a 443 tcp;'
t "global proto tcp, bloc ne définit que le port" 'proto tcp\n<connection>\nremote a\nport 8443\n</connection>\n' 'a 8443 tcp;'
t "global après les blocs" '<connection>\nremote a\n</connection>\nproto tcp\nport 443\n' 'a 443 tcp;'
echo "### sondes supplémentaires"
t "bloc ne redéfinit que proto (port global 443)" 'port 443\n<connection>\nremote a\nproto udp\n</connection>\n' 'a 443 udp;'
t "1er bloc sans options, 2e avec" 'proto tcp\nport 443\n<connection>\nremote a\n</connection>\n<connection>\nremote b\nport 1194\nproto udp\n</connection>\n' 'a 443 tcp;b 1194 udp;'
t "indentation/tabulations dans un bloc" '<connection>\n\tremote a\n\t  port 443\n\tproto tcp\n</connection>\n' 'a 443 tcp;'
t "lignes commentées # et ;" '# remote x 1\n; remote y 2\nremote a 1194 udp\n' 'a 1194 udp;'
t "remote-random / remote-cert-tls ignorés" 'remote-random\nremote-cert-tls server\nremote a 1194 udp\n' 'a 1194 udp;'
t "proto udp6 / tcp6-client normalisés" 'proto udp6\nremote a 1194\nremote b 443 tcp6-client\n' 'a 1194 udp;b 443 tcp;'
t "remote IPv6 littéral" 'proto udp\nremote 2001:db8::1 1194\n' '2001:db8::1 1194 udp;'
t "directive rport (équivaut au port distant)" 'proto tcp\nrport 443\nremote a\n' 'a 443 tcp;'
t "rport dans un bloc" '<connection>\nremote a\nrport 443\nproto tcp\n</connection>\n' 'a 443 tcp;'
t "BOM UTF-8 sur la 1re ligne (proto)" '\xef\xbb\xbfproto tcp\nremote a 443\n' 'a 443 tcp;'
t "fichier vide / sans remote" 'client\ndev tun\n' ''
t "proto inconnu ignoré (remote écarté)" 'proto foo\nremote a 1194\n' ''
echo "### cas rport/BOM annoncés par le journal"
t "rport global seul" 'proto tcp\nrport 443\nremote a\n' 'a 443 tcp;'
t "rport gagne sur port" 'proto tcp\nport 1194\nrport 443\nremote a\n' 'a 443 tcp;'
t "port explicite sur la ligne remote gagne sur rport" 'proto tcp\nrport 443\nremote a 8443\n' 'a 8443 tcp;'
t "rport global hérité par un bloc" 'proto tcp\nrport 443\n<connection>\nremote a\n</connection>\n' 'a 443 tcp;'
t "BOM + proto en 1re ligne" '\xef\xbb\xbfproto tcp\nremote a 443\n' 'a 443 tcp;'
t "BOM + bloc <connection> en 1re ligne" '\xef\xbb\xbf<connection>\nremote a\nport 443\nproto tcp\n</connection>\n' 'a 443 tcp;'
t "BOM + CRLF + remote en 1re ligne" '\xef\xbb\xbfremote a 443 tcp\r\nproto tcp\r\n' 'a 443 tcp;'
echo "### croisements de portée"
t "rport global + 2 blocs (un seul redéfinit port)" 'proto tcp\nrport 443\n<connection>\nremote a\n</connection>\n<connection>\nremote b\nrport 8443\n</connection>\n' 'a 443 tcp;b 8443 tcp;'
t "port de bloc VS rport global (la portée du bloc devrait gagner)" 'proto tcp\nrport 443\n<connection>\nremote a\nport 8443\n</connection>\n' 'a 8443 tcp;'
t "lport ignoré (port local, sans effet sur le remote)" 'proto udp\nlport 5000\nremote a 1194\n' 'a 1194 udp;'
t "BOM seul sur une ligne de commentaire" '\xef\xbb\xbf# commentaire\nremote a 443 tcp\n' 'a 443 tcp;'
echo "   -> $ok ok / $ko ko"
[ "$ko" -eq 0 ]
