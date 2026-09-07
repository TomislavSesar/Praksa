#!/ bin / bash
set - e

#Checks if first argument is string
    if[-z "$1"]; then
    echo "Upotreba: $0 <filter> [akcija] [interface]"
    echo "  Primjer: $0 \"tcp port 80\" redirect eth0"
    exit 1
fi

FILTER="$1"
ACTION="${2:-pass}"      
IFACE="${3:-enp0s1}"     

CBPFC_GEN_DIR="cbpfc_gen"     
CBPFC_GEN_BIN="cbpfc_gen_bin" 


case "$ACTION" in
    pass|drop|redirect) ;;
    *)
        echo "GREŠKA: Nepoznata akcija '$ACTION'. Dozvoljeno: pass | drop | redirect"
        exit 1
        ;;
esac

#Checking if there is an interface
if ! ip link show "$IFACE" >/dev/null 2>&1; then
    echo "GREŠKA: Interface '$IFACE' ne postoji. Dostupni:"
    ip -o link show | awk -F': ' '{print "  " $2}'
    exit 1
fi

#Files that get genrated 
PRODUCED_FILES=(
    "xdp_filter.o"
    "xdp_filter.c"
    "xdp_filter_gen"
    "Simple_AF_XDP"
)

#Function that delated all filer in PRODUCED FILES
cleanup_objects() {
    local deleted=0
    for f in "${PRODUCED_FILES[@]}"; do
        if [ -f "$f" ]; then
            rm -f "$f"
            echo "Obrisano: $f"
            deleted=1
        fi
    done
    [ "$deleted" -eq 0 ] && echo "Nema datoteka za brisanje."
}

trap cleanup_objects EXIT



build_cbpfc_gen() {
    if ! command -v go >/dev/null 2>&1; then
        echo "GREŠKA: 'go' nije u PATH-u. Instaliraj Go toolchain (>= 1.21)."
        exit 1
    fi

    if [ ! -d "$CBPFC_GEN_DIR" ]; then
        echo "GREŠKA: nema direktorija '$CBPFC_GEN_DIR/' s main.go."
        exit 1
    fi

    echo "Nema '$CBPFC_GEN_BIN', buildam Go generator iz '$CBPFC_GEN_DIR/'..."

    
    (
        cd "$CBPFC_GEN_DIR"

        if [ ! -f go.mod ]; then
            echo "  go mod init cbpfc_gen"
            go mod init cbpfc_gen
        fi

        echo "  go mod tidy   (skida cbpfc, gopacket, x/net/bpf — treba internet)"
        go mod tidy

        echo "  go build -o ../$CBPFC_GEN_BIN ."
        go build -o "../$CBPFC_GEN_BIN" .
    )

    echo "Buildan: $CBPFC_GEN_BIN"
}

if [ -x "$CBPFC_GEN_BIN" ]; then
    echo "Koristim postojeci $CBPFC_GEN_BIN"
else
    build_cbpfc_gen
fi



echo "Filter: \"$FILTER\", Akcija: $ACTION, Interface: $IFACE"

gcc -O2 -Wall Simple_AF_XDP.c -o Simple_AF_XDP -lxdp -lbpf -lpthread
gcc -O2 -Wall xdp_filter_gen.c -o xdp_filter_gen
./xdp_filter_gen "$FILTER" xdp_filter.c "$ACTION"
clang -O2 -g -target bpf \
    -I/usr/include/bpf \
    -c xdp_filter.c -o xdp_filter.o
sudo ./Simple_AF_XDP "$IFACE" || { echo "GREŠKA: Simple_AF_XDP nije uspio (exit code: $?), prekidam."; exit 1; }