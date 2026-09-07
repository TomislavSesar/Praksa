// cbpfc_gen/cbpfc_gen.go

package main

    import("fmt"
           "os"

           "github.com/cloudflare/cbpfc"
           "github.com/google/gopacket/layers"
           "github.com/google/gopacket/pcap"
           "golang.org/x/net/bpf")

        func main()
{
    if len (os.Args)
        < 2 {fmt.Fprintf(os.Stderr, "Usage: cbpfc_gen <filter expression>\n")
                 fmt.Fprintf(os.Stderr,
                             "  Example: cbpfc_gen \"tcp port 80\"\n")
                     os.Exit(1)}

            filterStr
            : = os.Args[1]

                rawInsns,
            err : = pcap.CompileBPFFilter(layers.LinkTypeEthernet, 65535,
                                          filterStr, ) if err != nil
        {
            fmt.Fprintf(os.Stderr, "pcap compile error: %v\n", err) os.Exit(1)
        }

    if len (rawInsns) == 0 {
		fmt.Fprintf(os.Stderr, "filter producirao 0 instrukcija\n")
		os.Exit(1)
	}

	insns := make([]bpf.Instruction, len(rawInsns))
	for i, raw := range rawInsns {
		insns[i] = bpf.RawInstruction{
			Op: raw.Code,
			Jt: raw.Jt,
			Jf: raw.Jf,
			K:  raw.K,
		}.Disassemble()
	}

	cCode, err := cbpfc.ToC(insns, cbpfc.COpts{
		FunctionName: "cbpf_filter",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "cbpfc error: %v\n", err)
		os.Exit(1)
	}

	fmt.Print(cCode)
}
