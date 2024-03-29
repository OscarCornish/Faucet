# Berkley packet filter allows a userspace program to apply a filter to packets

# https://github.com/torvalds/linux/blob/master/samples/bpf/bpf_insn.h

struct bpf_insn
    code::Cushort
    jt::Cuchar
    jf::Cuchar
    k::Clong
end

struct bpf_prog
    len::Cuint
    insns::Ptr{bpf_insn}
end

function local_bound_traffic(local_ip::String)::String
    return "dst host $local_ip"
end
local_bound_traffic() = local_bound_traffic(get_local_ip())

function pcap_setfilter(p::Ptr{Pcap}, fp::Ref{bpf_prog})
    ccall((:pcap_setfilter, "libpcap"), Cint, (Ptr{Cvoid}, Ref{bpf_prog}), p, fp)
end

function pcap_compile(p::Ptr{Pcap}, fp::Ref{bpf_prog}, str::String, optimize::Cint, netmask::Cuint)
    ccall((:pcap_compile, "libpcap"), Cint, (Ptr{Cvoid}, Ref{bpf_prog}, Ptr{Cchar}, Cint, Cuint), p, fp, str, optimize, netmask)
end

function pcap_freecode(fp::Ref{bpf_prog})
    ccall((:pcap_freecode, "libpcap"), Cvoid, (Ref{bpf_prog},), fp)
end

# Move these functions to environment, and allow for a filter to be passed to init_queue

# Only allow packets from $local_ip

# p = pcap_open_live(...)
# program = Ref{bpf_prog}()
# pcap_compile(p, program, "src host $local_ip", 1, 0)
# pcap_setfilter(p, program)
# pcap_freecode(program)
# pcap_loop(...)