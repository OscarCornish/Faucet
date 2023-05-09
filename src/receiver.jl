
include("main.jl")

using ..Inbound: init_receiver, listen # , listen_forever
using ..CovertChannels: covert_methods

queue = init_receiver(:local)

@debug "Listening..."

data = listen(queue, covert_methods)

open("../Testing-Data/payloads/$(ARGS[3]).received", "w") do io
    write(io, data)
end

@info "Data recieved" covert_payload=String(data)

exit(0)
