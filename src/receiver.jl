
include("main.jl")

using ..Inbound: init_receiver, listen # , listen_forever
using ..CovertChannels: covert_methods

queue = init_receiver(:local)

@debug "Listening..."

data = listen(queue, covert_methods)

@info "Data recieved" covert_payload=String(data)

sleep(10)
exit(0)
