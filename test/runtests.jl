using Test

include("t_utils.jl")


@testset "Whole program" begin
	# Setup
	include("../src/main.jl")
	using ..Inbound: init_reciever, listen
	using ..CovertChannels: covert_methods
	using .Outbound: init_environment, send_covert_payload
	using .Environment: init_queue

	# Init reciever queue first, so it doesn't miss anything
	queue = init_reciever(:local)

	# Then setup the sender
	net_env = init_environment(target, init_queue())
	covert_payload = Vector{UInt8}("Hello covert world!")
	send_covert_payload(covert_payload, covert_methods, net_env)

	# Then listen for the response
	data = listen(queue, covert_methods)

	@test data == covert_payload

end

