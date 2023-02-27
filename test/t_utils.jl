include("../src/utils.jl")

@testset "Utils" begin
	@test IPv4Addr("192.168.0.1").host == 0xc0a80001
	@test string(IPv4Addr("192.168.0.1")) == "192.168.0.1"
	@test IPv4Addr([0xc0, 0xa8, 0x00, 0x01]).host == 0xc0a80001
end