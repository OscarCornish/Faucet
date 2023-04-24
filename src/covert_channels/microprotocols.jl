#=

    Micro protcol definitions - *PROTOCOLS CANNOT BE LARGER THAN THE SMALLEST CHANNEL*

    Protocols are passed through the covert channel,
     the first channel used will be the most covert for the time being.

    Main protocols:

        first bit == 0b0 (MP_DATA)
            => Following bits are all data
        first bit == 0b1 (MP_META)
            => Following bits are meta
    
    Meta protocols:

        Taking smallest as Y bits (including MP_META)
        X = Y - 1 (Ignore the META flag)

        X bits -> 2ˣ permutations
            1 -> sentinel value
            2ˣ-1 -> protocols
        
        first X bits == "1"*X
            => Sentinel value (Start / end communication)
        otherwise
            => index in covert_channels

=#

using .Main: MINIMUM_CHANNEL_SIZE, target

const SENTINEL = parse(UInt16, "1"^(MINIMUM_CHANNEL_SIZE), base=2)
const DISCARD_CHUNK = SENTINEL - 1

#=

    Payload crafting functions

=# 

resize_payload(payload::Integer, capacity::Int)::String = resize_payload(UInt64(payload), capacity)
function resize_payload(payload::Unsigned, capacity::Int)::String
    content = bitstring(payload)[end-MINIMUM_CHANNEL_SIZE+1:end] # Get the last 5 bits
    padding = join([rand(("1","0")) for i ∈ 1:(capacity - length(content))])
    return content * padding # Pad with random bits
end

craft_discard_chunk_payload(capacity::Int)::String = resize_payload(DISCARD_CHUNK, capacity)

craft_sentinel_payload(capacity::Int)::String = resize_payload(SENTINEL, capacity)

function craft_change_method_payload(method_index::Int, capacity::Int)::Tuple{String, String}
    meta = parse(UInt64, "1" * bitstring(method_index)[end-MINIMUM_CHANNEL_SIZE+2:end], base=2)
    payload = resize_payload(meta, capacity)
    midx, key = extract_method(payload)
    @assert midx == method_index
    return payload, key
end

function extract_method(payload::String)::Tuple{Int, String} # Method_index, key
    key = lpad(payload[MINIMUM_CHANNEL_SIZE+1:min(MINIMUM_CHANNEL_SIZE+9, end)], 8, "0")
    method_index = parse(Int, payload[2:MINIMUM_CHANNEL_SIZE], base=2)
    return method_index, key
end

#=

    Micro protocol verification functions

=#

"""
    channel_capacity_check(methods::Vector{covert_method})::Bool

Check that the channel sizes are large enough to fit the microprotocols
"""
function channel_capacity_check(methods::Vector{covert_method})::Bool
    for method ∈ methods
        if method.payload_size < MINIMUM_CHANNEL_SIZE
            @error "Channel size too small for protocol" channel=method.name size=method.payload_size
            return false
        end
    end
    return true
end

"""
    registered_channel_check(methods::Vector{covert_method})::Bool

Check that the number of channels is less than the sentinel value, and therefore can be addressed in our microprotocols
"""
function registered_channel_check(methods::Vector{covert_method})::Bool
    if length(methods) >= SENTINEL - 1 # -1 for DISCARD_CHUNK
        @error "Too many registered channels" channels=length(methods) max=SENTINEL-1
        return false
    end
    return true
end

"""
    channel_match_check(methods::Vector{covert_method})::Bool

Check that the channels in the target match the channels in the microprotocols
"""
function channel_match_check(methods::Vector{covert_method})::Bool
    names = [method.name for method ∈ methods]::Vector{String}
    if length(names) != length(target.channels)
        @error "Channels in target and microprotocols do not match" target=target.channels microprotocols=names
        return false
    else
        for i=1:lastindex(names)
            if names[i] != target.channels[i]
                @error "Channels in target and microprotocols do not match" target=target.channels microprotocols=names index=i
                return false
            end
        end
    end
    return true
end

"""
    check_channels(methods::Vector{covert_method})::Bool

Check that the microprotocols are valid
"""
function check_channels(methods::Vector{covert_method})::Bool
    return all([
        channel_capacity_check(methods),
        registered_channel_check(methods),
        channel_match_check(methods)
    ])
end