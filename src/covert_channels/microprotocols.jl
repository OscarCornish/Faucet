#=

    Micro protcol definitions
    
    *Protocols can be larger than the smallest channel*
    - But must not rely on it
        - Exception here is for recovering the channel, which is a special case
    - DISCARD_CHUNK for example is padded with payload bits, but if there is not the capacity for it, then it isnt.

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
            2ˣ- 1 -> DISCARD_CHUNK signal
            2ˣ- 2 -> protocols
        
        first X bits == "1" ^ X
            => Sentinel value (Start / end communication)
        otherwise
            => index in covert_channels / DISCARD_CHUNK

=#

const SENTINEL = parse(UInt16, "1"^(MINIMUM_CHANNEL_SIZE), base=2)
const DISCARD_CHUNK = SENTINEL - 1

#=

    Payload crafting functions

=# 

"""
Take a unsigned integer (META_PROTOCOL) and pad it as required to fit a given capacity
"""
resize_payload(payload::Integer, capacity::Int)::String = resize_payload(UInt64(payload), capacity)
function resize_payload(payload::Unsigned, capacity::Int)::String
    content = bitstring(payload)[end-MINIMUM_CHANNEL_SIZE+1:end] # Get the last 5 bits
    padding = join([rand(("1","0")) for i ∈ 1:(capacity - length(content))])
    return content * padding # Pad with random bits
end

"""
The DISCARD_CHUNK protocol is the meta_protocol,
but padded with the more payload bits
"""
function craft_discard_chunk_payload(capacity::Int, bits::String, pointer::Int64)::Tuple{Int64, String}
    chunk = bitstring(DISCARD_CHUNK)[end-MINIMUM_CHANNEL_SIZE+1:end]
    pointer_offset = capacity - length(chunk)
    payload = chunk * bits[pointer:pointer+pointer_offset-1]
    @assert length(payload) == capacity
    @assert pointer_offset == length(payload) - length(chunk)
    return pointer_offset, payload
end

"""
SENTINEL payload has no additional data just random padding
"""
craft_sentinel_payload(capacity::Int)::String = resize_payload(SENTINEL, capacity)

"""
Recovery payload has a specific format,
to prevent false positives:
```
| MINIMUM_CHANNEL_SIZE | UInt8 | 4 bits | ...
| verification_length | integrity ⊻ known_host | verification_length % 0x10 | padding
```
REQUIRES `method.capacity >= MINIMUM_CHANNEL_SIZE + 8 + 4`
"""
function craft_recovery_payload(capacity::Int, (verification_length, integrity)::Tuple{Int64, UInt8}, known_host::UInt8)::String
    if capacity < MINIMUM_CHANNEL_SIZE + 8 + 4
        @error "Capacity too small for recovery payload" capacity=capacity
        return ""
    end
    meta = "1" ^ MINIMUM_CHANNEL_SIZE
    meta *= bitstring(integrity ⊻ known_host)
    payload = meta * bitstring(verification_length % 0x10)[end-3:end]
    padding = join([rand(("1","0")) for i ∈ 1:(capacity - length(payload))])
    @info "Recovery payload" vl=verification_length tl=verification_length % 0x10 meta payload
    @assert length(payload) + length(padding) == capacity
    return payload * padding
end

"""
payload structure:
```
| MINIMUM_CHANNEL_SIZE | UInt8 | ...
| Method_index | Offset | padding
```
If the capacity is too small, the offset is assumed to be 0.
This loses the benefit of the offset but allows usability in smaller channels.
"""
function craft_change_method_payload(method_index::Int, offset::UInt8, capacity::Int)::String
    meta = "1" * bitstring(method_index)[end-MINIMUM_CHANNEL_SIZE+2:end]
    meta *= bitstring(offset)
    padding = join([rand(("1","0")) for i ∈ 1:(capacity - length(meta))])
    payload = (meta * padding)[1:capacity]
    midx, key = extract_method(payload)
    @assert midx == method_index
    @assert key == offset
    return payload
end

"""
Remove the method index and offset from the method change payload.
"""
function extract_method(payload::String)::Tuple{Int, UInt8} # Method_index, key
    key = parse(UInt8, lpad(payload[MINIMUM_CHANNEL_SIZE+1:min(MINIMUM_CHANNEL_SIZE+8, end)], 8, "0")[1:8], base=2)
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
Check that the microprotocols pass all the channel checks.
see also: [`channel_capacity_check`](@ref), [`registered_channel_check`](@ref), [`channel_match_check`](@ref).
"""
function check_channels(methods::Vector{covert_method})::Bool
    return all([
        channel_capacity_check(methods),
        registered_channel_check(methods),
        channel_match_check(methods)
    ])
end