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

const MP_MASK = 0b10000000
const MP_DATA = 0x00
const MP_META = 0x80
const SENTINEL = parse(UInt, "1"^(MINIMUM_CHANNEL_SIZE-1), base=2)

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
    if length(methods) => SENTINEL
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