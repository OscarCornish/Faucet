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

@debug "microprotocols: Loading..."

include("constants.jl")

const MP_MASK = 0b10000000
const MP_DATA = 0x00
const MP_META = 0x80
const SENTINEL = parse(UInt, "1"^(MINIMUM_CHANNEL_SIZE-1), base=2)

@debug "microprotocols: Done."