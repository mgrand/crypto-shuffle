package com.markgrand.cryptoShuffle;

import org.jetbrains.annotations.NotNull;

/**
 * Utility class for manipulating bytes.
 *
 * @author Mark Grand
 */
class ByteUtil {
    @NotNull
    private static final int[] ones = {
            0, // 0x00
            1, // 0x01
            1, // 0x02
            2, // 0x03
            1, // 0x04
            2, // 0x05
            2, // 0x06
            3, // 0x07
            1, // 0x08
            2, // 0x09
            2, // 0x0a
            3, // 0x0b
            2, // 0x0c
            3, // 0x0d
            3, // 0x0e
            4, // 0x0f
            1, // 0x10
            2, // 0x11
            2, // 0x12
            3, // 0x13
            2, // 0x14
            3, // 0x15
            3, // 0x16
            4, // 0x17
            2, // 0x18
            3, // 0x19
            3, // 0x1a
            4, // 0x1b
            3, // 0x1c
            4, // 0x1d
            4, // 0x1e
            5, // 0x1f
            1, // 0x20
            2, // 0x21
            2, // 0x22
            3, // 0x23
            2, // 0x24
            3, // 0x25
            3, // 0x26
            4, // 0x27
            2, // 0x28
            3, // 0x29
            3, // 0x2a
            4, // 0x2b
            3, // 0x2c
            4, // 0x2d
            4, // 0x2e
            5, // 0x2f
            2, // 0x30
            3, // 0x31
            3, // 0x32
            4, // 0x33
            3, // 0x34
            4, // 0x35
            4, // 0x36
            5, // 0x37
            3, // 0x38
            4, // 0x39
            4, // 0x3a
            5, // 0x3b
            4, // 0x3c
            5, // 0x3d
            5, // 0x3e
            6, // 0x3f
            1, // 0x40
            2, // 0x41
            2, // 0x42
            3, // 0x43
            2, // 0x44
            3, // 0x45
            3, // 0x46
            4, // 0x47
            2, // 0x48
            3, // 0x49
            3, // 0x4a
            4, // 0x4b
            3, // 0x4c
            4, // 0x4d
            4, // 0x4e
            5, // 0x4f
            2, // 0x50
            3, // 0x51
            3, // 0x52
            4, // 0x53
            3, // 0x54
            4, // 0x55
            4, // 0x56
            5, // 0x57
            3, // 0x58
            4, // 0x59
            4, // 0x5a
            5, // 0x5b
            4, // 0x5c
            5, // 0x5d
            5, // 0x5e
            6, // 0x5f
            2, // 0x60
            3, // 0x61
            3, // 0x62
            4, // 0x63
            3, // 0x64
            4, // 0x65
            4, // 0x66
            5, // 0x67
            3, // 0x68
            4, // 0x69
            4, // 0x6a
            5, // 0x6b
            4, // 0x6c
            5, // 0x6d
            5, // 0x6e
            6, // 0x6f
            3, // 0x70
            4, // 0x71
            4, // 0x72
            5, // 0x73
            4, // 0x74
            5, // 0x75
            5, // 0x76
            6, // 0x77
            4, // 0x78
            5, // 0x79
            5, // 0x7a
            6, // 0x7b
            5, // 0x7c
            6, // 0x7d
            6, // 0x7e
            7, // 0x7f
            1, // 0x80
            2, // 0x81
            2, // 0x82
            3, // 0x83
            2, // 0x84
            3, // 0x85
            3, // 0x86
            4, // 0x87
            2, // 0x88
            3, // 0x89
            3, // 0x8a
            4, // 0x8b
            3, // 0x8c
            4, // 0x8d
            4, // 08e
            5, // 0x8f
            2, // 0x90
            3, // 0x91
            3, // 0x92
            4, // 0x93
            3, // 0x94
            4, // 0x95
            4, // 0x96
            5, // 0x97
            3, // 0x98
            4, // 0x99
            4, // 0x9a
            5, // 0x9b
            4, // 0x9c
            5, // 0x9d
            5, // 0x9e
            6, // 0x9f
            2, // 0xa0
            3, // 0xa1
            3, // 0xa2
            4, // 0xa3
            3, // 0xa4
            4, // 0xa5
            4, // 0xa6
            5, // 0xa7
            3, // 0xa8
            4, // 0xa9
            4, // 0xaa
            5, // 0xab
            4, // 0xac
            5, // 0xad
            5, // 0xae
            6, // 0xaf
            3, // 0xb0
            4, // 0xb1
            4, // 0xb2
            5, // 0xb3
            4, // 0xb4
            5, // 0xb5
            5, // 0xb6
            6, // 0xb7
            4, // 0xb8
            5, // 0xb9
            5, // 0xba
            6, // 0xbb
            5, // 0xbc
            6, // 0xbd
            6, // 0xbe
            7, // 0xbf
            2, // 0xc0
            3, // 0xc1
            3, // 0xc2
            4, // 0xc3
            3, // 0xc4
            4, // 0xc5
            4, // 0xc6
            5, // 0xc7
            3, // 0xc8
            4, // 0xc9
            4, // 0xca
            5, // 0xcb
            4, // 0xcc
            5, // 0xcd
            5, // 0xce
            6, // 0xcf
            3, // 0xd0
            4, // 0xd1
            4, // 0xd2
            5, // 0xd3
            4, // 0xd4
            5, // 0xd5
            5, // 0xd6
            6, // 0xd7
            4, // 0xd8
            5, // 0xd9
            5, // 0xda
            6, // 0xdb
            5, // 0xdc
            6, // 0xdd
            6, // 0xde
            7, // 0xdf
            3, // 0xe0
            4, // 0xe1
            4, // 0xe2
            5, // 0xe3
            4, // 0xe4
            5, // 0xe5
            5, // 0xe6
            6, // 0xe7
            4, // 0xe8
            5, // 0xe9
            5, // 0xea
            6, // 0xeb
            5, // 0xec
            6, // 0xed
            6, // 0xee
            7, // 0xef

            4, // 0xf0
            5, // 0xf1
            5, // 0xf2
            6, // 0xf3
            5, // 0xf4
            6, // 0xf5
            6, // 0xf6
            7, // 0xf7
            5, // 0xf8
            6, // 0xf9
            6, // 0xfa
            7, // 0xfb
            6, // 0xfc
            7, // 0xfd
            7, // 0xfe
            8, // 0xff
    };

    /**
     * Return the number of ones in the given byte value.
     *
     * @param b The byte value to be counted.
     * @return The number of ones in b.
     */
    static int countOnes(final byte b) {
        return ones[b & 0xff];
    }

    @SuppressWarnings("SameParameterValue")
    static int countOnes(final byte[] b, final int offset, final int length) {
        int count = 0;
        for (int i = offset; i < length + offset; i++) {
            count += ones[b[i] & 0xff];
        }
        return count;
    }
}
