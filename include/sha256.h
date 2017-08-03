#include <vector>
#include <array>
#include <iomanip>
#include <ict/ict.h>
#include <ict/command.h>

using std::cout;
using std::cerr;

namespace ict {
    namespace crypto {
        const auto initial_h = std::array<uint32_t, 8>{
            0x6a09e667,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19 };
        const auto k = std::array<uint32_t, 64>{
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

        struct digest {
            digest() : value(initial_h), w(64, 0) {}

            template <typename T>
            digest(T first, T last) : digest() { len = last - first; }

            std::array<uint32_t, 8> value;

            // state 
            uint64_t len;
            std::vector<uint32_t> w;
        };

        std::ostream& operator<<(std::ostream& os, const digest& hash) {
            os << std::hex << std::internal << std::setfill('0');
            for (auto i : hash.value) os << std::setw(8) << i;
            return os;
        }

        namespace util {
            template <typename ForwardIter>
            ForwardIter process_last_chunk(digest & value, ForwardIter first, ForwardIter last) {
                // first and last point to to the last part of the message, less than 512 bits
                
                auto chunk = std::array<uint32_t, 56 * 2>();
                auto start = first;
                first = std::copy(first, last, chunk.begin());
                *first++ = 0x80; // append 1 bit 

                // we have to append 0's and save enough space for a 64-bit length at the end of the last block.  This
                // may push us over into another block.
                while ((first - start) % 64 != 448) *first++ = 0x00;

                // append length of message as 64 bit bit-endian integer

                // now process the chunk(s) as normal here
                
                return last;
            }

            template <typename ForwardIter>
            ForwardIter process_chunk(digest & value, ForwardIter first, ForwardIter last) {

                // compress 
                // copy first 16 words, treating input as big-endian words (so we have to reverse byte order)
                for (int i = 0; i < 16; ++i) {
                    value.w[i] = ict::netvar<uint32_t>(first + (4 * i));
                }

                auto & w = value.w;
                uint32_t s0, s1;
                for (int i = 16; i < 64; ++i) {
                    s0 = ror(w[i-15], 7) ^ ror(w[i-15], 18) ^ shr(w[i-15], 3);
                    s1 = ror(w[i-2], 17) ^ ror(w[i-2], 19) ^ shr(w[i-2], 10);
                    w[i] = w[i-16] + s0 + w[i-7] + s1;
                }


                // initialize working variables
                auto & h = value.value;
                auto a = h[0];
                auto b = h[1];
                auto c = h[2];
                auto d = h[3];
                auto e = h[4];
                auto f = h[5];
                auto g = h[6];
                auto h = h[7];

                uint32_t temp1, temp2;
                uint32_t ch, maj;
                
                // compression function main loop
                for (int i = 0; i < 63; ++i) {
                    s1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
                    ch = (e & f) ^ ((~e) & g);
                    temp1 = h + s1 + ch + k[i] + w[i];

                    s0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
                    maj = (a & b) ^ (a & c) ^ (b & c);
                    temp1 = s0 + maj;
                }

                h[0] += a;
                h[1] += b;
                h[2] += c;
                h[3] += d;
                h[4] += e;
                h[5] += f;
                h[6] += g;
                h[7] += h;

                return first + 512;
            }
        }
    }

    template <typename ForwardIter>
    digest sha256(ForwardIter first, ForwardIter last) {
        digest value(first, last);

        while ((last - first) > 512) first = process_chunk(value, first, last);
        process_last_chunk(value, first, last);

        return value;
    }

    template <typename ForwardIter>
    void sha256(digest & hash, ForwardIter first, ForwardIter last) {
        hash = sha256(first, last);
    }

}

