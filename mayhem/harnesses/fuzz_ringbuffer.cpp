// Fuzz CSerialPort's RingBuffer (include/CSerialPort/ibuffer.hpp), the buffer every received serial
// byte goes through (SerialPortAsyncBase::readThreadFun writes, then readData/readAllData/parser
// peek+skip). Both the RingBuffer<char> memcpy specialization (the one the library uses) and the
// generic per-element RingBuffer<T> are driven by an op stream and checked against a std::deque model,
// so logic errors in the index/mirror arithmetic (e.g. upstream #79, read size > used len) abort.
//
// Input: byte 0 = requested buffer size (rounded to a power of two by the class; 0 -> 4096),
//        byte 1 bit 0 = which instantiation, then repeated {op, len[, len bytes for write]}.
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>

#include "CSerialPort/ibuffer.hpp"

namespace {

template <typename T>
void run(unsigned int requested, const uint8_t *p, size_t n) {
    itas109::RingBuffer<T> rb(requested);
    const unsigned int cap = rb.getBufferSize();
    if (cap == 0 || (cap & (cap - 1)) != 0) abort();
    if (requested && requested <= 1073741824u && cap < requested) abort();
    std::deque<T> model;

    size_t i = 0;
    while (i + 2 <= n) {
        const uint8_t op = p[i] % 4;
        unsigned int len = p[i + 1];
        i += 2;
        if (op == 0) { // write
            if (len > n - i) len = (unsigned int)(n - i);
            T *src = new T[len ? len : 1];
            for (unsigned int k = 0; k < len; ++k) src[k] = static_cast<T>(p[i + k]);
            i += len;
            int r = rb.write(src, len);
            if (r != (int)len) abort();
            for (unsigned int k = 0; k < len; ++k) model.push_back(src[k]);
            while (model.size() > cap) model.pop_front(); // full buffer overwrites the oldest data
            delete[] src;
        } else if (op == 1 || op == 2) { // read / peek into an exact-size buffer
            T *dst = new T[len ? len : 1];
            int r = (op == 1) ? rb.read(dst, len) : rb.peek(dst, len);
            size_t expect = len < model.size() ? len : model.size();
            if (r != (int)expect) abort();
            for (size_t k = 0; k < expect; ++k)
                if (dst[k] != model[k]) abort();
            if (op == 1) model.erase(model.begin(), model.begin() + expect);
            delete[] dst;
        } else { // skip
            int r = rb.skip(len);
            size_t expect = len < model.size() ? len : model.size();
            if (r != (int)expect) abort();
            model.erase(model.begin(), model.begin() + expect);
        }
        if (rb.getUsedLen() != model.size()) abort();
        if (rb.getUnusedLen() != cap - model.size()) abort();
        if (rb.isEmpty() != model.empty()) abort();
        if (rb.isFull() != (model.size() == cap)) abort();
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return -1;
    const unsigned int requested = data[0];
    if (data[1] & 1)
        run<unsigned char>(requested, data + 2, size - 2);
    else
        run<char>(requested, data + 2, size - 2);
    return 0;
}
