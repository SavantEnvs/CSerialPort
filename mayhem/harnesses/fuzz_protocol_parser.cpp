// Fuzz the public frame parsers of CSerialPort (include/CSerialPort/IProtocolParser.h):
// LengthFieldBasedProtocolParser and DelimiterBasedProtocolParser. In the library these parse the
// bytes received on the serial line (SerialPortAsyncBase::readThreadFun peeks up to 4096 bytes out of
// the read RingBuffer and calls parse()), so the frame bytes are attacker-controlled. The parser
// configuration is picked by the application; the first CONFIG_LEN input bytes choose one within the
// ranges the header documents (header 0-2, lengthFieldLength > 0, check code, footer 0-2).
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "CSerialPort/SerialPort_global.h" // defines CSERIALPORT_CPP11 as the library build does
#include "CSerialPort/IProtocolParser.h"

using namespace itas109;

namespace {

static bool xorCheck(const unsigned char *data, unsigned int size) {
    // NMEA-0183 style check from the header's own example: XOR of the frame body must be 0.
    unsigned char x = 0;
    for (unsigned int i = 0; i < size; ++i) x ^= data[i];
    return x == 0;
}

class LengthParser : public LengthFieldBasedProtocolParser {
public:
    LengthParser(unsigned int hl, unsigned char *h, unsigned int lfl, unsigned int lfo, unsigned int adj,
                 unsigned int maxv, unsigned int ccl, unsigned int fl, unsigned char *f, bool be, bool xorCk)
        : LengthFieldBasedProtocolParser(hl, h, lfl, lfo, adj, maxv, ccl, fl, f, be), m_xor(xorCk) {}
    bool isCheckCodeValid(const unsigned char *data, unsigned int size) override {
        return m_xor ? xorCheck(data, size) : true;
    }
    void onProtocolEvent(std::vector<IProtocolResult> &) override {}
private:
    bool m_xor;
};

class DelimParser : public DelimiterBasedProtocolParser {
public:
    DelimParser(unsigned int hl, unsigned char *h, unsigned int fl, unsigned char *f, bool xorCk)
        : DelimiterBasedProtocolParser(hl, h, fl, f), m_xor(xorCk) {}
    bool isCheckCodeValid(const unsigned char *data, unsigned int size) override {
        return m_xor ? xorCheck(data, size) : true;
    }
    void onProtocolEvent(std::vector<IProtocolResult> &) override {}
private:
    bool m_xor;
};

const size_t CONFIG_LEN = 13;
// SerialPortAsyncBase::readThreadFun always calls parse() on its 4096-byte peek buffer
// (char bufferArray[4096]) with realSize <= 4096, so the harness does the same: the bytes sit in a
// 4096-byte heap block, and a parser read past the block (e.g. at realSize == 4096) is what ASan flags.
const size_t PEEK_BUFFER = 4096;

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < CONFIG_LEN) return -1;
    const uint8_t mode = data[0];
    unsigned int headerLen = data[1] % 3;
    unsigned char header[2] = {data[2], data[3]};
    unsigned int lengthFieldLength = (data[4] % 4) + 1;        // documented "> 0"; up to 4 bytes (unsigned int)
    unsigned int lengthFieldOffset = headerLen + (data[5] % 8); // documented: offset >= header length
    unsigned int lengthFieldMaxValue = (unsigned int)data[7] | ((unsigned int)data[8] << 8);
    unsigned int checkCodeLen = data[9] % 3;
    unsigned int footerLen = data[10] % 3;
    // Frame layout per the class diagram (header|...|length|data|check|footer): the bytes after the data
    // are exactly the check code and footer, so lengthAdjustment = check + footer, as upstream's own
    // example configures it (examples/CommNoGuiProtocol: adjustment 2 with a 2-byte check, no footer).
    // data[6] is unused (kept so seeds keep their layout).
    unsigned int lengthAdjustment = checkCodeLen + footerLen;
    unsigned char footer[2] = {data[11], data[12]};
    const bool bigEndian = mode & 2;
    const bool xorCk = mode & 4;

    size_t n = size - CONFIG_LEN;
    if (n > PEEK_BUFFER) n = PEEK_BUFFER;
    unsigned char *buf = static_cast<unsigned char *>(calloc(PEEK_BUFFER, 1));
    if (n) memcpy(buf, data + CONFIG_LEN, n);

    std::vector<IProtocolResult> results;
    unsigned int processed;
    if (mode & 1) {
        if (footerLen == 0) footerLen = 1; // documented range for the delimiter parser: 1 or 2
        DelimParser p(headerLen, header, footerLen, footer, xorCk);
        processed = p.parse(buf, (unsigned int)n, results);
        if (!results.empty()) p.onProtocolEvent(results);
    } else {
        LengthParser p(headerLen, header, lengthFieldLength, lengthFieldOffset, lengthAdjustment,
                       lengthFieldMaxValue, checkCodeLen, footerLen, footer, bigEndian, xorCk);
        processed = p.parse(buf, (unsigned int)n, results);
        if (!results.empty()) p.onProtocolEvent(results);
    }
    // The caller skips `processed` bytes of its ring buffer: more than it handed in is a parser bug.
    if (processed > n) abort();
    for (size_t i = 0; i < results.size(); ++i)
        if (results[i].len > 256) abort();
    free(buf);
    return 0;
}
