// End-to-end fuzz of CSerialPort's receive path over a pseudo-terminal: the bytes the "remote device"
// sends are the fuzz input. A pty pair stands in for the serial line (as upstream's own test suite does,
// test/CSerialPortVirtual.cpp); CSerialPort::init/open run on the slave, the harness writes to the master,
// and the library's read thread (SerialPortAsyncBase::readThreadFun) moves the bytes through
// readDataNative -> RingBuffer<char> -> (optionally) an IProtocolParser -> onProtocolEvent, or the app
// drains them with readData/readAllData.
//
// Input: byte 0 = mode (bit0: 0 = readData path, 1 = protocol-parser path; bits1-2: which parser),
//        byte 1 = read-buffer size (16 << (b % 9), i.e. 16..4096; CSerialPort::init's readBufferSize),
//        then the received bytes. The readData path consumes them with read sizes taken from the tail
//        of the same input stream (see below).
//
// Synchronisation is by data, never by time: the readData path waits until the ring buffer holds every
// byte sent, the parser path until the parser has been handed every byte (parse() is virtual in
// IProtocolParser; the override only observes and forwards to the library's parse). At most
// one read-buffer of bytes is sent per input, so the library never has to drop data and both
// conditions are reached.
//
// State kept across inputs, on purpose: two CSerialPort objects (one for each path) live for the whole
// process, because every CSerialPort constructor creates a wake-up pipe that is never closed
// (SerialPortUnixBase.cpp), so a per-input object leaks two fds per input until FD_SET in
// waitCommEventNative() overflows its fd_set. What an input can influence is reset per input: init()
// re-creates the ring buffer (SerialPortAsyncBase::init), the port is opened on a fresh pty and closed
// again, and the parser path's parser is a forwarder whose target parser is rebuilt per input
// (setProtocolParser cannot be unset, so the readData object never gets one).
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <condition_variable>
#include <mutex>
#include <vector>

#include <pty.h>
#include <sched.h>
#include <termios.h>
#include <unistd.h>

#include "CSerialPort/SerialPort.h"
#include "CSerialPort/SerialPort_global.h"
#include "CSerialPort/IProtocolParser.h"

using namespace itas109;

namespace {

struct Progress {
    std::mutex m;
    std::condition_variable cv;
    unsigned int seen = 0;     // bytes the parser has been handed so far
    unsigned int leftover = 0; // bytes left in the ring buffer after the last parse
};

static void observe(Progress &pr, unsigned int size, unsigned int processed) {
    std::lock_guard<std::mutex> lk(pr.m);
    pr.seen += size - pr.leftover;
    pr.leftover = size - (processed < size ? processed : size);
    pr.cv.notify_all();
}

static void checkFrames(const std::vector<IProtocolResult> &results, const unsigned char *hdr, unsigned int hl,
                        const unsigned char *ftr, unsigned int fl) {
    for (size_t i = 0; i < results.size(); ++i) {
        const IProtocolResult &r = results[i];
        if (r.len > 256) abort();
        // every frame the parser emits starts with the configured header ...
        if (r.len < hl || memcmp(r.data, hdr, hl) != 0) abort();
        // ... and a delimiter frame (fully copied) ends with the footer
        if (fl && r.len < 256 && (r.len < hl + fl || memcmp(r.data + r.len - fl, ftr, fl) != 0)) abort();
    }
}

class DelimParser : public DelimiterBasedProtocolParser {
public:
    DelimParser(Progress &pr, unsigned int hl, const char *h, bool nmea)
        : DelimiterBasedProtocolParser(hl, hdrBuf(h), 2, ftrBuf()), m_pr(pr), m_hl(hl), m_nmea(nmea) {
        memcpy(m_h, h, 2);
    }
    bool isCheckCodeValid(const unsigned char *data, unsigned int size) override {
        if (!m_nmea) return true;
        // NMEA-0183 as documented in IProtocolParser.h: XOR of the bytes between '$' and '*' == hh
        unsigned char x = 0;
        unsigned int i = 1;
        for (; i < size && data[i] != '*'; ++i) x ^= data[i];
        if (i + 2 >= size) return false;
        char hex[3] = {(char)data[i + 1], (char)data[i + 2], 0};
        return strtoul(hex, nullptr, 16) == x;
    }
    unsigned int parse(const void *buffer, unsigned int size, std::vector<IProtocolResult> &results) override {
        unsigned int r = DelimiterBasedProtocolParser::parse(buffer, size, results);
        checkFrames(results, m_h, m_hl, (const unsigned char *)"\r\n", 2);
        observe(m_pr, size, r);
        return r;
    }
    void onProtocolEvent(std::vector<IProtocolResult> &results) override { checkFrames(results, m_h, m_hl, nullptr, 0); }
private:
    static unsigned char *hdrBuf(const char *h) { static unsigned char b[2]; memcpy(b, h, 2); return b; }
    static unsigned char *ftrBuf() { static unsigned char b[2] = {'\r', '\n'}; return b; }
    Progress &m_pr;
    unsigned int m_hl;
    unsigned char m_h[2];
    bool m_nmea;
};

class LengthParser : public LengthFieldBasedProtocolParser {
public:
    // header EB 90 | length (1 byte) | data | 1-byte additive checksum; adjustment = check length,
    // as in upstream's CommNoGuiProtocol example.
    explicit LengthParser(Progress &pr)
        : LengthFieldBasedProtocolParser(2, hdr(), 1, 2, 1, 250, 1, 0, hdr()), m_pr(pr) {}
    bool isCheckCodeValid(const unsigned char *data, unsigned int size) override {
        if (size < 1) return false;
        unsigned char s = 0;
        for (unsigned int i = 0; i + 1 < size; ++i) s += data[i];
        return s == data[size - 1];
    }
    unsigned int parse(const void *buffer, unsigned int size, std::vector<IProtocolResult> &results) override {
        unsigned int r = LengthFieldBasedProtocolParser::parse(buffer, size, results);
        checkFrames(results, hdr(), 2, nullptr, 0);
        observe(m_pr, size, r);
        return r;
    }
    void onProtocolEvent(std::vector<IProtocolResult> &) override {}
private:
    static unsigned char *hdr() { static unsigned char b[2] = {0xEB, 0x90}; return b; }
    Progress &m_pr;
};

static void writeAll(int fd, const uint8_t *p, size_t n) {
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w <= 0) abort();
        p += w;
        n -= (size_t)w;
    }
}

class Forwarder : public IProtocolParser {
public:
    IProtocolParser *target = nullptr;
    unsigned int parse(const void *buffer, unsigned int size, std::vector<IProtocolResult> &results) override {
        return target->parse(buffer, size, results);
    }
    void onProtocolEvent(std::vector<IProtocolResult> &results) override { target->onProtocolEvent(results); }
};

CSerialPort *g_readPort = nullptr;
CSerialPort *g_parsePort = nullptr;
Forwarder *g_forwarder = nullptr;

} // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
    g_readPort = new CSerialPort();
    g_parsePort = new CSerialPort();
    g_forwarder = new Forwarder();
    g_parsePort->setProtocolParser(g_forwarder);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return -1;
    const uint8_t mode = data[0];
    const unsigned int bufSize = 16u << (data[1] % 9);
    const uint8_t *payload = data + 2;
    size_t n = size - 2;

    int master = -1, slave = -1;
    char name[256] = {0};
    if (openpty(&master, &slave, name, nullptr, nullptr) != 0) abort();

    {
        Progress pr;
        DelimParser *dp = nullptr;
        LengthParser *lp = nullptr;
        const bool parserMode = mode & 1;
        CSerialPort &sp = parserMode ? *g_parsePort : *g_readPort;
        sp.init(name, BaudRate115200, ParityNone, DataBits8, StopOne, FlowNone, bufSize);
        sp.setReadIntervalTimeout(0);
        sp.setMinByteReadNotify(1);
        if (parserMode) {
            switch ((mode >> 1) % 3) {
            case 0: dp = new DelimParser(pr, 2, "AT", false); g_forwarder->target = dp; break;
            case 1: dp = new DelimParser(pr, 1, "$\0", true); g_forwarder->target = dp; break;
            default: lp = new LengthParser(pr); g_forwarder->target = lp; break;
            }
        }
        if (!sp.open()) abort();
        // the pty line discipline must pass bytes through untouched (a real UART does not rewrite them)
        struct termios t;
        if (tcgetattr(slave, &t) == 0) { cfmakeraw(&t); tcsetattr(slave, TCSANOW, &t); }

        if (parserMode) {
            const unsigned int sent = (unsigned int)(n > bufSize ? bufSize : n);
            writeAll(master, payload, sent);
            std::unique_lock<std::mutex> lk(pr.m);
            pr.cv.wait(lk, [&] { return pr.seen >= sent; });
            if (pr.seen != sent) abort();
        } else {
            // first half of the payload is sent, the second half drives the app's read sizes
            const size_t half = (n + 1) / 2;
            const unsigned int sent = (unsigned int)(half > bufSize ? bufSize : half);
            const uint8_t *ops = payload + half;
            size_t nops = n - half;
            writeAll(master, payload, sent);
            while (sp.getReadBufferUsedLen() < sent) sched_yield();
            if (sp.getReadBufferUsedLen() != sent) abort();
            unsigned int got = 0;
            std::vector<char> buf;
            for (size_t i = 0; i < nops && got < sent; ++i) {
                const int want = ops[i];
                buf.assign(want ? want : 1, 0);
                int r = sp.readData(buf.data(), want);
                const unsigned int expect = (unsigned int)want < sent - got ? (unsigned int)want : sent - got;
                if (r != (int)expect || memcmp(buf.data(), payload + got, expect) != 0) abort();
                got += expect;
            }
            buf.assign(sent - got + 1, 0);
            int r = sp.readAllData(buf.data());
            if (r != (int)(sent - got) || memcmp(buf.data(), payload + got, sent - got) != 0) abort();
            if (sp.getReadBufferUsedLen() != 0) abort();
        }
        sp.close();
        g_forwarder->target = nullptr;
        delete dp;
        delete lp;
    }
    close(master);
    close(slave);
    return 0;
}
