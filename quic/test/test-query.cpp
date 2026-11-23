#include <fmt/chrono.h>
#include <fmt/format.h>
#include <fmt/std.h>
#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>
#include <oxenc/hex.h>

#include <exception>
#include <filesystem>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <oxen/quic/btstream.hpp>
#include <oxen/quic/endpoint.hpp>

using namespace std::literals;
using namespace oxen;
using namespace log::literals;

static auto cat = log::Cat("query");

int main(int argc, char* argv[]) {

    log::add_sink(log::Type::Print, "stderr");
    log::reset_level(log::Level::warn);
    log::set_level(cat, log::Level::info);

    auto usage = [&argv](std::string_view msg) {
        if (!msg.empty())
            log::error(cat, "{}", msg);
        log::info(
                cat,
                "\n\nUsage: {} IP:PORT PUBKEY ENDPOINT BODY\n\nSend a body to the fileserver, shows the response.\n\n",
                argv[0]);
        return 1;
    };

    if (argc < 5)
        return usage("Insufficient arguments");

    quic::Address addr;
    try {
        addr = quic::Address::parse(argv[1]);
    } catch (const std::exception& e) {
        return usage("{} doesn't look like an IP:PORT address ({})"_format(argv[2], e.what()));
    }

    std::string_view pubkey{argv[2]};
    if (pubkey.size() != 64 || !oxenc::is_hex(pubkey))
        return usage("{} is not a valid pubkey"_format(pubkey));

    quic::Loop loop;
    auto ep = quic::Endpoint::endpoint(loop, quic::Address{});

    auto conn = ep->connect(
            quic::RemoteAddress{oxenc::from_hex(pubkey), addr},
            quic::opt::outbound_alpn("quic-files"));

    auto btr = conn->open_stream<quic::BTRequestStream>();

    std::promise<void> done_prom;
    auto done = done_prom.get_future();
    btr->command(std::string{argv[3]}, std::string_view{argv[4]},
            [&done_prom](quic::message m) {
                if (m.timed_out)
                    log::error(cat, "Request timed out!");
                else if (m.is_error())
                    log::error(cat, "Request returned an error: {}", m.body());
                else {
                    log::info(cat, "Request returned a body:\n");
                    fmt::print("{}", m.body());
                }
                done_prom.set_value();
            });

    done.wait();
}
